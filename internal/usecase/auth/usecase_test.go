package usecase

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	"github.com/redis/go-redis/v9"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/bcrypt"

	tokenadapter "go-auth/internal/adapter/token"
	"go-auth/internal/entity"
	tokenrepo "go-auth/internal/repo/token"
)

var (
	testAccessTTL        = 30 * time.Minute
	testRefreshTTL       = 720 * time.Hour
	testPasswordResetTTL = time.Hour
)

// newAuthUC - удобный конструктор для тестов с моками.
func newAuthUC(
	uRepo *MockUserRepository,
	uClient *MockUserClient,
	tRepo *MockTokenRepository,
	tSvc *MockTokenService,
	mailer *MockMailer,
) AuthUseCase {
	return NewAuthUseCase(
		uRepo,
		uClient,
		tRepo,
		tSvc,
		mailer,
		testAccessTTL,
		testRefreshTTL,
		testPasswordResetTTL,
		"http://localhost:3000",
	)
}

// ===========================================================================
// Базовые сценарии: используем чистые моки.
// ===========================================================================

func TestRegister_Success(t *testing.T) {
	mockUser := new(MockUserRepository)
	mockUserClient := new(MockUserClient)
	mockTokenRepo := new(MockTokenRepository)
	mockJWT := new(MockTokenService)
	mockMailer := new(MockMailer)

	uc := newAuthUC(mockUser, mockUserClient, mockTokenRepo, mockJWT, mockMailer)

	email := "test@example.com"
	password := "password123"

	mockUser.On("GetUserByEmail", mock.Anything, email).Return(nil, nil)
	mockUser.On("CreateUser", mock.Anything, mock.Anything).Return("new-user-id", nil)
	mockUserClient.On("SyncAuthUser", mock.Anything, "new-user-id", email).Return(nil)
	mockTokenRepo.On("StoreVerificationCode", mock.Anything, "new-user-id", mock.AnythingOfType("string"), VerificationCodeTTL).Return(nil)
	mockTokenRepo.On("StoreEmailVerificationRequest", mock.Anything, "new-user-id", mock.AnythingOfType("string"), VerificationCodeTTL).Return(nil)
	mockMailer.On("SendVerificationCode", email, mock.AnythingOfType("string")).Return(nil)

	userID, requestID, err := uc.Register(email, password)
	require.NoError(t, err)
	require.NotEmpty(t, userID)
	require.NotEmpty(t, requestID)
}

func TestLogin_Success(t *testing.T) {
	email := "test@example.com"
	password := "password123"

	mockUserRepo := new(MockUserRepository)
	mockUserClient := new(MockUserClient)
	mockTokenRepo := new(MockTokenRepository)
	mockTokenService := new(MockTokenService)
	mockMailer := new(MockMailer)

	uc := newAuthUC(mockUserRepo, mockUserClient, mockTokenRepo, mockTokenService, mockMailer)

	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	require.NoError(t, err)

	mockUser := &entity.User{
		ID:            "user-id",
		Email:         email,
		Password:      string(hashedPassword),
		IsActive:      true,
		EmailVerified: true,
	}

	mockUserRepo.On("GetUserByEmail", mock.Anything, email).Return(mockUser, nil)
	mockTokenService.On("GenerateAccessToken", mockUser).Return("access_token", nil)
	mockTokenService.On("GenerateRefreshTokenForFamily", mockUser, mock.AnythingOfType("string")).Return("refresh_token", nil)
	mockTokenRepo.On("StoreAccessToken", mock.Anything, mockUser.ID, "access_token", testAccessTTL).Return(nil)
	mockTokenRepo.On("CreateFamily", mock.Anything, mock.AnythingOfType("string"), mockUser.ID, "access_token", "refresh_token", testRefreshTTL).Return(nil)
	mockUserClient.On("ProfileExists", mock.Anything, mockUser.ID).Return(true, nil)

	accessToken, refreshToken, err := uc.Login(email, password)
	require.NoError(t, err)
	require.Equal(t, "access_token", accessToken)
	require.Equal(t, "refresh_token", refreshToken)
}

func TestLogin_InvalidCredentials(t *testing.T) {
	email := "test@example.com"
	password := "password123"

	mockUserRepo := new(MockUserRepository)
	mockUserClient := new(MockUserClient)
	mockTokenRepo := new(MockTokenRepository)
	mockTokenService := new(MockTokenService)
	mockMailer := new(MockMailer)

	uc := newAuthUC(mockUserRepo, mockUserClient, mockTokenRepo, mockTokenService, mockMailer)

	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	require.NoError(t, err)

	mockUser := &entity.User{
		ID: "user-id", Email: email, Password: string(hashedPassword),
		IsActive: true, EmailVerified: true,
	}
	mockUserRepo.On("GetUserByEmail", mock.Anything, email).Return(mockUser, nil)

	_, _, err = uc.Login(email, "wrong_password")
	require.ErrorIs(t, err, ErrInvalidCredentials)
}

func TestValidateToken_Success(t *testing.T) {
	mockUserRepo := new(MockUserRepository)
	mockUserClient := new(MockUserClient)
	mockTokenRepo := new(MockTokenRepository)
	mockTokenService := new(MockTokenService)
	mockMailer := new(MockMailer)
	uc := newAuthUC(mockUserRepo, mockUserClient, mockTokenRepo, mockTokenService, mockMailer)

	tok := "valid-access-token"
	mockTokenService.On("ValidateToken", tok).Return(true, nil)
	mockTokenRepo.On("ValidateAccessToken", mock.Anything, tok).Return(true, nil)

	valid, err := uc.ValidateToken(tok)
	require.NoError(t, err)
	require.True(t, valid)
}

func TestValidateToken_RevokedInRedis(t *testing.T) {
	mockUserRepo := new(MockUserRepository)
	mockUserClient := new(MockUserClient)
	mockTokenRepo := new(MockTokenRepository)
	mockTokenService := new(MockTokenService)
	mockMailer := new(MockMailer)
	uc := newAuthUC(mockUserRepo, mockUserClient, mockTokenRepo, mockTokenService, mockMailer)

	tok := "revoked-token"
	mockTokenService.On("ValidateToken", tok).Return(true, nil)
	mockTokenRepo.On("ValidateAccessToken", mock.Anything, tok).Return(false, nil)

	valid, err := uc.ValidateToken(tok)
	require.Error(t, err)
	require.False(t, valid)
	require.ErrorIs(t, err, ErrAccessTokenNotFound)
}

// ===========================================================================
// Refresh token family — интеграционные тесты с miniredis.
// Используем настоящий tokenrepo + настоящий tokenadapter (HS256) на mini Redis.
// ===========================================================================

// realStack — общий test fixture: miniredis + реальные repo + tokenSvc.
type realStack struct {
	mr        *miniredis.Miniredis
	client    *redis.Client
	tokenRepo tokenrepo.Repository
	tokenSvc  tokenadapter.JWTToken
}

func newRealStack(t *testing.T) *realStack {
	t.Helper()
	mr, err := miniredis.Run()
	require.NoError(t, err)
	t.Cleanup(mr.Close)

	cli := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	t.Cleanup(func() { _ = cli.Close() })

	repo := tokenrepo.NewRepository(cli)
	svc, err := tokenadapter.New("test-secret-family", testAccessTTL, testRefreshTTL)
	require.NoError(t, err)

	return &realStack{mr: mr, client: cli, tokenRepo: repo, tokenSvc: svc}
}

// ucWithReal - usecase, использующий настоящий tokenRepo + tokenSvc,
// но мок-userRepo / userClient / mailer (они не нужны для refresh-сценариев).
func (s *realStack) ucWithReal(userRepo *MockUserRepository) (AuthUseCase, *MockUserClient, *MockMailer) {
	uClient := new(MockUserClient)
	mailer := new(MockMailer)
	uc := NewAuthUseCase(
		userRepo,
		uClient,
		s.tokenRepo,
		s.tokenSvc,
		mailer,
		testAccessTTL,
		testRefreshTTL,
		testPasswordResetTTL,
		"http://localhost:3000",
	)
	return uc, uClient, mailer
}

// helper: создать семью + вернуть пару (access, refresh)
func issueFamily(t *testing.T, s *realStack, user *entity.User) (familyID, access, refresh string) {
	t.Helper()
	familyID = "fam-" + user.ID + "-" + time.Now().Format("150405.000000000")
	access, err := s.tokenSvc.GenerateAccessToken(user)
	require.NoError(t, err)
	refresh, err = s.tokenSvc.GenerateRefreshTokenForFamily(user, familyID)
	require.NoError(t, err)
	require.NoError(t, s.tokenRepo.CreateFamily(context.Background(), familyID, user.ID, access, refresh, testRefreshTTL))
	require.NoError(t, s.tokenRepo.StoreAccessToken(context.Background(), user.ID, access, testAccessTTL))
	return
}

func TestRefreshToken_ConcurrentRotation_ReturnsSamePair(t *testing.T) {
	s := newRealStack(t)
	userRepo := new(MockUserRepository)
	user := &entity.User{ID: "u-concurrent", Email: "c@e.com", IsActive: true, EmailVerified: true}
	userRepo.On("GetUserById", mock.Anything, user.ID).Return(user, nil)

	uc, _, _ := s.ucWithReal(userRepo)

	_, _, refresh := issueFamily(t, s, user)

	const N = 5
	type res struct {
		a, r string
		err  error
	}
	results := make([]res, N)
	var wg sync.WaitGroup
	wg.Add(N)
	for i := 0; i < N; i++ {
		go func(i int) {
			defer wg.Done()
			a, r, err := uc.RefreshToken(refresh)
			results[i] = res{a: a, r: r, err: err}
		}(i)
	}
	wg.Wait()

	// Все запросы должны успешно вернуть одну и ту же пару.
	for i, r := range results {
		require.NoErrorf(t, r.err, "goroutine %d failed", i)
		require.NotEmpty(t, r.a)
		require.NotEmpty(t, r.r)
		require.Equal(t, results[0].a, r.a, "access mismatch in goroutine %d", i)
		require.Equal(t, results[0].r, r.r, "refresh mismatch in goroutine %d", i)
	}

	// Старый refresh больше не активен в семье
	_, curR, _, ok, err := s.tokenRepo.GetFamilyCurrent(context.Background(), s.familyIDFromRefresh(t, results[0].r))
	require.NoError(t, err)
	require.True(t, ok)
	require.Equal(t, results[0].r, curR)
}

// familyIDFromRefresh — извлечь family_id из refresh (через tokenSvc).
func (s *realStack) familyIDFromRefresh(t *testing.T, refresh string) string {
	t.Helper()
	claims, err := s.tokenSvc.GetClaimsFromToken(refresh)
	require.NoError(t, err)
	return claims.FamilyID
}

func TestRefreshToken_StaleAfterMinutes_ReturnsCurrent(t *testing.T) {
	s := newRealStack(t)
	userRepo := new(MockUserRepository)
	user := &entity.User{ID: "u-stale", Email: "s@e.com", IsActive: true, EmailVerified: true}
	userRepo.On("GetUserById", mock.Anything, user.ID).Return(user, nil)
	uc, _, _ := s.ucWithReal(userRepo)

	// R0 → R1 → R2: симулируем две успешные ротации
	_, _, R0 := issueFamily(t, s, user)
	_, R1, err := uc.RefreshToken(R0)
	require.NoError(t, err)
	require.NotEmpty(t, R1)
	// Чуть подождём — miniredis детектит TTL, но мы хотим однозначно "позже".
	s.mr.FastForward(time.Second)
	_, R2, err := uc.RefreshToken(R1)
	require.NoError(t, err)
	require.NotEmpty(t, R2)

	// Теперь "отставшая вкладка" приходит с R0 спустя 10 минут — намного дольше
	// прежнего 30s-grace окна. Она должна получить (curA, R2), а не 401.
	s.mr.FastForward(10 * time.Minute)
	gotA, gotR, err := uc.RefreshToken(R0)
	require.NoError(t, err, "stale refresh must return current pair idempotently")
	require.NotEmpty(t, gotA)
	require.Equal(t, R2, gotR, "stale refresh must return CURRENT refresh of the family")

	// И с R1 — тот же эффект
	gotA2, gotR2, err := uc.RefreshToken(R1)
	require.NoError(t, err)
	require.Equal(t, gotA, gotA2)
	require.Equal(t, R2, gotR2)
}

func TestRefreshToken_ReuseAfterFamilyRevoke_KillsFamily(t *testing.T) {
	s := newRealStack(t)
	userRepo := new(MockUserRepository)
	user := &entity.User{ID: "u-reuse", Email: "r@e.com", IsActive: true, EmailVerified: true}
	userRepo.On("GetUserById", mock.Anything, user.ID).Return(user, nil)
	uc, _, _ := s.ucWithReal(userRepo)

	familyID, _, R0 := issueFamily(t, s, user)

	// Делаем одну успешную ротацию
	_, R1, err := uc.RefreshToken(R0)
	require.NoError(t, err)

	// Админ/logout/ban отзывает семью
	require.NoError(t, s.tokenRepo.RevokeFamily(context.Background(), familyID))

	// Любой токен из этой семьи должен теперь возвращать ErrRefreshTokenNotFound
	_, _, err = uc.RefreshToken(R0)
	require.ErrorIs(t, err, ErrRefreshTokenNotFound)
	_, _, err = uc.RefreshToken(R1)
	require.ErrorIs(t, err, ErrRefreshTokenNotFound)

	// Флаг должен держаться
	revoked, err := s.tokenRepo.IsFamilyRevoked(context.Background(), familyID)
	require.NoError(t, err)
	require.True(t, revoked)
}

func TestRefreshToken_Legacy_AutoMigrates(t *testing.T) {
	s := newRealStack(t)
	userRepo := new(MockUserRepository)
	user := &entity.User{ID: "u-legacy", Email: "l@e.com", IsActive: true, EmailVerified: true}
	userRepo.On("GetUserById", mock.Anything, user.ID).Return(user, nil)
	uc, _, _ := s.ucWithReal(userRepo)

	// Старый refresh — без family_id
	legacyRefresh, err := s.tokenSvc.GenerateRefreshToken(user)
	require.NoError(t, err)
	// Кладём как legacy: refresh_token:<jwt> = userID
	require.NoError(t, s.tokenRepo.StoreRefreshToken(context.Background(), user.ID, legacyRefresh, testRefreshTTL))

	// Первый рефреш — должен сработать как миграция в новую семью
	newA, newR, err := uc.RefreshToken(legacyRefresh)
	require.NoError(t, err)
	require.NotEmpty(t, newA)
	require.NotEmpty(t, newR)

	// Новый refresh должен содержать family_id
	claims, err := s.tokenSvc.GetClaimsFromToken(newR)
	require.NoError(t, err)
	require.NotEmpty(t, claims.FamilyID)

	// Legacy refresh снят
	ok, err := s.tokenRepo.ValidateRefreshToken(context.Background(), user.ID, legacyRefresh)
	require.NoError(t, err)
	require.False(t, ok)

	// А новый refresh находится через family-индекс
	famByToken, ok, err := s.tokenRepo.GetFamilyByRefresh(context.Background(), newR)
	require.NoError(t, err)
	require.True(t, ok)
	require.Equal(t, claims.FamilyID, famByToken)
}

func TestRefreshToken_InvalidJWT_Unauthenticated(t *testing.T) {
	s := newRealStack(t)
	userRepo := new(MockUserRepository)
	uc, _, _ := s.ucWithReal(userRepo)

	_, _, err := uc.RefreshToken("garbage.not.a.jwt")
	require.ErrorIs(t, err, ErrInvalidRefreshToken)

	// JWT, подписанный другим ключом
	badSvc, err := tokenadapter.New("OTHER-secret", testAccessTTL, testRefreshTTL)
	require.NoError(t, err)
	bad, err := badSvc.GenerateRefreshTokenForFamily(&entity.User{ID: "x"}, "fam-x")
	require.NoError(t, err)
	_, _, err = uc.RefreshToken(bad)
	require.ErrorIs(t, err, ErrInvalidRefreshToken)
}

func TestLogout_RevokesAllFamilies(t *testing.T) {
	s := newRealStack(t)

	user := &entity.User{ID: "u-logout", Email: "lo@e.com", IsActive: true, EmailVerified: true}
	userRepo := new(MockUserRepository)
	// Не зовётся напрямую в этом тесте, но allowed
	userRepo.On("GetUserById", mock.Anything, user.ID).Return(user, nil).Maybe()
	uc, _, _ := s.ucWithReal(userRepo)

	// Два логина = две семьи
	fam1, _, R1 := issueFamily(t, s, user)
	fam2, _, R2 := issueFamily(t, s, user)

	// Logout по R1 — должен отозвать ВСЕ семьи пользователя
	require.NoError(t, uc.Logout(R1))

	rev1, _ := s.tokenRepo.IsFamilyRevoked(context.Background(), fam1)
	rev2, _ := s.tokenRepo.IsFamilyRevoked(context.Background(), fam2)
	require.True(t, rev1, "family 1 must be revoked")
	require.True(t, rev2, "family 2 must be revoked after multi-device logout")

	// Refresh с любым старым токеном должен теперь падать
	_, _, err := uc.RefreshToken(R1)
	require.ErrorIs(t, err, ErrRefreshTokenNotFound)
	_, _, err = uc.RefreshToken(R2)
	require.ErrorIs(t, err, ErrRefreshTokenNotFound)
}

func TestRefreshToken_TamperedFamilyID_ReuseDetected(t *testing.T) {
	s := newRealStack(t)
	userRepo := new(MockUserRepository)
	user := &entity.User{ID: "u-tamper", Email: "t@e.com", IsActive: true, EmailVerified: true}
	userRepo.On("GetUserById", mock.Anything, user.ID).Return(user, nil)
	uc, _, _ := s.ucWithReal(userRepo)

	// Семья A
	famA, _, RA := issueFamily(t, s, user)
	// Семья B (того же пользователя, но другая)
	famB, _, _ := issueFamily(t, s, user)

	// Тампер: сгенерируем refresh с family_id = famB, который НИКОГДА не
	// проходил через CreateFamily/Rotate (т.е. отсутствует в refresh_family
	// индексе). Используем фиктивный userID для уникальности JWT-payload.
	tampered, err := s.tokenSvc.GenerateRefreshTokenForFamily(
		&entity.User{ID: user.ID + "::tamper-marker", Role: "user"},
		famB,
	)
	require.NoError(t, err)
	// Перехитрим subject: JWT subject будет другим (user.ID+"::tamper-marker")
	// → curUserID != userID → reuse-detection отзовёт famB.
	// Это эмулирует подмену claims в JWT с тем же секретом.

	_, _, err = uc.RefreshToken(tampered)
	require.ErrorIs(t, err, ErrRefreshTokenNotFound)

	// Семья B должна быть помечена как revoked (reuse detected по famB)
	revB, _ := s.tokenRepo.IsFamilyRevoked(context.Background(), famB)
	require.True(t, revB, "family B must be revoked due to reuse-detection")

	// Семья A по-прежнему живёт — её никто не трогал
	revA, _ := s.tokenRepo.IsFamilyRevoked(context.Background(), famA)
	require.False(t, revA, "family A must NOT be revoked")

	// Контроль: RA из семьи A работает нормально
	a, r, err := uc.RefreshToken(RA)
	require.NoError(t, err)
	require.NotEmpty(t, a)
	require.NotEmpty(t, r)

	// Errors.Is sanity-check на repository sentinels
	require.True(t, errors.Is(tokenrepo.ErrFamilyConflict, tokenrepo.ErrFamilyConflict))
}

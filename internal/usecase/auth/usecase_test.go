package usecase

import (
	"errors"
	"testing"
	"time"

	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/bcrypt"

	"go-auth/internal/entity"
)

var (
	testAccessTTL  = 30 * time.Minute
	testRefreshTTL = 720 * time.Hour
)

func TestRegister(t *testing.T) {
	mockUser := new(MockUserRepository)
	mockTokenRepo := new(MockTokenRepository)
	mockJWT := new(MockTokenService)
	mockMailer := new(MockMailer)

	repo := NewAuthUseCase(mockUser, mockTokenRepo, mockJWT, mockMailer, testAccessTTL, testRefreshTTL)

	t.Run("success", func(t *testing.T) {
		email := "test@example.com"
		password := "password123"

		// Мок репозитория возвращает nil (пользователя еще нет)
		mockUser.On("GetUserByEmail", mock.Anything, email).Return(nil, nil)

		// Переопределяем ожидание создания пользователя в репозитории
		mockUser.On("CreateUser", mock.Anything, mock.Anything).Return("new-user-id", nil)

		// Мок сохранения кода верификации в Redis
		mockTokenRepo.On("StoreVerificationCode", mock.Anything, email, mock.AnythingOfType("string"), VerificationCodeTTL).Return(nil)

		// Мок отправки email
		mockMailer.On("SendVerificationCode", email, mock.AnythingOfType("string")).Return(nil)

		// Проверяем результат
		userID, err := repo.Register(email, password)

		require.NoError(t, err)
		require.NotEmpty(t, userID)

		mockUser.AssertExpectations(t)
	})
}

func TestLogin(t *testing.T) {
	email := "test@example.com"
	password := "password123"

	t.Run("success", func(t *testing.T) {
		mockUserRepo := new(MockUserRepository)
		mockTokenRepo := new(MockTokenRepository)
		mockTokenService := new(MockTokenService)
		mockMailer := new(MockMailer)

		authUseCase := NewAuthUseCase(mockUserRepo, mockTokenRepo, mockTokenService, mockMailer, testAccessTTL, testRefreshTTL)

		// Генерация хэша пароля
		hashedPassword, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
		require.NoError(t, err)

		mockUser := &entity.User{
			ID:       "user-id",
			Email:    email,
			Password: string(hashedPassword),
			IsActive: true,
		}

		mockUserRepo.On("GetUserByEmail", mock.Anything, email).Return(mockUser, nil)
		mockTokenService.On("GenerateAccessToken", mockUser).Return("access_token", nil)
		mockTokenService.On("GenerateRefreshToken", mockUser).Return("refresh_token", nil)
		mockTokenRepo.On("StoreAccessToken", mock.Anything, mockUser.ID, "access_token", testAccessTTL).Return(nil)
		mockTokenRepo.On("StoreRefreshToken", mock.Anything, mockUser.ID, "refresh_token", testRefreshTTL).Return(nil)

		accessToken, refreshToken, err := authUseCase.Login(email, password)

		require.NoError(t, err)
		require.Equal(t, "access_token", accessToken)
		require.Equal(t, "refresh_token", refreshToken)

		mockUserRepo.AssertExpectations(t)
		mockTokenService.AssertExpectations(t)
		mockTokenRepo.AssertExpectations(t)
	})

	t.Run("invalid credentials", func(t *testing.T) {
		mockUserRepo := new(MockUserRepository)
		mockTokenRepo := new(MockTokenRepository)
		mockTokenService := new(MockTokenService)
		mockMailer := new(MockMailer)

		authUseCase := NewAuthUseCase(mockUserRepo, mockTokenRepo, mockTokenService, mockMailer, testAccessTTL, testRefreshTTL)

		// Генерация хэша пароля
		hashedPassword, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
		require.NoError(t, err)

		mockUser := &entity.User{
			ID:       "user-id",
			Email:    email,
			Password: string(hashedPassword),
			IsActive: true,
		}

		mockUserRepo.On("GetUserByEmail", mock.Anything, email).Return(mockUser, nil)

		_, _, err = authUseCase.Login(email, "wrong_password")
		require.ErrorIs(t, err, ErrInvalidCredentials)

		mockUserRepo.AssertExpectations(t)
	})
}

func TestRefreshToken(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		mockUserRepo := new(MockUserRepository)
		mockTokenRepo := new(MockTokenRepository)
		mockTokenService := new(MockTokenService)
		mockMailer := new(MockMailer)

		authUseCase := NewAuthUseCase(mockUserRepo, mockTokenRepo, mockTokenService, mockMailer, testAccessTTL, testRefreshTTL)

		refreshToken := "valid-refresh-token"
		newAccessToken := "new-access-token"
		userID := "user-id"

		// Настраиваем моки
		mockTokenService.On("ValidateToken", refreshToken).Return(true, nil)
		mockTokenService.On("GetUserIDFromToken", refreshToken).Return(userID, nil)
		mockTokenRepo.On("ValidateRefreshToken", mock.Anything, userID, refreshToken).Return(true, nil)
		mockTokenService.On("RefreshAccessToken", refreshToken).Return(newAccessToken, nil)
		mockTokenRepo.On("StoreAccessToken", mock.Anything, userID, newAccessToken, testAccessTTL).Return(nil)

		// Тестируем
		token, err := authUseCase.RefreshToken(refreshToken)
		require.NoError(t, err)
		require.Equal(t, newAccessToken, token)

		// Проверяем вызовы
		mockTokenRepo.AssertExpectations(t)
		mockTokenService.AssertExpectations(t)
	})

	t.Run("invalid token", func(t *testing.T) {
		mockUserRepo := new(MockUserRepository)
		mockTokenRepo := new(MockTokenRepository)
		mockTokenService := new(MockTokenService)
		mockMailer := new(MockMailer)

		authUseCase := NewAuthUseCase(mockUserRepo, mockTokenRepo, mockTokenService, mockMailer, testAccessTTL, testRefreshTTL)

		refreshToken := "invalid-refresh-token"

		mockTokenService.On("ValidateToken", refreshToken).Return(false, errors.New("invalid token"))

		token, err := authUseCase.RefreshToken(refreshToken)
		require.Error(t, err)
		require.Empty(t, token)
		require.ErrorIs(t, err, ErrInvalidRefreshToken)

		mockTokenService.AssertExpectations(t)
	})

	t.Run("token not found in storage", func(t *testing.T) {
		mockUserRepo := new(MockUserRepository)
		mockTokenRepo := new(MockTokenRepository)
		mockTokenService := new(MockTokenService)
		mockMailer := new(MockMailer)

		authUseCase := NewAuthUseCase(mockUserRepo, mockTokenRepo, mockTokenService, mockMailer, testAccessTTL, testRefreshTTL)

		refreshToken := "not-stored-token"
		userID := "user-id"

		mockTokenService.On("ValidateToken", refreshToken).Return(true, nil)
		mockTokenService.On("GetUserIDFromToken", refreshToken).Return(userID, nil)
		mockTokenRepo.On("ValidateRefreshToken", mock.Anything, userID, refreshToken).Return(false, nil)

		token, err := authUseCase.RefreshToken(refreshToken)
		require.Error(t, err)
		require.Empty(t, token)
		require.ErrorIs(t, err, ErrRefreshTokenNotFound)

		mockTokenRepo.AssertExpectations(t)
		mockTokenService.AssertExpectations(t)
	})
}

func TestValidateToken(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		mockUserRepo := new(MockUserRepository)
		mockTokenRepo := new(MockTokenRepository)
		mockTokenService := new(MockTokenService)
		mockMailer := new(MockMailer)

		authUseCase := NewAuthUseCase(mockUserRepo, mockTokenRepo, mockTokenService, mockMailer, testAccessTTL, testRefreshTTL)

		token := "valid-access-token"

		mockTokenService.On("ValidateToken", token).Return(true, nil)
		mockTokenRepo.On("ValidateAccessToken", mock.Anything, token).Return(true, nil)

		valid, err := authUseCase.ValidateToken(token)
		require.NoError(t, err)
		require.True(t, valid)

		mockTokenService.AssertExpectations(t)
		mockTokenRepo.AssertExpectations(t)
	})

	t.Run("token not found in redis", func(t *testing.T) {
		mockUserRepo := new(MockUserRepository)
		mockTokenRepo := new(MockTokenRepository)
		mockTokenService := new(MockTokenService)
		mockMailer := new(MockMailer)

		authUseCase := NewAuthUseCase(mockUserRepo, mockTokenRepo, mockTokenService, mockMailer, testAccessTTL, testRefreshTTL)

		token := "revoked-token"

		mockTokenService.On("ValidateToken", token).Return(true, nil)
		mockTokenRepo.On("ValidateAccessToken", mock.Anything, token).Return(false, nil)

		valid, err := authUseCase.ValidateToken(token)
		require.Error(t, err)
		require.False(t, valid)
		require.ErrorIs(t, err, ErrAccessTokenNotFound)

		mockTokenRepo.AssertExpectations(t)
	})

	t.Run("invalid jwt token", func(t *testing.T) {
		mockUserRepo := new(MockUserRepository)
		mockTokenRepo := new(MockTokenRepository)
		mockTokenService := new(MockTokenService)
		mockMailer := new(MockMailer)

		authUseCase := NewAuthUseCase(mockUserRepo, mockTokenRepo, mockTokenService, mockMailer, testAccessTTL, testRefreshTTL)

		token := "invalid-access-token"

		mockTokenService.On("ValidateToken", token).Return(false, nil)

		valid, err := authUseCase.ValidateToken(token)
		require.NoError(t, err)
		require.False(t, valid)

		mockTokenService.AssertExpectations(t)
	})
}

// TestLogout и TestLogoutAll закомментированы, т.к. методы Logout и LogoutAll
// ещё не реализованы в usecase. Раскомментируйте после добавления этих методов.
/*
func TestLogout(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		mockTokenRepo := new(MockTokenRepository)
		mockTokenService := new(MockTokenService)
		mockMailer := new(MockMailer)

		authUseCase := &auth{
			tokenRepo:    mockTokenRepo,
			tokenService: mockTokenService,
			mailer:       mockMailer,
			accessTTL:    testAccessTTL,
		}

		accessToken := "valid-access-token"
		userID := "user-id"

		mockTokenService.On("GetUserIDFromToken", accessToken).Return(userID, nil)
		mockTokenRepo.On("RevokeAccessToken", mock.Anything, userID, accessToken).Return(nil)

		err := authUseCase.Logout(accessToken)
		require.NoError(t, err)

		mockTokenRepo.AssertExpectations(t)
		mockTokenService.AssertExpectations(t)
	})
}

func TestLogoutAll(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		mockTokenRepo := new(MockTokenRepository)
		mockMailer := new(MockMailer)

		authUseCase := &auth{
			tokenRepo: mockTokenRepo,
			mailer:    mockMailer,
		}

		userID := "user-id"

		mockTokenRepo.On("RevokeAllUserTokens", mock.Anything, userID).Return(nil)

		err := authUseCase.LogoutAll(userID)
		require.NoError(t, err)

		mockTokenRepo.AssertExpectations(t)
	})
}
*/

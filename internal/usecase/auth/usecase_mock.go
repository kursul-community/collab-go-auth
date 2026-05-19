package usecase

import (
	"context"
	"time"

	"github.com/stretchr/testify/mock"

	"go-auth/internal/adapter/token"
	"go-auth/internal/entity"
)

// === MockUserRepository ===

type MockUserRepository struct {
	mock.Mock
}

func (m *MockUserRepository) GetUserById(ctx context.Context, id string) (*entity.User, error) {
	args := m.Called(ctx, id)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*entity.User), args.Error(1)
}

func (m *MockUserRepository) GetUserByEmail(ctx context.Context, email string) (*entity.User, error) {
	args := m.Called(ctx, email)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*entity.User), args.Error(1)
}

func (m *MockUserRepository) CreateUser(ctx context.Context, user *entity.User) (string, error) {
	args := m.Called(ctx, user)
	return args.String(0), args.Error(1)
}

func (m *MockUserRepository) SetEmailVerified(ctx context.Context, userID string, verified bool) error {
	args := m.Called(ctx, userID, verified)
	return args.Error(0)
}

func (m *MockUserRepository) UpdatePassword(ctx context.Context, userID string, hashedPassword string) error {
	args := m.Called(ctx, userID, hashedPassword)
	return args.Error(0)
}

func (m *MockUserRepository) GetUserByOAuthProvider(ctx context.Context, provider, providerID string) (*entity.User, error) {
	args := m.Called(ctx, provider, providerID)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*entity.User), args.Error(1)
}

func (m *MockUserRepository) CreateOAuthUser(ctx context.Context, user *entity.User) (string, error) {
	args := m.Called(ctx, user)
	return args.String(0), args.Error(1)
}

func (m *MockUserRepository) LinkOAuthProvider(ctx context.Context, userID, provider, providerID string) error {
	args := m.Called(ctx, userID, provider, providerID)
	return args.Error(0)
}

func (m *MockUserRepository) DeleteUser(ctx context.Context, userID string) error {
	args := m.Called(ctx, userID)
	return args.Error(0)
}

// === MockUserClient (gRPC user-service) ===

type MockUserClient struct {
	mock.Mock
}

func (m *MockUserClient) SyncAuthUser(ctx context.Context, userID, email string) error {
	args := m.Called(ctx, userID, email)
	return args.Error(0)
}

func (m *MockUserClient) ProfileExists(ctx context.Context, userID string) (bool, error) {
	args := m.Called(ctx, userID)
	return args.Bool(0), args.Error(1)
}

func (m *MockUserClient) UpdateGitURL(ctx context.Context, userID, gitURL, accessToken string) error {
	args := m.Called(ctx, userID, gitURL, accessToken)
	return args.Error(0)
}

func (m *MockUserClient) GetUserStatus(ctx context.Context, userID string) (string, string, error) {
	args := m.Called(ctx, userID)
	return args.String(0), args.String(1), args.Error(2)
}

// === MockTokenRepository ===

type MockTokenRepository struct {
	mock.Mock
}

// Access токены
func (m *MockTokenRepository) StoreAccessToken(ctx context.Context, userID string, token string, ttl time.Duration) error {
	args := m.Called(ctx, userID, token, ttl)
	return args.Error(0)
}

func (m *MockTokenRepository) ValidateAccessToken(ctx context.Context, token string) (bool, error) {
	args := m.Called(ctx, token)
	return args.Bool(0), args.Error(1)
}

func (m *MockTokenRepository) RevokeAccessToken(ctx context.Context, userID string, token string) error {
	args := m.Called(ctx, userID, token)
	return args.Error(0)
}

// Refresh токены (legacy)
func (m *MockTokenRepository) StoreRefreshToken(ctx context.Context, userID string, token string, ttl time.Duration) error {
	args := m.Called(ctx, userID, token, ttl)
	return args.Error(0)
}

func (m *MockTokenRepository) ValidateRefreshToken(ctx context.Context, userID string, token string) (bool, error) {
	args := m.Called(ctx, userID, token)
	return args.Bool(0), args.Error(1)
}

func (m *MockTokenRepository) RevokeRefreshToken(ctx context.Context, userID string, token string) error {
	args := m.Called(ctx, userID, token)
	return args.Error(0)
}

func (m *MockTokenRepository) StoreReplacedRefreshToken(ctx context.Context, oldToken, newAccessToken, newRefreshToken string, ttl time.Duration) error {
	args := m.Called(ctx, oldToken, newAccessToken, newRefreshToken, ttl)
	return args.Error(0)
}

func (m *MockTokenRepository) GetReplacedRefreshToken(ctx context.Context, oldToken string) (string, string, bool, error) {
	args := m.Called(ctx, oldToken)
	return args.String(0), args.String(1), args.Bool(2), args.Error(3)
}

// Управление сессиями
func (m *MockTokenRepository) RevokeAllUserTokens(ctx context.Context, userID string) error {
	args := m.Called(ctx, userID)
	return args.Error(0)
}

func (m *MockTokenRepository) GetUserSessions(ctx context.Context, userID string) ([]string, error) {
	args := m.Called(ctx, userID)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).([]string), args.Error(1)
}

// Refresh token family
func (m *MockTokenRepository) CreateFamily(ctx context.Context, familyID, userID, accessToken, refreshToken string, ttl time.Duration) error {
	args := m.Called(ctx, familyID, userID, accessToken, refreshToken, ttl)
	return args.Error(0)
}

func (m *MockTokenRepository) RotateFamily(ctx context.Context, familyID, expectedOldRefresh, newAccessToken, newRefreshToken string, ttl time.Duration) error {
	args := m.Called(ctx, familyID, expectedOldRefresh, newAccessToken, newRefreshToken, ttl)
	return args.Error(0)
}

func (m *MockTokenRepository) GetFamilyCurrent(ctx context.Context, familyID string) (string, string, string, bool, error) {
	args := m.Called(ctx, familyID)
	return args.String(0), args.String(1), args.String(2), args.Bool(3), args.Error(4)
}

func (m *MockTokenRepository) GetFamilyByRefresh(ctx context.Context, refreshToken string) (string, bool, error) {
	args := m.Called(ctx, refreshToken)
	return args.String(0), args.Bool(1), args.Error(2)
}

func (m *MockTokenRepository) RevokeFamily(ctx context.Context, familyID string) error {
	args := m.Called(ctx, familyID)
	return args.Error(0)
}

func (m *MockTokenRepository) IsFamilyRevoked(ctx context.Context, familyID string) (bool, error) {
	args := m.Called(ctx, familyID)
	return args.Bool(0), args.Error(1)
}

func (m *MockTokenRepository) RevokeAllUserFamilies(ctx context.Context, userID string) error {
	args := m.Called(ctx, userID)
	return args.Error(0)
}

// Верификация email
func (m *MockTokenRepository) StoreVerificationCode(ctx context.Context, userID string, code string, ttl time.Duration) error {
	args := m.Called(ctx, userID, code, ttl)
	return args.Error(0)
}

func (m *MockTokenRepository) GetVerificationCode(ctx context.Context, userID string) (string, error) {
	args := m.Called(ctx, userID)
	return args.String(0), args.Error(1)
}

func (m *MockTokenRepository) DeleteVerificationCode(ctx context.Context, userID string) error {
	args := m.Called(ctx, userID)
	return args.Error(0)
}

// Email verification request
func (m *MockTokenRepository) StoreEmailVerificationRequest(ctx context.Context, userID string, requestID string, ttl time.Duration) error {
	args := m.Called(ctx, userID, requestID, ttl)
	return args.Error(0)
}

func (m *MockTokenRepository) GetEmailVerificationRequest(ctx context.Context, userID string) (string, error) {
	args := m.Called(ctx, userID)
	return args.String(0), args.Error(1)
}

func (m *MockTokenRepository) DeleteEmailVerificationRequest(ctx context.Context, userID string) error {
	args := m.Called(ctx, userID)
	return args.Error(0)
}

// Password reset request
func (m *MockTokenRepository) StorePasswordResetRequest(ctx context.Context, userID string, requestID string, ttl time.Duration) error {
	args := m.Called(ctx, userID, requestID, ttl)
	return args.Error(0)
}

func (m *MockTokenRepository) GetPasswordResetRequest(ctx context.Context, userID string) (string, error) {
	args := m.Called(ctx, userID)
	return args.String(0), args.Error(1)
}

func (m *MockTokenRepository) DeletePasswordResetRequest(ctx context.Context, userID string) error {
	args := m.Called(ctx, userID)
	return args.Error(0)
}

// OAuth
func (m *MockTokenRepository) StoreOAuthState(ctx context.Context, state string, data string, ttl time.Duration) error {
	args := m.Called(ctx, state, data, ttl)
	return args.Error(0)
}

func (m *MockTokenRepository) GetOAuthState(ctx context.Context, state string) (string, error) {
	args := m.Called(ctx, state)
	return args.String(0), args.Error(1)
}

func (m *MockTokenRepository) DeleteOAuthState(ctx context.Context, state string) error {
	args := m.Called(ctx, state)
	return args.Error(0)
}

// === MockTokenService ===

type MockTokenService struct {
	mock.Mock
}

func (m *MockTokenService) GenerateAccessToken(user *entity.User) (string, error) {
	args := m.Called(user)
	return args.String(0), args.Error(1)
}

func (m *MockTokenService) GenerateRefreshToken(user *entity.User) (string, error) {
	args := m.Called(user)
	return args.String(0), args.Error(1)
}

func (m *MockTokenService) GenerateRefreshTokenForFamily(user *entity.User, familyID string) (string, error) {
	args := m.Called(user, familyID)
	return args.String(0), args.Error(1)
}

func (m *MockTokenService) RefreshAccessToken(refreshToken string) (string, error) {
	args := m.Called(refreshToken)
	return args.String(0), args.Error(1)
}

func (m *MockTokenService) ValidateToken(tok string) (bool, error) {
	args := m.Called(tok)
	return args.Bool(0), args.Error(1)
}

func (m *MockTokenService) GetUserIDFromToken(tok string) (string, error) {
	args := m.Called(tok)
	return args.String(0), args.Error(1)
}

func (m *MockTokenService) GetClaimsFromToken(tok string) (*token.TokenClaims, error) {
	args := m.Called(tok)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*token.TokenClaims), args.Error(1)
}

// === MockMailer ===

type MockMailer struct {
	mock.Mock
}

func (m *MockMailer) SendVerificationCode(to, code string) error {
	args := m.Called(to, code)
	return args.Error(0)
}

func (m *MockMailer) SendWelcome(to, username string) error {
	args := m.Called(to, username)
	return args.Error(0)
}

func (m *MockMailer) SendPasswordReset(to, userID, requestID, frontendURL string) error {
	args := m.Called(to, userID, requestID, frontendURL)
	return args.Error(0)
}

func (m *MockMailer) Send(to, subject, body string) error {
	args := m.Called(to, subject, body)
	return args.Error(0)
}

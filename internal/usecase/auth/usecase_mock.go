package usecase

import (
	"context"
	"time"

	"github.com/stretchr/testify/mock"

	"go-auth/internal/entity"
)

type MockUserRepository struct {
	mock.Mock
}

func (m *MockUserRepository) GetUserById(ctx context.Context, id string) (*entity.User, error) {
	args := m.Called(ctx, id)
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

// MockTokenRepository - мок для репозитория токенов в Redis
type MockTokenRepository struct {
	mock.Mock
}

// === Access токены ===

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

// === Refresh токены ===

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

// === Управление сессиями ===

func (m *MockTokenRepository) RevokeAllUserTokens(ctx context.Context, userID string) error {
	args := m.Called(ctx, userID)
	return args.Error(0)
}

func (m *MockTokenRepository) GetUserSessions(ctx context.Context, userID string) ([]string, error) {
	args := m.Called(ctx, userID)
	return args.Get(0).([]string), args.Error(1)
}

// === Верификация email ===

func (m *MockTokenRepository) StoreVerificationCode(ctx context.Context, email string, code string, ttl time.Duration) error {
	args := m.Called(ctx, email, code, ttl)
	return args.Error(0)
}

func (m *MockTokenRepository) GetVerificationCode(ctx context.Context, email string) (string, error) {
	args := m.Called(ctx, email)
	return args.String(0), args.Error(1)
}

func (m *MockTokenRepository) DeleteVerificationCode(ctx context.Context, email string) error {
	args := m.Called(ctx, email)
	return args.Error(0)
}

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

func (m *MockTokenService) RefreshAccessToken(refreshToken string) (string, error) {
	args := m.Called(refreshToken)
	return args.String(0), args.Error(1)
}

func (m *MockTokenService) ValidateToken(token string) (bool, error) {
	args := m.Called(token)
	return args.Bool(0), args.Error(1)
}

func (m *MockTokenService) GetUserIDFromToken(token string) (string, error) {
	args := m.Called(token)
	return args.String(0), args.Error(1)
}

// MockMailer - мок для email сервиса
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

func (m *MockMailer) SendPasswordReset(to, resetLink string) error {
	args := m.Called(to, resetLink)
	return args.Error(0)
}

func (m *MockMailer) Send(to, subject, body string) error {
	args := m.Called(to, subject, body)
	return args.Error(0)
}

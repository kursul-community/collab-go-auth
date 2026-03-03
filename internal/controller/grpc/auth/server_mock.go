package grpcauth

import (
	"github.com/stretchr/testify/mock"
)

type MockAuth struct {
	mock.Mock
}

func (m *MockAuth) Register(email string, password string) (string, string, error) {
	args := m.Called(email, password)
	return args.String(0), args.String(1), args.Error(2)
}

func (m *MockAuth) Login(email string, password string) (string, string, error) {
	args := m.Called(email, password)
	return args.String(0), args.String(1), args.Error(2)
}

func (m *MockAuth) RefreshToken(token string) (string, string, error) {
	args := m.Called(token)
	return args.String(0), args.String(1), args.Error(2)
}

func (m *MockAuth) Logout(token string) error {
	args := m.Called(token)
	return args.Error(0)
}

func (m *MockAuth) ValidateToken(token string) (bool, error) {
	args := m.Called(token)
	return args.Bool(0), args.Error(1)
}

func (m *MockAuth) ResendVerificationEmail(userID string, requestID string) error {
	args := m.Called(userID, requestID)
	return args.Error(0)
}

func (m *MockAuth) VerifyEmail(userID string, requestID string, code string) error {
	args := m.Called(userID, requestID, code)
	return args.Error(0)
}

func (m *MockAuth) RestorePasswordBegin(email string, frontendURL string) error {
	args := m.Called(email, frontendURL)
	return args.Error(0)
}

func (m *MockAuth) RestorePasswordComplete(userID string, requestID string, newPassword string) error {
	args := m.Called(userID, requestID, newPassword)
	return args.Error(0)
}

package grpcauth

import (
	"github.com/stretchr/testify/mock"
)

type MockAuth struct {
	mock.Mock
}

func (m *MockAuth) Register(email string, password string) (string, error) {
	args := m.Called(email, password)
	return args.String(0), args.Error(1)
}

func (m *MockAuth) Login(email string, password string) (string, string, error) {
	args := m.Called(email, password)
	return args.String(0), args.String(1), args.Error(2)
}

func (m *MockAuth) RefreshToken(token string) (string, error) {
	args := m.Called(token)
	return args.String(0), args.Error(1)
}

func (m *MockAuth) ValidateToken(token string) (bool, error) {
	args := m.Called(token)
	return args.Bool(0), args.Error(1)
}

func (m *MockAuth) ResendVerificationEmail(email string, requestID string) (string, string, error) {
	args := m.Called(email, requestID)
	return args.String(0), args.String(1), args.Error(2)
}

func (m *MockAuth) VerifyEmail(email string, code string, requestID string) (bool, string, string, error) {
	args := m.Called(email, code, requestID)
	return args.Bool(0), args.String(1), args.String(2), args.Error(3)
}
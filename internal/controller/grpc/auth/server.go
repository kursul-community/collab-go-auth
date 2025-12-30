package grpcauth

import (
	"context"
	pb "go-auth/gen/auth"
	"go-auth/internal/usecase/auth"
	"go-auth/pkg/validator"
)

var _ pb.AuthServer = (*AuthServer)(nil)

// AuthServer - структура для обработки RPC-методов, реализующая интерфейс pb.AuthServer
type AuthServer struct {
	pb.UnimplementedAuthServer
	auth usecase.AuthUseCase
}

// RequestValidation - структура для валидации запроса
type RequestValidation struct {
	Email    string `validate:"required,email"`
	Password string `validate:"required,min=6,max=128"`
}

// NewAuthServer - конструктор для AuthServer
func NewAuthServer(auth usecase.AuthUseCase) *AuthServer {
	return &AuthServer{auth: auth}
}

// Register - регистрация нового пользователя
func (s *AuthServer) Register(ctx context.Context, req *pb.RegisterRequest) (*pb.RegisterResponse, error) {
	// Подготовка структуры для валидации
	validateReq := &RequestValidation{
		Email:    req.Email,
		Password: req.Password,
	}
	if err := validator.ValidateRequest(validateReq); err != nil {
		return nil, err
	}

	userID, err := s.auth.Register(req.Email, req.Password)
	if err != nil {
		return nil, err
	}
	return &pb.RegisterResponse{UserId: userID}, nil
}

// Login - авторизация пользователя
func (s *AuthServer) Login(ctx context.Context, req *pb.LoginRequest) (*pb.LoginResponse, error) {
	// Подготовка структуры для валидации
	validateReq := &RequestValidation{
		Email:    req.Email,
		Password: req.Password,
	}
	if err := validator.ValidateRequest(validateReq); err != nil {
		return nil, err
	}

	accessToken, refreshToken, err := s.auth.Login(req.Email, req.Password)
	if err != nil {
		return nil, err
	}
	return &pb.LoginResponse{
		AccessToken:  accessToken,
		RefreshToken: refreshToken,
	}, nil
}

// RefreshToken - обновление токена
func (s *AuthServer) RefreshToken(ctx context.Context, req *pb.RefreshTokenRequest) (*pb.RefreshTokenResponse, error) {
	accessToken, err := s.auth.RefreshToken(req.RefreshToken)
	if err != nil {
		return nil, err
	}
	return &pb.RefreshTokenResponse{AccessToken: accessToken}, nil
}

// ValidateToken - проверка токена
func (s *AuthServer) ValidateToken(ctx context.Context, req *pb.ValidateTokenRequest) (*pb.ValidateTokenResponse, error) {
	valid, err := s.auth.ValidateToken(req.AccessToken)
	if err != nil {
		return nil, err
	}
	return &pb.ValidateTokenResponse{Valid: valid}, nil
}

// ResendVerificationEmailValidation - структура для валидации запроса повторной отправки кода
type ResendVerificationEmailValidation struct {
	UserID    string `validate:"required,uuid"`
	RequestID string `validate:"required,uuid"`
}

// ResendVerificationEmail - повторная отправка кода верификации email
func (s *AuthServer) ResendVerificationEmail(ctx context.Context, req *pb.ResendVerificationEmailRequest) (*pb.ResendVerificationEmailResponse, error) {
	// Валидация
	validateReq := &ResendVerificationEmailValidation{
		UserID:    req.UserId,
		RequestID: req.RequestId,
	}
	if err := validator.ValidateRequest(validateReq); err != nil {
		return nil, err
	}

	err := s.auth.ResendVerificationEmail(req.UserId, req.RequestId)
	if err != nil {
		return nil, err
	}
	return &pb.ResendVerificationEmailResponse{}, nil
}

// VerifyEmailValidation - структура для валидации верификации email
type VerifyEmailValidation struct {
	UserID    string `validate:"required,uuid"`
	RequestID string `validate:"required,uuid"`
	Code      string `validate:"required,len=6"`
}

// VerifyEmail - верификация email по коду
func (s *AuthServer) VerifyEmail(ctx context.Context, req *pb.VerifyEmailRequest) (*pb.VerifyEmailResponse, error) {
	// Валидация
	validateReq := &VerifyEmailValidation{
		UserID:    req.UserId,
		RequestID: req.RequestId,
		Code:      req.Code,
	}
	if err := validator.ValidateRequest(validateReq); err != nil {
		return nil, err
	}

	err := s.auth.VerifyEmail(req.UserId, req.RequestId, req.Code)
	if err != nil {
		return nil, err
	}
	return &pb.VerifyEmailResponse{}, nil
}
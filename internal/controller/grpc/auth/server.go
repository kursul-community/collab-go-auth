package grpcauth

import (
	"context"
	"errors"
	"log"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/structpb"

	pb "go-auth/gen/auth"
	usecase "go-auth/internal/usecase/auth"
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
		return nil, status.Error(codes.InvalidArgument, err.Error())
	}

	userID, requestID, err := s.auth.Register(req.Email, req.Password)
	if err != nil {
		if errors.Is(err, usecase.ErrExistingUser) {
			return nil, status.Error(codes.AlreadyExists, err.Error())
		}
		return nil, status.Error(codes.Internal, err.Error())
	}
	return &pb.RegisterResponse{UserId: userID, RequestId: requestID}, nil
}

// Login - авторизация пользователя
func (s *AuthServer) Login(ctx context.Context, req *pb.LoginRequest) (*pb.LoginResponse, error) {
	// Подготовка структуры для валидации
	validateReq := &RequestValidation{
		Email:    req.Email,
		Password: req.Password,
	}
	if err := validator.ValidateRequest(validateReq); err != nil {
		return nil, status.Error(codes.InvalidArgument, err.Error())
	}

	accessToken, refreshToken, err := s.auth.Login(req.Email, req.Password)
	if err != nil {
		if errors.Is(err, usecase.ErrInvalidCredentials) {
			return nil, status.Error(codes.Unauthenticated, "Invalid Credentials")
		}
		
		// Проверяем, является ли ошибка LoginError с userID и requestID
		var loginErr *usecase.LoginError
		if errors.As(err, &loginErr) {
			// Добавляем userID и requestID в metadata ответа
			md := metadata.New(map[string]string{
				"user-id":    loginErr.UserID,
				"request-id": loginErr.RequestID,
			})
			// Устанавливаем metadata через SetHeader для gRPC
			// Это должно работать для передачи через gateway
			grpc.SetHeader(ctx, md)
			
			if errors.Is(loginErr.Err, usecase.ErrUserNotActive) {
				// Создаем статус с Struct в details (только requestId и userId)
				st := status.New(codes.PermissionDenied, "User account is not active")
				detailsStruct, err := structpb.NewStruct(map[string]interface{}{
					"requestId": loginErr.RequestID,
					"userId":    loginErr.UserID,
				})
				if err == nil {
					st, _ = st.WithDetails(detailsStruct)
				}
				return nil, st.Err()
			}
			if errors.Is(loginErr.Err, usecase.ErrEmailNotVerified) {
				// Отправляем код верификации на почту
				if err := s.auth.ResendVerificationEmail(loginErr.UserID, loginErr.RequestID); err != nil {
					// Логируем ошибку, но продолжаем возвращать ошибку с userId и requestId
					// Это важно, чтобы фронтенд получил необходимые данные даже если отправка не удалась
					log.Printf("Failed to resend verification email for user %s (requestID: %s): %v", loginErr.UserID, loginErr.RequestID, err)
				} else {
					log.Printf("Verification code resent for user %s (requestID: %s)", loginErr.UserID, loginErr.RequestID)
				}
				
				// Создаем статус с Struct в details (только requestId и userId)
				st := status.New(codes.PermissionDenied, "Email not verified")
				detailsStruct, err := structpb.NewStruct(map[string]interface{}{
					"requestId": loginErr.RequestID,
					"userId":    loginErr.UserID,
				})
				if err == nil {
					st, _ = st.WithDetails(detailsStruct)
				}
				return nil, st.Err()
			}
		}
		
		return nil, status.Error(codes.Internal, err.Error())
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
		return nil, status.Error(codes.InvalidArgument, err.Error())
	}

	err := s.auth.ResendVerificationEmail(req.UserId, req.RequestId)
	if err != nil {
		if errors.Is(err, usecase.ErrInvalidRequestID) {
			return nil, status.Error(codes.InvalidArgument, err.Error())
		}
		if errors.Is(err, usecase.ErrUserNotFound) {
			return nil, status.Error(codes.NotFound, err.Error())
		}
		if errors.Is(err, usecase.ErrEmailAlreadyVerified) {
			return nil, status.Error(codes.AlreadyExists, err.Error())
		}
		return nil, status.Error(codes.Internal, err.Error())
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
		return nil, status.Error(codes.InvalidArgument, err.Error())
	}

	err := s.auth.VerifyEmail(req.UserId, req.RequestId, req.Code)
	if err != nil {
		if errors.Is(err, usecase.ErrInvalidRequestID) {
			return nil, status.Error(codes.InvalidArgument, err.Error())
		}
		if errors.Is(err, usecase.ErrUserNotFound) {
			return nil, status.Error(codes.NotFound, err.Error())
		}
		if errors.Is(err, usecase.ErrEmailAlreadyVerified) {
			return nil, status.Error(codes.AlreadyExists, err.Error())
		}
		if errors.Is(err, usecase.ErrInvalidVerificationCode) {
			return nil, status.Error(codes.InvalidArgument, err.Error())
		}
		return nil, status.Error(codes.Internal, err.Error())
	}
	return &pb.VerifyEmailResponse{}, nil
}

// === Восстановление пароля ===

// RestorePasswordBeginValidation - структура для валидации запроса начала восстановления пароля
type RestorePasswordBeginValidation struct {
	Email string `validate:"required,email"`
}

// RestorePasswordBegin - начало восстановления пароля
func (s *AuthServer) RestorePasswordBegin(ctx context.Context, req *pb.RestorePasswordBeginRequest) (*pb.RestorePasswordBeginResponse, error) {
	// Валидация
	validateReq := &RestorePasswordBeginValidation{
		Email: req.Email,
	}
	if err := validator.ValidateRequest(validateReq); err != nil {
		return nil, status.Error(codes.InvalidArgument, err.Error())
	}

	// Извлекаем frontend URL из metadata (передается из gateway)
	frontendURL := ""
	if md, ok := metadata.FromIncomingContext(ctx); ok {
		if origins := md.Get("x-frontend-origin"); len(origins) > 0 {
			frontendURL = origins[0]
		}
	}

	err := s.auth.RestorePasswordBegin(req.Email, frontendURL)
	if err != nil {
		// Для безопасности не раскрываем детали ошибки
		return nil, status.Error(codes.Internal, "failed to process request")
	}
	return &pb.RestorePasswordBeginResponse{}, nil
}

// RestorePasswordCompleteValidation - структура для валидации запроса завершения восстановления пароля
type RestorePasswordCompleteValidation struct {
	UserID    string `validate:"required,uuid"`
	RequestID string `validate:"required,uuid"`
	Password  string `validate:"required,min=6,max=128"`
}

// RestorePasswordComplete - завершение восстановления пароля
func (s *AuthServer) RestorePasswordComplete(ctx context.Context, req *pb.RestorePasswordCompleteRequest) (*pb.RestorePasswordCompleteResponse, error) {
	// Валидация
	validateReq := &RestorePasswordCompleteValidation{
		UserID:    req.UserId,
		RequestID: req.RequestId,
		Password:  req.Password,
	}
	if err := validator.ValidateRequest(validateReq); err != nil {
		return nil, status.Error(codes.InvalidArgument, err.Error())
	}

	err := s.auth.RestorePasswordComplete(req.UserId, req.RequestId, req.Password)
	if err != nil {
		if errors.Is(err, usecase.ErrUserNotFound) {
			return nil, status.Error(codes.NotFound, err.Error())
		}
		if errors.Is(err, usecase.ErrInvalidPasswordResetToken) {
			return nil, status.Error(codes.InvalidArgument, err.Error())
		}
		if errors.Is(err, usecase.ErrMinLengthPswd) {
			return nil, status.Error(codes.InvalidArgument, err.Error())
		}
		return nil, status.Error(codes.Internal, err.Error())
	}
	return &pb.RestorePasswordCompleteResponse{}, nil
}
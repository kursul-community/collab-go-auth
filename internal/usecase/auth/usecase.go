package usecase

import (
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"log"
	"math/big"
	"time"

	"github.com/google/uuid"
	"golang.org/x/crypto/bcrypt"

	"go-auth/internal/adapter/email"
	"go-auth/internal/adapter/token"
	"go-auth/internal/entity"
	tokenrepo "go-auth/internal/repo/token"
	"go-auth/internal/repo/user"
)

// TTL для кода верификации email (15 минут)
const VerificationCodeTTL = 15 * time.Minute

// TTL для токена сброса пароля по умолчанию (1 час)
const DefaultPasswordResetTTL = 1 * time.Hour

var (
	ErrInvalidCredentials        = errors.New("invalid credentials")
	ErrExistingUser              = errors.New("email already in use")
	ErrUserNotActive             = errors.New("user account is not active")
	ErrAccessTokenNotFound       = errors.New("access token not found or revoked")
	ErrMinLengthPswd             = errors.New("password length must be between 6 and 128 characters")
	ErrInvalidRefreshToken       = errors.New("invalid or expired refresh token")
	ErrRefreshTokenNotFound      = errors.New("refresh token not found in storage")
	ErrUserNotFound              = errors.New("user not found")
	ErrEmailAlreadyVerified      = errors.New("email already verified")
	ErrInvalidVerificationCode   = errors.New("invalid or expired verification code")
	ErrInvalidRequestID          = errors.New("invalid or expired requestId")
	ErrInvalidPasswordResetToken = errors.New("invalid or expired password reset token")
)

var _ AuthUseCase = (*auth)(nil)

// AuthUseCase - интерфейс для аутентификации
type AuthUseCase interface {
	// Register - регистрация нового пользователя (возвращает userId и requestId для верификации)
	Register(email string, password string) (userId string, requestId string, err error)
	// Login - авторизация пользователя
	Login(email string, password string) (accessToken, refreshToken string, err error)
	// RefreshToken - обновление токена
	RefreshToken(refreshToken string) (accessToken string, err error)
	// ValidateToken - проверка токена
	ValidateToken(accessToken string) (valid bool, err error)
	// ResendVerificationEmail - повторная отправка кода верификации email
	ResendVerificationEmail(userID string, requestID string) error
	// VerifyEmail - верификация email по коду
	VerifyEmail(userID string, requestID string, code string) error
	// RestorePasswordBegin - начало восстановления пароля
	RestorePasswordBegin(email string) error
	// RestorePasswordComplete - завершение восстановления пароля
	RestorePasswordComplete(userID string, requestID string, newPassword string) error
}

// Auth - структура для аутентификации
type auth struct {
	userRepo         user.Repository
	tokenRepo        tokenrepo.Repository // Redis репозиторий для токенов
	tokenService     token.JWTToken
	mailer           email.Mailer // Email сервис для отправки писем
	accessTTL        time.Duration
	refreshTTL       time.Duration
	passwordResetTTL time.Duration // TTL для токена сброса пароля
	frontendURL      string        // URL фронтенда для ссылок
}

// GetBaseAuth - возвращает указатель на базовую структуру auth для использования в OAuth
func GetBaseAuth(uc AuthUseCase) *auth {
	if a, ok := uc.(*auth); ok {
		return a
	}
	return nil
}

// NewAuthUseCase - конструктор для auth
func NewAuthUseCase(
	userRepo user.Repository,
	tokenRepo tokenrepo.Repository,
	tokenSvc token.JWTToken,
	mailer email.Mailer,
	accessTTL, refreshTTL time.Duration,
	passwordResetTTL time.Duration,
	frontendURL string,
) AuthUseCase {
	if passwordResetTTL == 0 {
		passwordResetTTL = DefaultPasswordResetTTL
	}
	return &auth{
		userRepo:         userRepo,
		tokenRepo:        tokenRepo,
		tokenService:     tokenSvc,
		mailer:           mailer,
		accessTTL:        accessTTL,
		refreshTTL:       refreshTTL,
		passwordResetTTL: passwordResetTTL,
		frontendURL:      frontendURL,
	}
}

// generateVerificationCode - генерация 6-значного кода верификации
func generateVerificationCode() (string, error) {
	// Генерируем случайное число от 100000 до 999999
	max := big.NewInt(900000)
	n, err := rand.Int(rand.Reader, max)
	if err != nil {
		return "", err
	}
	code := n.Int64() + 100000
	return fmt.Sprintf("%06d", code), nil
}

// sendVerificationCode - отправка кода верификации на email
func (uc *auth) sendVerificationCode(emailAddr string, code string, requestID string) error {
	log.Printf("[RequestID: %s] Sending verification code to %s", requestID, emailAddr)

	// Отправляем письмо с кодом верификации
	if err := uc.mailer.SendVerificationCode(emailAddr, code); err != nil {
		log.Printf("[RequestID: %s] Failed to send verification email: %v", requestID, err)
		return fmt.Errorf("failed to send verification email: %w", err)
	}

	log.Printf("[RequestID: %s] Verification email sent successfully to %s", requestID, emailAddr)
	return nil
}

// Register - регистрация нового пользователя
func (uc *auth) Register(email string, password string) (string, string, error) {
	ctx := context.Background()

	// Проверка сложности и длины пароля
	if len(password) < 6 || len(password) > 128 {
		return "", "", ErrMinLengthPswd
	}

	// Проверяем, что пользователя с таким email не существует
	existingUser, err := uc.userRepo.GetUserByEmail(ctx, email)
	if err == nil && existingUser != nil {
		return "", "", ErrExistingUser
	}

	// Хэшируем пароль
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return "", "", err
	}

	// Генерация ID пользователя
	userID := uuid.New().String()

	// Создаем нового пользователя
	newUser := &entity.User{
		ID:            userID,
		Email:         email,
		Password:      string(hashedPassword),
		CreatedAt:     time.Now(),
		IsActive:      true,  // Пользователь активен по умолчанию
		EmailVerified: false, // Email не подтвержден
	}

	createdID, err := uc.userRepo.CreateUser(ctx, newUser)
	if err != nil {
		return "", "", err
	}

	// Генерируем случайный requestID для верификации email
	requestID := uuid.New().String()

	// Генерируем код верификации
	code, err := generateVerificationCode()
	if err != nil {
		return createdID, requestID, nil // Пользователь создан, но код не отправлен
	}

	// Сохраняем код в Redis по userID
	err = uc.tokenRepo.StoreVerificationCode(ctx, createdID, code, VerificationCodeTTL)
	if err != nil {
		return createdID, requestID, nil // Пользователь создан, но код не сохранен
	}

	// Сохраняем requestID в Redis для валидации при верификации
	err = uc.tokenRepo.StoreEmailVerificationRequest(ctx, createdID, requestID, VerificationCodeTTL)
	if err != nil {
		log.Printf("Failed to store email verification request: %v", err)
	}

	// Отправляем код на email
	uc.sendVerificationCode(email, code, requestID)

	log.Printf("User registered: %s, requestID: %s", createdID, requestID)
	return createdID, requestID, nil
}

// ResendVerificationEmail - повторная отправка кода верификации email
func (uc *auth) ResendVerificationEmail(userID string, requestID string) error {
	ctx := context.Background()

	log.Printf("[RequestID: %s] ResendVerificationEmail request for userID: %s", requestID, userID)

	// Проверяем, существует ли пользователь по ID
	curUser, err := uc.userRepo.GetUserById(ctx, userID)
	if err != nil || curUser == nil {
		log.Printf("[RequestID: %s] User not found: %s", requestID, userID)
		return ErrUserNotFound
	}

	// Проверяем, не подтвержден ли уже email
	if curUser.EmailVerified {
		log.Printf("[RequestID: %s] Email already verified for user: %s", requestID, userID)
		return ErrEmailAlreadyVerified
	}

	// Проверяем requestID в Redis
	storedRequestID, err := uc.tokenRepo.GetEmailVerificationRequest(ctx, userID)
	if err != nil {
		log.Printf("[RequestID: %s] Failed to get email verification request: %v", requestID, err)
		return fmt.Errorf("failed to get email verification request: %w", err)
	}

	// Проверяем, что requestID совпадает
	if storedRequestID == "" || storedRequestID != requestID {
		log.Printf("[RequestID: %s] Invalid requestID for user %s (expected: %s)", requestID, userID, storedRequestID)
		return ErrInvalidRequestID
	}

	// Генерируем новый код верификации
	code, err := generateVerificationCode()
	if err != nil {
		log.Printf("[RequestID: %s] Failed to generate verification code: %v", requestID, err)
		return fmt.Errorf("failed to generate verification code: %w", err)
	}

	log.Printf("[RequestID: %s] Generated verification code for user %s", requestID, userID)

	// Сохраняем код в Redis по userID (перезаписывает старый)
	err = uc.tokenRepo.StoreVerificationCode(ctx, userID, code, VerificationCodeTTL)
	if err != nil {
		log.Printf("[RequestID: %s] Failed to store verification code: %v", requestID, err)
		return fmt.Errorf("failed to store verification code: %w", err)
	}

	// Обновляем TTL для requestID (сбрасываем таймер)
	err = uc.tokenRepo.StoreEmailVerificationRequest(ctx, userID, requestID, VerificationCodeTTL)
	if err != nil {
		log.Printf("[RequestID: %s] Failed to update email verification request TTL: %v", requestID, err)
	}

	// Отправляем код на email
	err = uc.sendVerificationCode(curUser.Email, code, requestID)
	if err != nil {
		log.Printf("[RequestID: %s] Failed to send verification code: %v", requestID, err)
		return fmt.Errorf("failed to send verification code: %w", err)
	}

	log.Printf("[RequestID: %s] Verification code sent successfully to user %s", requestID, userID)
	return nil
}

// VerifyEmail - верификация email по коду
func (uc *auth) VerifyEmail(userID string, requestID string, code string) error {
	ctx := context.Background()

	log.Printf("[RequestID: %s] VerifyEmail request for userID: %s", requestID, userID)

	// Проверяем, существует ли пользователь по ID
	curUser, err := uc.userRepo.GetUserById(ctx, userID)
	if err != nil || curUser == nil {
		log.Printf("[RequestID: %s] User not found: %s", requestID, userID)
		return ErrUserNotFound
	}

	// Проверяем, не подтвержден ли уже email
	if curUser.EmailVerified {
		log.Printf("[RequestID: %s] Email already verified for user: %s", requestID, userID)
		return ErrEmailAlreadyVerified
	}

	// Проверяем requestID в Redis
	storedRequestID, err := uc.tokenRepo.GetEmailVerificationRequest(ctx, userID)
	if err != nil {
		log.Printf("[RequestID: %s] Failed to get email verification request: %v", requestID, err)
		return fmt.Errorf("failed to get email verification request: %w", err)
	}

	// Проверяем, что requestID совпадает
	if storedRequestID == "" || storedRequestID != requestID {
		log.Printf("[RequestID: %s] Invalid requestID for user %s (expected: %s)", requestID, userID, storedRequestID)
		return ErrInvalidRequestID
	}

	// Получаем код из Redis по userID
	storedCode, err := uc.tokenRepo.GetVerificationCode(ctx, userID)
	if err != nil {
		log.Printf("[RequestID: %s] Failed to get verification code: %v", requestID, err)
		return fmt.Errorf("failed to get verification code: %w", err)
	}

	// Проверяем код
	if storedCode == "" || storedCode != code {
		log.Printf("[RequestID: %s] Invalid verification code for user %s", requestID, userID)
		return ErrInvalidVerificationCode
	}

	// Устанавливаем email_verified = true
	err = uc.userRepo.SetEmailVerified(ctx, userID, true)
	if err != nil {
		log.Printf("[RequestID: %s] Failed to verify email: %v", requestID, err)
		return fmt.Errorf("failed to verify email: %w", err)
	}

	// Удаляем код и requestID из Redis
	uc.tokenRepo.DeleteVerificationCode(ctx, userID)
	uc.tokenRepo.DeleteEmailVerificationRequest(ctx, userID)

	log.Printf("[RequestID: %s] Email verified successfully for user: %s", requestID, userID)
	return nil
}

// RestorePasswordBegin - начало восстановления пароля
func (uc *auth) RestorePasswordBegin(emailAddr string) error {
	ctx := context.Background()

	log.Printf("RestorePasswordBegin request for email: %s", emailAddr)

	// Проверяем, существует ли пользователь
	curUser, err := uc.userRepo.GetUserByEmail(ctx, emailAddr)
	if err != nil || curUser == nil {
		// Для безопасности не раскрываем, существует ли пользователь
		log.Printf("User not found for password reset: %s (returning success anyway)", emailAddr)
		return nil // Возвращаем успех, чтобы не раскрывать информацию
	}

	// Генерируем уникальный requestID для сброса пароля
	requestID := uuid.New().String()

	// Сохраняем requestID в Redis
	err = uc.tokenRepo.StorePasswordResetRequest(ctx, curUser.ID, requestID, uc.passwordResetTTL)
	if err != nil {
		log.Printf("Failed to store password reset request: %v", err)
		return fmt.Errorf("failed to store password reset request: %w", err)
	}

	log.Printf("Password reset requestID generated for user %s: %s", curUser.ID, requestID)

	// Отправляем email со ссылкой для сброса пароля
	err = uc.mailer.SendPasswordReset(emailAddr, curUser.ID, requestID, uc.frontendURL)
	if err != nil {
		log.Printf("Failed to send password reset email: %v", err)
		return fmt.Errorf("failed to send password reset email: %w", err)
	}

	log.Printf("Password reset email sent to: %s", emailAddr)
	return nil
}

// RestorePasswordComplete - завершение восстановления пароля
func (uc *auth) RestorePasswordComplete(userID string, requestID string, newPassword string) error {
	ctx := context.Background()

	log.Printf("[RequestID: %s] RestorePasswordComplete request for userID: %s", requestID, userID)

	// Проверка длины пароля
	if len(newPassword) < 6 || len(newPassword) > 128 {
		return ErrMinLengthPswd
	}

	// Проверяем, существует ли пользователь
	curUser, err := uc.userRepo.GetUserById(ctx, userID)
	if err != nil || curUser == nil {
		log.Printf("[RequestID: %s] User not found: %s", requestID, userID)
		return ErrUserNotFound
	}

	// Проверяем requestID в Redis
	storedRequestID, err := uc.tokenRepo.GetPasswordResetRequest(ctx, userID)
	if err != nil {
		log.Printf("[RequestID: %s] Failed to get password reset request: %v", requestID, err)
		return fmt.Errorf("failed to get password reset request: %w", err)
	}

	// Проверяем, что requestID совпадает
	if storedRequestID == "" || storedRequestID != requestID {
		log.Printf("[RequestID: %s] Invalid password reset token for user %s", requestID, userID)
		return ErrInvalidPasswordResetToken
	}

	// Хэшируем новый пароль
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(newPassword), bcrypt.DefaultCost)
	if err != nil {
		log.Printf("[RequestID: %s] Failed to hash password: %v", requestID, err)
		return fmt.Errorf("failed to hash password: %w", err)
	}

	// Обновляем пароль в базе данных
	err = uc.userRepo.UpdatePassword(ctx, userID, string(hashedPassword))
	if err != nil {
		log.Printf("[RequestID: %s] Failed to update password: %v", requestID, err)
		return fmt.Errorf("failed to update password: %w", err)
	}

	// Удаляем использованный requestID из Redis
	uc.tokenRepo.DeletePasswordResetRequest(ctx, userID)

	// Отзываем все существующие токены пользователя (для безопасности)
	uc.tokenRepo.RevokeAllUserTokens(ctx, userID)

	log.Printf("[RequestID: %s] Password reset successfully for user: %s", requestID, userID)
	return nil
}

// Login - авторизация пользователя
func (uc *auth) Login(email string, password string) (string, string, error) {
	ctx := context.Background()

	// Получаем пользователя
	curUser, err := uc.userRepo.GetUserByEmail(ctx, email)
	if err != nil || curUser == nil {
		return "", "", ErrInvalidCredentials
	}

	// Проверяем пароль
	if err := bcrypt.CompareHashAndPassword([]byte(curUser.Password), []byte(password)); err != nil {
		return "", "", ErrInvalidCredentials
	}

	// Проверяем, активен ли пользователь
	if !curUser.IsActive {
		return "", "", ErrUserNotActive
	}

	// Генерируем access токен
	accessToken, err := uc.tokenService.GenerateAccessToken(curUser)
	if err != nil {
		return "", "", err
	}

	// Генерируем refresh токен
	refreshToken, err := uc.tokenService.GenerateRefreshToken(curUser)
	if err != nil {
		return "", "", err
	}

	// Сохраняем access токен в Redis
	err = uc.tokenRepo.StoreAccessToken(ctx, curUser.ID, accessToken, uc.accessTTL)
	if err != nil {
		return "", "", fmt.Errorf("failed to store access token: %w", err)
	}

	// Сохраняем refresh токен в Redis
	err = uc.tokenRepo.StoreRefreshToken(ctx, curUser.ID, refreshToken, uc.refreshTTL)
	if err != nil {
		return "", "", fmt.Errorf("failed to store refresh token: %w", err)
	}

	return accessToken, refreshToken, nil
}

// RefreshToken - обновление токена
func (uc *auth) RefreshToken(refreshToken string) (string, error) {
	ctx := context.Background()

	// Проверяем валидность JWT токена (подпись и срок действия)
	isValid, err := uc.tokenService.ValidateToken(refreshToken)
	if !isValid || err != nil {
		return "", ErrInvalidRefreshToken
	}

	// Получаем userID из токена
	userID, err := uc.tokenService.GetUserIDFromToken(refreshToken)
	if err != nil {
		return "", ErrInvalidRefreshToken
	}

	// Проверяем, что refresh токен существует в Redis (не был отозван)
	exists, err := uc.tokenRepo.ValidateRefreshToken(ctx, userID, refreshToken)
	if err != nil {
		return "", fmt.Errorf("failed to validate refresh token: %w", err)
	}
	if !exists {
		return "", ErrRefreshTokenNotFound
	}

	// Генерация нового access токена
	newAccessToken, err := uc.tokenService.RefreshAccessToken(refreshToken)
	if err != nil {
		return "", fmt.Errorf("failed to generate access token: %w", err)
	}

	// Сохраняем новый access токен в Redis
	err = uc.tokenRepo.StoreAccessToken(ctx, userID, newAccessToken, uc.accessTTL)
	if err != nil {
		return "", fmt.Errorf("failed to store new access token: %w", err)
	}

	return newAccessToken, nil
}

// ValidateToken - проверка access токена
func (uc *auth) ValidateToken(accessToken string) (bool, error) {
	ctx := context.Background()

	// Проверяем валидность JWT токена (подпись и срок действия)
	isValid, err := uc.tokenService.ValidateToken(accessToken)
	if err != nil {
		return false, err
	}
	if !isValid {
		return false, nil
	}

	// Проверяем, существует ли токен в Redis (не был отозван)
	exists, err := uc.tokenRepo.ValidateAccessToken(ctx, accessToken)
	if err != nil {
		return false, fmt.Errorf("failed to validate access token: %w", err)
	}
	if !exists {
		return false, ErrAccessTokenNotFound
	}

	return true, nil
}

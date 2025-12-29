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

var (
	ErrInvalidCredentials      = errors.New("invalid credentials")
	ErrExistingUser            = errors.New("email already in use")
	ErrUserNotActive           = errors.New("user account is not active")
	ErrAccessTokenNotFound     = errors.New("access token not found or revoked")
	ErrMinLengthPswd           = errors.New("password length must be between 6 and 128 characters")
	ErrInvalidRefreshToken     = errors.New("invalid or expired refresh token")
	ErrRefreshTokenNotFound    = errors.New("refresh token not found in storage")
	ErrUserNotFound            = errors.New("user not found")
	ErrEmailAlreadyVerified    = errors.New("email already verified")
	ErrInvalidVerificationCode = errors.New("invalid or expired verification code")
)

var _ AuthUseCase = (*auth)(nil)

// AuthUseCase - интерфейс для аутентификации
type AuthUseCase interface {
	// Register - регистрация нового пользователя
	Register(email string, password string) (userId string, err error)
	// Login - авторизация пользователя
	Login(email string, password string) (accessToken, refreshToken string, err error)
	// RefreshToken - обновление токена
	RefreshToken(refreshToken string) (accessToken string, err error)
	// ValidateToken - проверка токена
	ValidateToken(accessToken string) (valid bool, err error)
	// ResendVerificationEmail - повторная отправка кода верификации email
	ResendVerificationEmail(email string, requestID string) (message string, requestIDOut string, err error)
	// VerifyEmail - верификация email по коду
	VerifyEmail(email string, code string, requestID string) (success bool, message string, requestIDOut string, err error)
}

// Auth - структура для аутентификации
type auth struct {
	userRepo     user.Repository
	tokenRepo    tokenrepo.Repository // Redis репозиторий для токенов
	tokenService token.JWTToken
	mailer       email.Mailer // Email сервис для отправки писем
	accessTTL    time.Duration
	refreshTTL   time.Duration
}

// NewAuthUseCase - конструктор для auth
func NewAuthUseCase(
	userRepo user.Repository,
	tokenRepo tokenrepo.Repository,
	tokenSvc token.JWTToken,
	mailer email.Mailer,
	accessTTL, refreshTTL time.Duration,
) AuthUseCase {
	return &auth{
		userRepo:     userRepo,
		tokenRepo:    tokenRepo,
		tokenService: tokenSvc,
		mailer:       mailer,
		accessTTL:    accessTTL,
		refreshTTL:   refreshTTL,
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
func (uc *auth) Register(email string, password string) (string, error) {
	ctx := context.Background()

	// Проверка сложности и длины пароля
	if len(password) < 6 || len(password) > 128 {
		return "", ErrMinLengthPswd
	}

	// Проверяем, что пользователя с таким email не существует
	existingUser, err := uc.userRepo.GetUserByEmail(ctx, email)
	if err == nil && existingUser != nil {
		return "", ErrExistingUser
	}

	// Хэшируем пароль
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return "", err
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
		return "", err
	}

	// Генерируем и отправляем код верификации
	code, err := generateVerificationCode()
	if err != nil {
		return createdID, nil // Пользователь создан, но код не отправлен
	}

	// Сохраняем код в Redis
	err = uc.tokenRepo.StoreVerificationCode(ctx, email, code, VerificationCodeTTL)
	if err != nil {
		return createdID, nil // Пользователь создан, но код не сохранен
	}

	// Отправляем код на email (при регистрации requestID не используется)
	uc.sendVerificationCode(email, code, "")

	return createdID, nil
}

// ResendVerificationEmail - повторная отправка кода верификации email
func (uc *auth) ResendVerificationEmail(email string, requestID string) (string, string, error) {
	ctx := context.Background()

	// Генерируем requestID если не передан
	if requestID == "" {
		requestID = uuid.New().String()
	}

	log.Printf("[RequestID: %s] ResendVerificationEmail request for email: %s", requestID, email)

	// Проверяем, существует ли пользователь
	curUser, err := uc.userRepo.GetUserByEmail(ctx, email)
	if err != nil || curUser == nil {
		log.Printf("[RequestID: %s] User not found: %s", requestID, email)
		return "", requestID, ErrUserNotFound
	}

	// Проверяем, не подтвержден ли уже email
	if curUser.EmailVerified {
		log.Printf("[RequestID: %s] Email already verified: %s", requestID, email)
		return "", requestID, ErrEmailAlreadyVerified
	}

	// Генерируем новый код верификации
	code, err := generateVerificationCode()
	if err != nil {
		log.Printf("[RequestID: %s] Failed to generate verification code: %v", requestID, err)
		return "", requestID, fmt.Errorf("failed to generate verification code: %w", err)
	}

	log.Printf("[RequestID: %s] Generated verification code for %s", requestID, email)

	// Сохраняем код в Redis (перезаписывает старый)
	err = uc.tokenRepo.StoreVerificationCode(ctx, email, code, VerificationCodeTTL)
	if err != nil {
		log.Printf("[RequestID: %s] Failed to store verification code: %v", requestID, err)
		return "", requestID, fmt.Errorf("failed to store verification code: %w", err)
	}

	// Отправляем код на email
	err = uc.sendVerificationCode(email, code, requestID)
	if err != nil {
		log.Printf("[RequestID: %s] Failed to send verification code: %v", requestID, err)
		return "", requestID, fmt.Errorf("failed to send verification code: %w", err)
	}

	log.Printf("[RequestID: %s] Verification code sent successfully to %s", requestID, email)
	return "Verification code sent successfully", requestID, nil
}

// VerifyEmail - верификация email по коду
func (uc *auth) VerifyEmail(email string, code string, requestID string) (bool, string, string, error) {
	ctx := context.Background()

	// Генерируем requestID если не передан
	if requestID == "" {
		requestID = uuid.New().String()
	}

	log.Printf("[RequestID: %s] VerifyEmail request for email: %s", requestID, email)

	// Проверяем, существует ли пользователь
	curUser, err := uc.userRepo.GetUserByEmail(ctx, email)
	if err != nil || curUser == nil {
		log.Printf("[RequestID: %s] User not found: %s", requestID, email)
		return false, "", requestID, ErrUserNotFound
	}

	// Проверяем, не подтвержден ли уже email
	if curUser.EmailVerified {
		log.Printf("[RequestID: %s] Email already verified: %s", requestID, email)
		return true, "Email already verified", requestID, nil
	}

	// Получаем код из Redis
	storedCode, err := uc.tokenRepo.GetVerificationCode(ctx, email)
	if err != nil {
		log.Printf("[RequestID: %s] Failed to get verification code: %v", requestID, err)
		return false, "", requestID, fmt.Errorf("failed to get verification code: %w", err)
	}

	// Проверяем код
	if storedCode == "" || storedCode != code {
		log.Printf("[RequestID: %s] Invalid verification code for %s", requestID, email)
		return false, "", requestID, ErrInvalidVerificationCode
	}

	// Устанавливаем email_verified = true
	err = uc.userRepo.SetEmailVerified(ctx, curUser.ID, true)
	if err != nil {
		log.Printf("[RequestID: %s] Failed to verify email: %v", requestID, err)
		return false, "", requestID, fmt.Errorf("failed to verify email: %w", err)
	}

	// Удаляем код из Redis
	uc.tokenRepo.DeleteVerificationCode(ctx, email)

	log.Printf("[RequestID: %s] Email verified successfully: %s", requestID, email)
	return true, "Email verified successfully", requestID, nil
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

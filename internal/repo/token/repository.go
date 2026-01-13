package token

import (
	"context"
	"fmt"
	"time"

	"github.com/redis/go-redis/v9"
)

// Префиксы ключей в Redis
const (
	accessTokenPrefix              = "access_token:"               // Префикс для активных access токенов
	refreshTokenPrefix             = "refresh_token:"              // Префикс для refresh токенов
	userSessionsPrefix             = "user_sessions:"              // Префикс для списка сессий пользователя
	userAccessTokens               = "user_access:"                // Префикс для списка access токенов пользователя
	emailVerificationPrefix        = "email_verification:"         // Префикс для кодов верификации email
	emailVerificationRequestPrefix = "email_verification_request:" // Префикс для requestID верификации email
	passwordResetRequestPrefix     = "password_reset_request:"     // Префикс для requestID сброса пароля
	oauthStatePrefix               = "oauth_state:"                // Префикс для OAuth state (CSRF защита)
)

// Убедимся, что repository реализует интерфейс Repository
var _ Repository = (*repository)(nil)

// Repository - интерфейс для работы с токенами в Redis
type Repository interface {
	// === Access токены ===
	// StoreAccessToken - сохранение access токена
	StoreAccessToken(ctx context.Context, userID string, token string, ttl time.Duration) error
	// ValidateAccessToken - проверка существования access токена в Redis
	ValidateAccessToken(ctx context.Context, token string) (bool, error)
	// RevokeAccessToken - отзыв access токена
	RevokeAccessToken(ctx context.Context, userID string, token string) error

	// === Refresh токены ===
	// StoreRefreshToken - сохранение refresh токена
	StoreRefreshToken(ctx context.Context, userID string, token string, ttl time.Duration) error
	// ValidateRefreshToken - проверка валидности refresh токена
	ValidateRefreshToken(ctx context.Context, userID string, token string) (bool, error)
	// RevokeRefreshToken - отзыв refresh токена
	RevokeRefreshToken(ctx context.Context, userID string, token string) error

	// === Управление сессиями ===
	// RevokeAllUserTokens - отзыв всех токенов пользователя (logout everywhere)
	RevokeAllUserTokens(ctx context.Context, userID string) error
	// GetUserSessions - получение всех активных сессий пользователя
	GetUserSessions(ctx context.Context, userID string) ([]string, error)

	// === Верификация email ===
	// StoreVerificationCode - сохранение кода верификации email (по userID)
	StoreVerificationCode(ctx context.Context, userID string, code string, ttl time.Duration) error
	// GetVerificationCode - получение кода верификации email (по userID)
	GetVerificationCode(ctx context.Context, userID string) (string, error)
	// DeleteVerificationCode - удаление кода верификации email (по userID)
	DeleteVerificationCode(ctx context.Context, userID string) error

	// === Email verification request ===
	// StoreEmailVerificationRequest - сохранение requestID для верификации email
	StoreEmailVerificationRequest(ctx context.Context, userID string, requestID string, ttl time.Duration) error
	// GetEmailVerificationRequest - получение requestID для верификации email
	GetEmailVerificationRequest(ctx context.Context, userID string) (string, error)
	// DeleteEmailVerificationRequest - удаление requestID после верификации
	DeleteEmailVerificationRequest(ctx context.Context, userID string) error

	// === Password reset request ===
	// StorePasswordResetRequest - сохранение requestID для сброса пароля
	StorePasswordResetRequest(ctx context.Context, userID string, requestID string, ttl time.Duration) error
	// GetPasswordResetRequest - получение requestID для сброса пароля
	GetPasswordResetRequest(ctx context.Context, userID string) (string, error)
	// DeletePasswordResetRequest - удаление requestID после сброса пароля
	DeletePasswordResetRequest(ctx context.Context, userID string) error

	// === OAuth ===
	// StoreOAuthState - сохранение OAuth state (теперь сохраняет произвольную строку данных)
	StoreOAuthState(ctx context.Context, state string, data string, ttl time.Duration) error
	// GetOAuthState - получение данных по OAuth state
	GetOAuthState(ctx context.Context, state string) (string, error)
	// DeleteOAuthState - удаление OAuth state
	DeleteOAuthState(ctx context.Context, state string) error
}

// repository - структура репозитория для работы с Redis
type repository struct {
	client *redis.Client
}

// NewRepository - конструктор для repository
func NewRepository(client *redis.Client) Repository {
	return &repository{client: client}
}

// ==================== Access токены ====================

// StoreAccessToken - сохранение access токена в Redis
func (r *repository) StoreAccessToken(ctx context.Context, userID string, token string, ttl time.Duration) error {
	// Сохраняем токен с привязкой к userID
	tokenKey := accessTokenPrefix + token
	err := r.client.Set(ctx, tokenKey, userID, ttl).Err()
	if err != nil {
		return fmt.Errorf("failed to store access token: %w", err)
	}

	// Добавляем токен в список access токенов пользователя
	userTokensKey := userAccessTokens + userID
	err = r.client.SAdd(ctx, userTokensKey, token).Err()
	if err != nil {
		return fmt.Errorf("failed to add access token to user list: %w", err)
	}

	// Устанавливаем TTL для списка (обновляем при каждом новом токене)
	r.client.Expire(ctx, userTokensKey, ttl)

	return nil
}

// ValidateAccessToken - проверка существования access токена в Redis
func (r *repository) ValidateAccessToken(ctx context.Context, token string) (bool, error) {
	tokenKey := accessTokenPrefix + token
	result, err := r.client.Exists(ctx, tokenKey).Result()
	if err != nil {
		return false, fmt.Errorf("failed to validate access token: %w", err)
	}
	return result > 0, nil
}

// RevokeAccessToken - отзыв access токена (удаление из Redis)
func (r *repository) RevokeAccessToken(ctx context.Context, userID string, token string) error {
	// Удаляем токен
	tokenKey := accessTokenPrefix + token
	err := r.client.Del(ctx, tokenKey).Err()
	if err != nil {
		return fmt.Errorf("failed to revoke access token: %w", err)
	}

	// Удаляем из списка access токенов пользователя
	userTokensKey := userAccessTokens + userID
	r.client.SRem(ctx, userTokensKey, token)

	return nil
}

// StoreRefreshToken - сохранение refresh токена в Redis
// Хранит токен и добавляет его в список сессий пользователя
func (r *repository) StoreRefreshToken(ctx context.Context, userID string, token string, ttl time.Duration) error {
	// Сохраняем токен с привязкой к userID
	tokenKey := refreshTokenPrefix + token
	err := r.client.Set(ctx, tokenKey, userID, ttl).Err()
	if err != nil {
		return fmt.Errorf("failed to store refresh token: %w", err)
	}

	// Добавляем токен в список сессий пользователя (для возможности отзыва всех токенов)
	sessionsKey := userSessionsPrefix + userID
	err = r.client.SAdd(ctx, sessionsKey, token).Err()
	if err != nil {
		return fmt.Errorf("failed to add token to user sessions: %w", err)
	}

	// Устанавливаем TTL для списка сессий (обновляем при каждом новом токене)
	r.client.Expire(ctx, sessionsKey, ttl)

	return nil
}

// ValidateRefreshToken - проверка валидности refresh токена
func (r *repository) ValidateRefreshToken(ctx context.Context, userID string, token string) (bool, error) {
	tokenKey := refreshTokenPrefix + token
	storedUserID, err := r.client.Get(ctx, tokenKey).Result()
	if err == redis.Nil {
		return false, nil // Токен не найден
	}
	if err != nil {
		return false, fmt.Errorf("failed to validate refresh token: %w", err)
	}

	// Проверяем, что токен принадлежит указанному пользователю
	return storedUserID == userID, nil
}

// RevokeRefreshToken - отзыв конкретного refresh токена
func (r *repository) RevokeRefreshToken(ctx context.Context, userID string, token string) error {
	// Удаляем токен
	tokenKey := refreshTokenPrefix + token
	err := r.client.Del(ctx, tokenKey).Err()
	if err != nil {
		return fmt.Errorf("failed to revoke refresh token: %w", err)
	}

	// Удаляем токен из списка сессий пользователя
	sessionsKey := userSessionsPrefix + userID
	err = r.client.SRem(ctx, sessionsKey, token).Err()
	if err != nil {
		return fmt.Errorf("failed to remove token from user sessions: %w", err)
	}

	return nil
}

// RevokeAllUserTokens - отзыв всех токенов пользователя (access + refresh)
func (r *repository) RevokeAllUserTokens(ctx context.Context, userID string) error {
	// Удаляем все refresh токены
	sessionsKey := userSessionsPrefix + userID
	refreshTokens, err := r.client.SMembers(ctx, sessionsKey).Result()
	if err != nil {
		return fmt.Errorf("failed to get user sessions: %w", err)
	}

	for _, token := range refreshTokens {
		tokenKey := refreshTokenPrefix + token
		r.client.Del(ctx, tokenKey)
	}

	// Удаляем список refresh сессий
	r.client.Del(ctx, sessionsKey)

	// Удаляем все access токены
	accessTokensKey := userAccessTokens + userID
	accessTokens, err := r.client.SMembers(ctx, accessTokensKey).Result()
	if err != nil {
		return fmt.Errorf("failed to get user access tokens: %w", err)
	}

	for _, token := range accessTokens {
		tokenKey := accessTokenPrefix + token
		r.client.Del(ctx, tokenKey)
	}

	// Удаляем список access токенов
	r.client.Del(ctx, accessTokensKey)

	return nil
}

// GetUserSessions - получение всех активных сессий пользователя
func (r *repository) GetUserSessions(ctx context.Context, userID string) ([]string, error) {
	sessionsKey := userSessionsPrefix + userID
	tokens, err := r.client.SMembers(ctx, sessionsKey).Result()
	if err != nil {
		return nil, fmt.Errorf("failed to get user sessions: %w", err)
	}
	return tokens, nil
}

// ==================== Верификация email ====================

// StoreVerificationCode - сохранение кода верификации email в Redis (по userID)
func (r *repository) StoreVerificationCode(ctx context.Context, userID string, code string, ttl time.Duration) error {
	key := emailVerificationPrefix + userID
	err := r.client.Set(ctx, key, code, ttl).Err()
	if err != nil {
		return fmt.Errorf("failed to store verification code: %w", err)
	}
	return nil
}

// GetVerificationCode - получение кода верификации email из Redis (по userID)
func (r *repository) GetVerificationCode(ctx context.Context, userID string) (string, error) {
	key := emailVerificationPrefix + userID
	code, err := r.client.Get(ctx, key).Result()
	if err == redis.Nil {
		return "", nil // Код не найден
	}
	if err != nil {
		return "", fmt.Errorf("failed to get verification code: %w", err)
	}
	return code, nil
}

// DeleteVerificationCode - удаление кода верификации email из Redis (по userID)
func (r *repository) DeleteVerificationCode(ctx context.Context, userID string) error {
	key := emailVerificationPrefix + userID
	err := r.client.Del(ctx, key).Err()
	if err != nil {
		return fmt.Errorf("failed to delete verification code: %w", err)
	}
	return nil
}

// ==================== Email verification request ====================

// StoreEmailVerificationRequest - сохранение requestID для верификации email в Redis
func (r *repository) StoreEmailVerificationRequest(ctx context.Context, userID string, requestID string, ttl time.Duration) error {
	key := emailVerificationRequestPrefix + userID
	err := r.client.Set(ctx, key, requestID, ttl).Err()
	if err != nil {
		return fmt.Errorf("failed to store email verification request: %w", err)
	}
	return nil
}

// GetEmailVerificationRequest - получение requestID для верификации email из Redis
func (r *repository) GetEmailVerificationRequest(ctx context.Context, userID string) (string, error) {
	key := emailVerificationRequestPrefix + userID
	requestID, err := r.client.Get(ctx, key).Result()
	if err == redis.Nil {
		return "", nil // RequestID не найден
	}
	if err != nil {
		return "", fmt.Errorf("failed to get email verification request: %w", err)
	}
	return requestID, nil
}

// DeleteEmailVerificationRequest - удаление requestID после верификации email из Redis
func (r *repository) DeleteEmailVerificationRequest(ctx context.Context, userID string) error {
	key := emailVerificationRequestPrefix + userID
	err := r.client.Del(ctx, key).Err()
	if err != nil {
		return fmt.Errorf("failed to delete email verification request: %w", err)
	}
	return nil
}

// ==================== Password reset request ====================

// StorePasswordResetRequest - сохранение requestID для сброса пароля в Redis
func (r *repository) StorePasswordResetRequest(ctx context.Context, userID string, requestID string, ttl time.Duration) error {
	key := passwordResetRequestPrefix + userID
	err := r.client.Set(ctx, key, requestID, ttl).Err()
	if err != nil {
		return fmt.Errorf("failed to store password reset request: %w", err)
	}
	return nil
}

// GetPasswordResetRequest - получение requestID для сброса пароля из Redis
func (r *repository) GetPasswordResetRequest(ctx context.Context, userID string) (string, error) {
	key := passwordResetRequestPrefix + userID
	requestID, err := r.client.Get(ctx, key).Result()
	if err == redis.Nil {
		return "", nil // RequestID не найден
	}
	if err != nil {
		return "", fmt.Errorf("failed to get password reset request: %w", err)
	}
	return requestID, nil
}

// DeletePasswordResetRequest - удаление requestID после сброса пароля из Redis
func (r *repository) DeletePasswordResetRequest(ctx context.Context, userID string) error {
	key := passwordResetRequestPrefix + userID
	err := r.client.Del(ctx, key).Err()
	if err != nil {
		return fmt.Errorf("failed to delete password reset request: %w", err)
	}
	return nil
}

// ==================== OAuth ====================

// StoreOAuthState - сохранение OAuth state для CSRF защиты
func (r *repository) StoreOAuthState(ctx context.Context, state string, data string, ttl time.Duration) error {
	key := oauthStatePrefix + state
	err := r.client.Set(ctx, key, data, ttl).Err()
	if err != nil {
		return fmt.Errorf("failed to store oauth state: %w", err)
	}

	// Проверяем, что действительно сохранилось
	stored, _ := r.client.Get(ctx, key).Result()
	if stored != data {
		return fmt.Errorf("failed to verify oauth state storage: expected %s, got %s", data, stored)
	}

	return nil
}

// GetOAuthState - получение провайдера по OAuth state
func (r *repository) GetOAuthState(ctx context.Context, state string) (string, error) {
	key := oauthStatePrefix + state
	provider, err := r.client.Get(ctx, key).Result()
	if err == redis.Nil {
		return "", nil // State не найден
	}
	if err != nil {
		return "", fmt.Errorf("failed to get oauth state: %w", err)
	}
	return provider, nil
}

// DeleteOAuthState - удаление OAuth state
func (r *repository) DeleteOAuthState(ctx context.Context, state string) error {
	key := oauthStatePrefix + state
	err := r.client.Del(ctx, key).Err()
	if err != nil {
		return fmt.Errorf("failed to delete oauth state: %w", err)
	}
	return nil
}

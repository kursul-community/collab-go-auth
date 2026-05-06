package token

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"time"

	"github.com/redis/go-redis/v9"
)

// authDebugTokenSuffix — last 8 chars for log correlation. [auth-debug] helper.
func authDebugTokenSuffix(t string) string {
	if len(t) > 8 {
		return "..." + t[len(t)-8:]
	}
	return t
}

// Префиксы ключей в Redis
const (
	accessTokenPrefix              = "access_token:"               // Префикс для активных access токенов
	refreshTokenPrefix             = "refresh_token:"              // Префикс для refresh токенов
	refreshReplacedPrefix          = "refresh_replaced:"           // Grace-window: oldToken → JSON{access, refresh}
	userSessionsPrefix             = "user_sessions:"              // Префикс для списка сессий пользователя
	userAccessTokens               = "user_access:"                // Префикс для списка access токенов пользователя
	emailVerificationPrefix        = "email_verification:"         // Префикс для кодов верификации email
	emailVerificationRequestPrefix = "email_verification_request:" // Префикс для requestID верификации email
	passwordResetRequestPrefix     = "password_reset_request:"     // Префикс для requestID сброса пароля
	oauthStatePrefix               = "oauth_state:"                // Префикс для OAuth state (CSRF защита)
)

type replacedRefreshTokens struct {
	AccessToken  string `json:"access"`
	RefreshToken string `json:"refresh"`
}

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
	// RotateRefreshToken атомарно (через Lua) проверяет, что refresh_token:{token}
	// принадлежит userID, и сразу удаляет его. Используется на горячем пути
	// ротации, чтобы убрать race-окно между Validate и Revoke: только один
	// параллельный запрос становится winner. Возвращает true, если токен
	// существовал и был успешно удалён; false — если токена нет (уже
	// ротирован или никогда не сохранялся).
	RotateRefreshToken(ctx context.Context, userID string, token string) (bool, error)
	// StoreReplacedRefreshToken - сохраняет (newAccess, newRefresh), выпущенные
	// взамен oldToken, на короткий TTL. Используется для grace-window: если
	// клиент потерял ответ на ротацию (deploy-disconnect, network-blip,
	// multi-tab-race) — повторный запрос с тем же oldToken получает ту же пару.
	StoreReplacedRefreshToken(ctx context.Context, oldToken, newAccessToken, newRefreshToken string, ttl time.Duration) error
	// GetReplacedRefreshToken возвращает пару (access, refresh), записанную
	// для oldToken в grace-window. ok=false когда записи нет / истекла.
	GetReplacedRefreshToken(ctx context.Context, oldToken string) (string, string, bool, error)

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
	tokSfx := authDebugTokenSuffix(token)
	// Сохраняем токен с привязкой к userID
	tokenKey := refreshTokenPrefix + token
	err := r.client.Set(ctx, tokenKey, userID, ttl).Err()
	if err != nil {
		log.Printf("[auth-debug] StoreRefreshToken: redis SET failed userID=%s token=%s err=%v", userID, tokSfx, err)
		return fmt.Errorf("failed to store refresh token: %w", err)
	}

	// Добавляем токен в список сессий пользователя (для возможности отзыва всех токенов)
	sessionsKey := userSessionsPrefix + userID
	err = r.client.SAdd(ctx, sessionsKey, token).Err()
	if err != nil {
		log.Printf("[auth-debug] StoreRefreshToken: SADD failed userID=%s token=%s err=%v", userID, tokSfx, err)
		return fmt.Errorf("failed to add token to user sessions: %w", err)
	}

	// Устанавливаем TTL для списка сессий (обновляем при каждом новом токене)
	r.client.Expire(ctx, sessionsKey, ttl)

	log.Printf("[auth-debug] StoreRefreshToken: STORED userID=%s token=%s ttl=%s", userID, tokSfx, ttl)
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

// rotateRefreshLua атомарно проверяет владельца refresh_token:{token} и
// удаляет ключ + чистит вхождение в user_sessions:{userID}. Возвращает 1 при
// успешной ротации, 0 если токена нет, -1 если userID не совпадает.
var rotateRefreshLua = redis.NewScript(`
local stored = redis.call('GET', KEYS[1])
if not stored then
    return 0
end
if stored ~= ARGV[1] then
    return -1
end
redis.call('DEL', KEYS[1])
redis.call('SREM', KEYS[2], ARGV[2])
return 1
`)

// RotateRefreshToken атомарно валидирует и удаляет refresh-токен. Возвращает
// true, если ключ был и был удалён нашей операцией (winner ротации); false,
// если ключа нет либо он принадлежит другому userID. Реализовано через
// Lua-скрипт, чтобы между GET и DEL не открывалось окно для параллельных
// запросов.
func (r *repository) RotateRefreshToken(ctx context.Context, userID, token string) (bool, error) {
	tokenKey := refreshTokenPrefix + token
	sessionsKey := userSessionsPrefix + userID
	tokSfx := authDebugTokenSuffix(token)
	res, err := rotateRefreshLua.Run(ctx, r.client, []string{tokenKey, sessionsKey}, userID, token).Int()
	if err != nil {
		log.Printf("[auth-debug] RotateRefreshToken: redis/lua error userID=%s token=%s err=%v", userID, tokSfx, err)
		return false, fmt.Errorf("rotate refresh token: %w", err)
	}
	switch res {
	case 1:
		log.Printf("[auth-debug] RotateRefreshToken: lua=1 winner userID=%s token=%s", userID, tokSfx)
	case 0:
		log.Printf("[auth-debug] RotateRefreshToken: lua=0 token-missing userID=%s token=%s (key %q absent in redis — never stored, expired, or already rotated)", userID, tokSfx, tokenKey)
	case -1:
		log.Printf("[auth-debug] RotateRefreshToken: lua=-1 owner-mismatch userID=%s token=%s (key exists but belongs to different userID)", userID, tokSfx)
	default:
		log.Printf("[auth-debug] RotateRefreshToken: lua=%d unexpected userID=%s token=%s", res, userID, tokSfx)
	}
	return res == 1, nil
}

// StoreReplacedRefreshToken сохраняет пару (access, refresh), выпущенную
// взамен oldToken, в grace-окне. TTL короткий (порядка 10-30s). Если ответ
// ротации потерян, повторный refresh с oldToken вернёт ту же пару вместо
// логаута.
func (r *repository) StoreReplacedRefreshToken(ctx context.Context, oldToken, newAccessToken, newRefreshToken string, ttl time.Duration) error {
	payload, err := json.Marshal(replacedRefreshTokens{
		AccessToken:  newAccessToken,
		RefreshToken: newRefreshToken,
	})
	if err != nil {
		return fmt.Errorf("marshal replaced refresh payload: %w", err)
	}
	if err := r.client.Set(ctx, refreshReplacedPrefix+oldToken, payload, ttl).Err(); err != nil {
		return fmt.Errorf("store replaced refresh token: %w", err)
	}
	return nil
}

// GetReplacedRefreshToken возвращает пару (access, refresh), сохранённую при
// предыдущей ротации oldToken. ok=false когда записи нет или истекла.
func (r *repository) GetReplacedRefreshToken(ctx context.Context, oldToken string) (string, string, bool, error) {
	tokSfx := authDebugTokenSuffix(oldToken)
	raw, err := r.client.Get(ctx, refreshReplacedPrefix+oldToken).Result()
	if err == redis.Nil {
		log.Printf("[auth-debug] GetReplacedRefreshToken: MISS oldTok=%s (no grace mapping)", tokSfx)
		return "", "", false, nil
	}
	if err != nil {
		log.Printf("[auth-debug] GetReplacedRefreshToken: redis error oldTok=%s err=%v", tokSfx, err)
		return "", "", false, fmt.Errorf("get replaced refresh token: %w", err)
	}
	var payload replacedRefreshTokens
	if err := json.Unmarshal([]byte(raw), &payload); err != nil {
		log.Printf("[auth-debug] GetReplacedRefreshToken: unmarshal error oldTok=%s err=%v", tokSfx, err)
		return "", "", false, fmt.Errorf("unmarshal replaced refresh payload: %w", err)
	}
	log.Printf("[auth-debug] GetReplacedRefreshToken: HIT oldTok=%s newRefresh=%s", tokSfx, authDebugTokenSuffix(payload.RefreshToken))
	return payload.AccessToken, payload.RefreshToken, true, nil
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

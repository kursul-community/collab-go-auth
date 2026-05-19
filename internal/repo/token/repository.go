package token

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/redis/go-redis/v9"
)

// Префиксы ключей в Redis
const (
	accessTokenPrefix              = "access_token:"               // Префикс для активных access токенов
	refreshTokenPrefix             = "refresh_token:"              // Префикс для refresh токенов (legacy)
	refreshReplacedPrefix          = "refresh_replaced:"           // Legacy grace-window: oldToken → JSON{access, refresh}
	userSessionsPrefix             = "user_sessions:"              // Префикс для списка сессий пользователя (legacy)
	userAccessTokens               = "user_access:"                // Префикс для списка access токенов пользователя
	emailVerificationPrefix        = "email_verification:"         // Префикс для кодов верификации email
	emailVerificationRequestPrefix = "email_verification_request:" // Префикс для requestID верификации email
	passwordResetRequestPrefix     = "password_reset_request:"     // Префикс для requestID сброса пароля
	oauthStatePrefix               = "oauth_state:"                // Префикс для OAuth state (CSRF защита)

	// === Refresh token family (OAuth 2.0 Security BCP §4.13) ===
	refreshCurrentPrefix = "refresh_current:" // family_id → JSON{access, refresh, user_id, created_at}
	refreshFamilyPrefix  = "refresh_family:"  // refresh_jwt → family_id (обратный индекс)
	userFamiliesPrefix   = "user_families:"   // user_id → SET<family_id>
	revokedFamilyPrefix  = "revoked_family:"  // family_id → "1" (флаг compromised)
)

// Sentinel-ошибки для операций над семьями refresh-токенов
var (
	ErrFamilyNotFound = errors.New("token family not found")
	ErrFamilyRevoked  = errors.New("token family revoked")
	ErrFamilyConflict = errors.New("token family concurrent rotation conflict")
)

type replacedRefreshTokens struct {
	AccessToken  string `json:"access"`
	RefreshToken string `json:"refresh"`
}

// familyCurrent — payload, хранящийся под refresh_current:<family_id>
type familyCurrent struct {
	AccessToken  string `json:"access"`
	RefreshToken string `json:"refresh"`
	UserID       string `json:"user_id"`
	CreatedAt    int64  `json:"created_at"`
}

// rotateFamilyScript — атомарная ротация family-токена.
//
// KEYS:
//
//	1: refresh_current:<family_id>
//	2: refresh_family:<new_refresh_token>
//	3: revoked_family:<family_id>
//
// ARGV:
//
//	1: expected old refresh token (для optimistic CAS)
//	2: new payload JSON {access, refresh, user_id, created_at}
//	3: new refresh token (для значения второго ключа = family_id)
//	4: TTL (секунды)
//	5: family_id
//
// Возвращает 1 при успехе, либо error_reply("REVOKED"|"NOT_FOUND"|"CONFLICT").
var rotateFamilyScript = redis.NewScript(`
if redis.call('EXISTS', KEYS[3]) == 1 then
  return redis.error_reply('REVOKED')
end
local cur = redis.call('GET', KEYS[1])
if not cur then
  return redis.error_reply('NOT_FOUND')
end
local ok, parsed = pcall(cjson.decode, cur)
if not ok or parsed.refresh ~= ARGV[1] then
  return redis.error_reply('CONFLICT')
end
redis.call('SET', KEYS[1], ARGV[2], 'EX', ARGV[4])
redis.call('SET', KEYS[2], ARGV[5], 'EX', ARGV[4])
return 1
`)

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

	// === Refresh token family (OAuth 2.0 Security BCP §4.13) ===
	// CreateFamily - создаёт новую семью refresh-токенов (Login/OAuth callback).
	CreateFamily(ctx context.Context, familyID, userID, accessToken, refreshToken string, ttl time.Duration) error
	// RotateFamily - атомарно ротирует пару (access, refresh) в семье.
	// Возвращает ErrFamilyConflict если кто-то ротировал параллельно,
	// ErrFamilyRevoked если семья была помечена скомпрометированной,
	// ErrFamilyNotFound если семья отсутствует / истекла.
	RotateFamily(ctx context.Context, familyID, expectedOldRefresh, newAccessToken, newRefreshToken string, ttl time.Duration) error
	// GetFamilyCurrent - возвращает текущую активную пару семьи.
	GetFamilyCurrent(ctx context.Context, familyID string) (access, refresh, userID string, ok bool, err error)
	// GetFamilyByRefresh - возвращает family_id по refresh-токену (обратный индекс).
	GetFamilyByRefresh(ctx context.Context, refreshToken string) (familyID string, ok bool, err error)
	// RevokeFamily - отзывает всю семью (reuse detection / logout / admin action).
	RevokeFamily(ctx context.Context, familyID string) error
	// IsFamilyRevoked - проверяет, помечена ли семья как отозванная.
	IsFamilyRevoked(ctx context.Context, familyID string) (bool, error)
	// RevokeAllUserFamilies - отзывает все семьи пользователя (logout everywhere / admin).
	RevokeAllUserFamilies(ctx context.Context, userID string) error

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
	res, err := rotateRefreshLua.Run(ctx, r.client, []string{tokenKey, sessionsKey}, userID, token).Int()
	if err != nil {
		return false, fmt.Errorf("rotate refresh token: %w", err)
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
	raw, err := r.client.Get(ctx, refreshReplacedPrefix+oldToken).Result()
	if err == redis.Nil {
		return "", "", false, nil
	}
	if err != nil {
		return "", "", false, fmt.Errorf("get replaced refresh token: %w", err)
	}
	var payload replacedRefreshTokens
	if err := json.Unmarshal([]byte(raw), &payload); err != nil {
		return "", "", false, fmt.Errorf("unmarshal replaced refresh payload: %w", err)
	}
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

// ==================== Refresh token family ====================

// CreateFamily - создаёт новую семью refresh-токенов (Login / OAuth / register).
// Атомарно через TxPipeline: refresh_current, refresh_family и user_families
// обновляются одной транзакцией, чтобы не оставлять "висящих" обратных индексов.
func (r *repository) CreateFamily(ctx context.Context, familyID, userID, accessToken, refreshToken string, ttl time.Duration) error {
	if familyID == "" || userID == "" || refreshToken == "" {
		return fmt.Errorf("CreateFamily: familyID, userID and refreshToken must be non-empty")
	}
	payload, err := json.Marshal(familyCurrent{
		AccessToken:  accessToken,
		RefreshToken: refreshToken,
		UserID:       userID,
		CreatedAt:    time.Now().Unix(),
	})
	if err != nil {
		return fmt.Errorf("marshal family payload: %w", err)
	}
	pipe := r.client.TxPipeline()
	pipe.Set(ctx, refreshCurrentPrefix+familyID, payload, ttl)
	pipe.Set(ctx, refreshFamilyPrefix+refreshToken, familyID, ttl)
	pipe.SAdd(ctx, userFamiliesPrefix+userID, familyID)
	pipe.Expire(ctx, userFamiliesPrefix+userID, ttl)
	if _, err := pipe.Exec(ctx); err != nil {
		return fmt.Errorf("create family pipeline: %w", err)
	}
	return nil
}

// RotateFamily - атомарная ротация семьи через Lua-скрипт.
// Гарантирует, что параллельные запросы с одним и тем же refresh-токеном
// приведут максимум к одной реальной ротации (CAS на refresh).
func (r *repository) RotateFamily(ctx context.Context, familyID, expectedOldRefresh, newAccessToken, newRefreshToken string, ttl time.Duration) error {
	if familyID == "" || expectedOldRefresh == "" || newRefreshToken == "" {
		return fmt.Errorf("RotateFamily: familyID, expectedOldRefresh, newRefreshToken must be non-empty")
	}
	payload, err := json.Marshal(familyCurrent{
		AccessToken:  newAccessToken,
		RefreshToken: newRefreshToken,
		UserID:       "", // user_id заполняется на чтении; для CAS не используется
		CreatedAt:    time.Now().Unix(),
	})
	if err != nil {
		return fmt.Errorf("marshal family payload: %w", err)
	}
	// Подмешиваем user_id из текущей записи, чтобы не терять его при ротации.
	cur, err := r.client.Get(ctx, refreshCurrentPrefix+familyID).Result()
	if err == redis.Nil {
		return ErrFamilyNotFound
	}
	if err != nil {
		return fmt.Errorf("read current family for rotation: %w", err)
	}
	var curParsed familyCurrent
	if jerr := json.Unmarshal([]byte(cur), &curParsed); jerr != nil {
		return fmt.Errorf("unmarshal current family payload: %w", jerr)
	}
	payload, err = json.Marshal(familyCurrent{
		AccessToken:  newAccessToken,
		RefreshToken: newRefreshToken,
		UserID:       curParsed.UserID,
		CreatedAt:    time.Now().Unix(),
	})
	if err != nil {
		return fmt.Errorf("marshal family payload: %w", err)
	}

	ttlSec := int64(ttl.Seconds())
	if ttlSec <= 0 {
		ttlSec = 1
	}
	_, err = rotateFamilyScript.Run(ctx, r.client,
		[]string{
			refreshCurrentPrefix + familyID,
			refreshFamilyPrefix + newRefreshToken,
			revokedFamilyPrefix + familyID,
		},
		expectedOldRefresh,
		string(payload),
		newRefreshToken,
		ttlSec,
		familyID,
	).Result()
	if err != nil {
		// Lua error_reply возвращает err.Error() с префиксом или содержимым нашего reply.
		msg := err.Error()
		switch {
		case strings.Contains(msg, "REVOKED"):
			return ErrFamilyRevoked
		case strings.Contains(msg, "NOT_FOUND"):
			return ErrFamilyNotFound
		case strings.Contains(msg, "CONFLICT"):
			return ErrFamilyConflict
		}
		return fmt.Errorf("rotate family lua: %w", err)
	}
	// Не удаляем старый refresh_family:<old>: TTL заберёт его, а пока он живёт —
	// помогает идемпотентному lookup отставшей вкладки.
	return nil
}

// GetFamilyCurrent - читает текущую активную пару семьи.
func (r *repository) GetFamilyCurrent(ctx context.Context, familyID string) (string, string, string, bool, error) {
	raw, err := r.client.Get(ctx, refreshCurrentPrefix+familyID).Result()
	if err == redis.Nil {
		return "", "", "", false, nil
	}
	if err != nil {
		return "", "", "", false, fmt.Errorf("get family current: %w", err)
	}
	var p familyCurrent
	if err := json.Unmarshal([]byte(raw), &p); err != nil {
		return "", "", "", false, fmt.Errorf("unmarshal family current: %w", err)
	}
	return p.AccessToken, p.RefreshToken, p.UserID, true, nil
}

// GetFamilyByRefresh - возвращает family_id по refresh-токену (обратный индекс).
func (r *repository) GetFamilyByRefresh(ctx context.Context, refreshToken string) (string, bool, error) {
	v, err := r.client.Get(ctx, refreshFamilyPrefix+refreshToken).Result()
	if err == redis.Nil {
		return "", false, nil
	}
	if err != nil {
		return "", false, fmt.Errorf("get family by refresh: %w", err)
	}
	return v, true, nil
}

// RevokeFamily - помечает семью как отозванную и удаляет активную пару.
// Флаг revoked_family:<id> переживает удаление refresh_current — нужен для
// reuse-detection повторных попыток с уже ротированным токеном.
func (r *repository) RevokeFamily(ctx context.Context, familyID string) error {
	if familyID == "" {
		return nil
	}
	pipe := r.client.TxPipeline()
	// TTL флага = TTL refresh: после истечения никаких токенов из семьи уже нет.
	pipe.Set(ctx, revokedFamilyPrefix+familyID, "1", 0)
	pipe.Del(ctx, refreshCurrentPrefix+familyID)
	if _, err := pipe.Exec(ctx); err != nil {
		return fmt.Errorf("revoke family pipeline: %w", err)
	}
	return nil
}

// IsFamilyRevoked - проверка флага revoked_family.
func (r *repository) IsFamilyRevoked(ctx context.Context, familyID string) (bool, error) {
	if familyID == "" {
		return false, nil
	}
	n, err := r.client.Exists(ctx, revokedFamilyPrefix+familyID).Result()
	if err != nil {
		return false, fmt.Errorf("is family revoked: %w", err)
	}
	return n > 0, nil
}

// RevokeAllUserFamilies - отзывает все семьи пользователя.
func (r *repository) RevokeAllUserFamilies(ctx context.Context, userID string) error {
	if userID == "" {
		return nil
	}
	families, err := r.client.SMembers(ctx, userFamiliesPrefix+userID).Result()
	if err != nil {
		return fmt.Errorf("get user families: %w", err)
	}
	for _, fid := range families {
		if err := r.RevokeFamily(ctx, fid); err != nil {
			// Логически не критично — продолжаем отзывать остальные.
			continue
		}
	}
	// Удаляем агрегатный SET — больше живых семей нет.
	r.client.Del(ctx, userFamiliesPrefix+userID)
	return nil
}

package redis

import (
	"context"
	"fmt"
	"time"

	"github.com/redis/go-redis/v9"
)

const (
	// banBlacklistPrefix — ключ для blacklist забаненных пользователей: user:banned:<userId>
	banBlacklistPrefix = "user:banned:"
	// statusCachePrefix — ключ для кеша статуса пользователя: user:status:<userId>
	statusCachePrefix = "user:status:"
	// statusCacheTTL — время жизни кеша статуса (60 секунд)
	statusCacheTTL = 60 * time.Second
)

// BanCache предоставляет методы для работы с кешем банов в Redis
type BanCache interface {
	// IsInBanBlacklist проверяет наличие пользователя в blacklist забаненных
	IsInBanBlacklist(ctx context.Context, userID string) (bannedAt time.Time, found bool, err error)
	// AddToBanBlacklist добавляет пользователя в blacklist забаненных
	AddToBanBlacklist(ctx context.Context, userID string, bannedAt time.Time) error
	// RemoveFromBanBlacklist удаляет пользователя из blacklist (при разбане)
	RemoveFromBanBlacklist(ctx context.Context, userID string) error
	// GetCachedStatus возвращает закешированный статус пользователя
	GetCachedStatus(ctx context.Context, userID string) (status string, found bool, err error)
	// SetCachedStatus кеширует статус пользователя с TTL 60 секунд
	SetCachedStatus(ctx context.Context, userID string, status string) error
	// InvalidateCachedStatus удаляет кеш статуса пользователя
	InvalidateCachedStatus(ctx context.Context, userID string) error
}

type banCache struct {
	client *redis.Client
}

// NewBanCache создает новый экземпляр BanCache
func NewBanCache(client *redis.Client) BanCache {
	return &banCache{client: client}
}

func (bc *banCache) IsInBanBlacklist(ctx context.Context, userID string) (time.Time, bool, error) {
	key := banBlacklistPrefix + userID
	val, err := bc.client.Get(ctx, key).Result()
	if err == redis.Nil {
		return time.Time{}, false, nil
	}
	if err != nil {
		return time.Time{}, false, fmt.Errorf("ban_cache: get blacklist: %w", err)
	}

	bannedAt, err := time.Parse(time.RFC3339, val)
	if err != nil {
		return time.Time{}, false, fmt.Errorf("ban_cache: parse banned_at: %w", err)
	}

	return bannedAt, true, nil
}

func (bc *banCache) AddToBanBlacklist(ctx context.Context, userID string, bannedAt time.Time) error {
	key := banBlacklistPrefix + userID
	// Без TTL — запись хранится пока не будет удалена вручную (при разбане)
	if err := bc.client.Set(ctx, key, bannedAt.Format(time.RFC3339), 0).Err(); err != nil {
		return fmt.Errorf("ban_cache: add to blacklist: %w", err)
	}
	return nil
}

func (bc *banCache) RemoveFromBanBlacklist(ctx context.Context, userID string) error {
	key := banBlacklistPrefix + userID
	if err := bc.client.Del(ctx, key).Err(); err != nil {
		return fmt.Errorf("ban_cache: remove from blacklist: %w", err)
	}
	return nil
}

func (bc *banCache) GetCachedStatus(ctx context.Context, userID string) (string, bool, error) {
	key := statusCachePrefix + userID
	val, err := bc.client.Get(ctx, key).Result()
	if err == redis.Nil {
		return "", false, nil
	}
	if err != nil {
		return "", false, fmt.Errorf("ban_cache: get cached status: %w", err)
	}
	return val, true, nil
}

func (bc *banCache) SetCachedStatus(ctx context.Context, userID string, status string) error {
	key := statusCachePrefix + userID
	if err := bc.client.Set(ctx, key, status, statusCacheTTL).Err(); err != nil {
		return fmt.Errorf("ban_cache: set cached status: %w", err)
	}
	return nil
}

func (bc *banCache) InvalidateCachedStatus(ctx context.Context, userID string) error {
	key := statusCachePrefix + userID
	if err := bc.client.Del(ctx, key).Err(); err != nil {
		return fmt.Errorf("ban_cache: invalidate cached status: %w", err)
	}
	return nil
}

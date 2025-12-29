package redis

import (
	"context"
	"fmt"

	"github.com/redis/go-redis/v9"
	"go-auth/config"
)

// New создает новое подключение к Redis
func New(ctx context.Context, cfg config.RedisConfig) (*redis.Client, error) {
	client := redis.NewClient(&redis.Options{
		Addr:     cfg.Addr(),
		Password: cfg.Password,
		DB:       cfg.DB,
	})

	// Проверяем подключение
	if err := client.Ping(ctx).Err(); err != nil {
		return nil, fmt.Errorf("failed to connect to Redis: %w", err)
	}

	return client, nil
}


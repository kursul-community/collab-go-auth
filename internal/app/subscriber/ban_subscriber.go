package subscriber

import (
	"context"
	"encoding/json"
	"log"
	"time"

	redisadapter "go-auth/internal/adapter/redis"
	tokenrepo "go-auth/internal/repo/token"

	"github.com/redis/go-redis/v9"
)

const (
	// banChannel — Redis pub/sub канал для событий бана
	banChannel = "user:banned"
)

// banEvent — структура события бана из pub/sub
type banEvent struct {
	UserID   string `json:"userId"`
	BannedAt string `json:"bannedAt"`
}

// StartBanSubscriber запускает горутину, слушающую Redis pub/sub канал user:banned.
// При получении события — добавляет пользователя в blacklist, инвалидирует кеш статуса
// и отзывает все активные токены пользователя.
func StartBanSubscriber(ctx context.Context, redisClient *redis.Client, banCache redisadapter.BanCache, tokenRepo tokenrepo.Repository) {
	go func() {
		logger := log.Default()
		logger.Printf("Ban subscriber: starting, listening on channel '%s'", banChannel)

		pubsub := redisClient.Subscribe(ctx, banChannel)
		defer pubsub.Close()

		ch := pubsub.Channel()

		for {
			select {
			case <-ctx.Done():
				logger.Printf("Ban subscriber: shutting down")
				return
			case msg, ok := <-ch:
				if !ok {
					logger.Printf("Ban subscriber: channel closed, exiting")
					return
				}

				var event banEvent
				if err := json.Unmarshal([]byte(msg.Payload), &event); err != nil {
					logger.Printf("Ban subscriber: failed to parse event: %v, payload: %s", err, msg.Payload)
					continue
				}

				if event.UserID == "" {
					logger.Printf("Ban subscriber: received event with empty userId, skipping")
					continue
				}

				bannedAt, err := time.Parse(time.RFC3339, event.BannedAt)
				if err != nil {
					logger.Printf("Ban subscriber: failed to parse bannedAt for user %s: %v", event.UserID, err)
					bannedAt = time.Now().UTC()
				}

				// Добавляем в blacklist
				if err := banCache.AddToBanBlacklist(ctx, event.UserID, bannedAt); err != nil {
					logger.Printf("Ban subscriber: failed to add user %s to blacklist: %v", event.UserID, err)
				}

				// Инвалидируем кеш статуса
				if err := banCache.InvalidateCachedStatus(ctx, event.UserID); err != nil {
					logger.Printf("Ban subscriber: failed to invalidate cache for user %s: %v", event.UserID, err)
				}

				// Отзываем все токены — немедленная инвалидация всех сессий
				if err := tokenRepo.RevokeAllUserTokens(ctx, event.UserID); err != nil {
					logger.Printf("Ban subscriber: failed to revoke tokens for user %s: %v", event.UserID, err)
				}

				logger.Printf("Ban subscriber: user %s banned at %s — blacklisted, cache invalidated, tokens revoked", event.UserID, event.BannedAt)
			}
		}
	}()
}

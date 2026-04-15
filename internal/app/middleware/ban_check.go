package middleware

import (
	"context"
	"encoding/json"
	"log"
	"net/http"
	"strings"
	"time"

	redisadapter "go-auth/internal/adapter/redis"
	"go-auth/internal/adapter/token"
	userclient "go-auth/internal/adapter/user"
)

// CheckBanStatus проверяет статус бана пользователя через 3-уровневую систему:
// blacklist → cache → gRPC fallback. Возвращает true если пользователь забанен.
func CheckBanStatus(
	ctx context.Context,
	banCache redisadapter.BanCache,
	userClient userclient.Client,
	userID string,
	tokenIssuedAt time.Time,
) bool {
	// 1. Проверяем blacklist (самая быстрая проверка — Redis GET)
	bannedAt, found, err := banCache.IsInBanBlacklist(ctx, userID)
	if err != nil {
		log.Printf("ban_check: blacklist check error for user %s: %v", userID, err)
	}
	if found {
		if tokenIssuedAt.IsZero() || tokenIssuedAt.Before(bannedAt) {
			return true
		}
	}

	// 2. Проверяем кеш статуса (Redis GET с TTL 60s)
	status, cached, err := banCache.GetCachedStatus(ctx, userID)
	if err != nil {
		log.Printf("ban_check: cache check error for user %s: %v", userID, err)
	}
	if cached {
		return status == "banned"
	}

	// 3. Cache miss — делаем gRPC вызов в user-service
	grpcStatus, grpcBannedAt, err := userClient.GetUserStatus(ctx, userID)
	if err != nil {
		log.Printf("ban_check: gRPC GetUserStatus error for user %s: %v", userID, err)
		return false // fail-open
	}

	// Кешируем результат
	if cacheErr := banCache.SetCachedStatus(ctx, userID, grpcStatus); cacheErr != nil {
		log.Printf("ban_check: cache set error for user %s: %v", userID, cacheErr)
	}

	// Если забанен — добавляем в blacklist
	if grpcStatus == "banned" {
		parsedBannedAt, parseErr := time.Parse(time.RFC3339, grpcBannedAt)
		if parseErr == nil {
			if blErr := banCache.AddToBanBlacklist(ctx, userID, parsedBannedAt); blErr != nil {
				log.Printf("ban_check: add to blacklist error for user %s: %v", userID, blErr)
			}
		}
		return true
	}

	return false
}

// BanCheckMiddleware проверяет забаненных пользователей на уровне HTTP.
func BanCheckMiddleware(
	tokenSvc token.JWTToken,
	banCache redisadapter.BanCache,
	userClient userclient.Client,
	next http.Handler,
) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Пропускаем эндпоинты, доступные забаненным пользователям
		if strings.HasSuffix(r.URL.Path, "/auth/session-info") ||
			strings.HasSuffix(r.URL.Path, "/auth/forward-auth") {
			next.ServeHTTP(w, r)
			return
		}

		// 1. Извлекаем токен из заголовка Authorization
		authHeader := r.Header.Get("Authorization")
		if authHeader == "" {
			next.ServeHTTP(w, r)
			return
		}

		parts := strings.SplitN(authHeader, " ", 2)
		if len(parts) != 2 || parts[0] != "Bearer" {
			next.ServeHTTP(w, r)
			return
		}

		tokenStr := parts[1]

		// 2. Валидация токена и извлечение claims
		claims, err := tokenSvc.GetClaimsFromToken(tokenStr)
		if err != nil {
			writeJSON(w, http.StatusUnauthorized, map[string]string{
				"error":   "unauthorized",
				"message": "Invalid or expired token",
			})
			return
		}

		// 3. Проверяем статус бана
		if CheckBanStatus(r.Context(), banCache, userClient, claims.UserID, claims.IssuedAt) {
			writeBannedResponse(w)
			return
		}

		next.ServeHTTP(w, r)
	})
}

func writeBannedResponse(w http.ResponseWriter) {
	writeJSON(w, http.StatusForbidden, map[string]string{
		"error":   "account_banned",
		"message": "Your account has been banned",
	})
}

func writeJSON(w http.ResponseWriter, statusCode int, data interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(statusCode)
	json.NewEncoder(w).Encode(data)
}

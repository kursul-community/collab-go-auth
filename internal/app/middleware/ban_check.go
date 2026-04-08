package middleware

import (
	"encoding/json"
	"log"
	"net/http"
	"strings"
	"time"

	redisadapter "go-auth/internal/adapter/redis"
	"go-auth/internal/adapter/token"
	userclient "go-auth/internal/adapter/user"
)

// BanCheckMiddleware проверяет забаненных пользователей на уровне HTTP.
//
// Логика:
//  1. Извлекает JWT из заголовка Authorization: Bearer <token>
//  2. Если заголовка нет — пропускает запрос (публичные маршруты)
//  3. Если токен невалиден — возвращает 401 Unauthorized
//  4. Проверяет blacklist в Redis (user:banned:<userId>) — быстрая проверка
//  5. Проверяет кеш статуса (user:status:<userId>) — TTL 60 сек
//  6. При cache miss — делает gRPC вызов GetUserStatus в user-service
//  7. Если статус banned — возвращает 403 Forbidden
func BanCheckMiddleware(
	tokenSvc token.JWTToken,
	banCache redisadapter.BanCache,
	userClient userclient.Client,
	next http.Handler,
) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Пропускаем session-info — забаненный пользователь должен узнать свой статус
		if strings.HasSuffix(r.URL.Path, "/auth/session-info") {
			next.ServeHTTP(w, r)
			return
		}

		// 1. Извлекаем токен из заголовка Authorization
		authHeader := r.Header.Get("Authorization")
		if authHeader == "" {
			// Нет заголовка — пропускаем (публичные маршруты)
			next.ServeHTTP(w, r)
			return
		}

		parts := strings.SplitN(authHeader, " ", 2)
		if len(parts) != 2 || parts[0] != "Bearer" {
			// Неверный формат — пропускаем (пусть бизнес-сервис решит)
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

		userID := claims.UserID
		tokenIssuedAt := claims.IssuedAt

		// 3. Проверяем blacklist (самая быстрая проверка — Redis GET)
		bannedAt, found, err := banCache.IsInBanBlacklist(r.Context(), userID)
		if err != nil {
			log.Printf("ban_check: blacklist check error for user %s: %v", userID, err)
			// При ошибке Redis — пропускаем проверку, чтобы не блокировать сервис
		}
		if found {
			// Если iat отсутствует (zero) — считаем что токен выдан до бана (блокируем)
			if tokenIssuedAt.IsZero() || tokenIssuedAt.Before(bannedAt) {
				writeBannedResponse(w)
				return
			}
		}

		// 4. Проверяем кеш статуса (Redis GET с TTL 60s)
		status, cached, err := banCache.GetCachedStatus(r.Context(), userID)
		if err != nil {
			log.Printf("ban_check: cache check error for user %s: %v", userID, err)
		}

		if cached {
			if status == "banned" {
				writeBannedResponse(w)
				return
			}
			// status == "active" — пропускаем
			next.ServeHTTP(w, r)
			return
		}

		// 5. Cache miss — делаем gRPC вызов в user-service
		grpcStatus, grpcBannedAt, err := userClient.GetUserStatus(r.Context(), userID)
		if err != nil {
			log.Printf("ban_check: gRPC GetUserStatus error for user %s: %v", userID, err)
			// При ошибке gRPC — пропускаем проверку (fail-open)
			next.ServeHTTP(w, r)
			return
		}

		// 6. Кешируем результат
		if cacheErr := banCache.SetCachedStatus(r.Context(), userID, grpcStatus); cacheErr != nil {
			log.Printf("ban_check: cache set error for user %s: %v", userID, cacheErr)
		}

		// 7. Если забанен — добавляем в blacklist и блокируем
		if grpcStatus == "banned" {
			parsedBannedAt, parseErr := time.Parse(time.RFC3339, grpcBannedAt)
			if parseErr == nil {
				if blErr := banCache.AddToBanBlacklist(r.Context(), userID, parsedBannedAt); blErr != nil {
					log.Printf("ban_check: add to blacklist error for user %s: %v", userID, blErr)
				}
			}
			writeBannedResponse(w)
			return
		}

		// 8. Пользователь активен — пропускаем
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

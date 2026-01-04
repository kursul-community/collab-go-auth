// Package app configures and runs HTTP Gateway for REST API.
package app

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"strings"

	"github.com/grpc-ecosystem/grpc-gateway/v2/runtime"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"

	"go-auth/config"
	"go-auth/gen/auth"
)

// Константы для cookies
const (
	AccessTokenCookieName  = "access_token"
	RefreshTokenCookieName = "refresh_token"
	AccessTokenMaxAge      = 30 * 60        // 30 минут
	RefreshTokenMaxAge     = 30 * 24 * 3600 // 30 дней
)

// RunGateway - запускает HTTP Gateway сервер для REST API
func RunGateway(cfg *config.Config) error {
	logger := log.Default()

	ctx := context.Background()
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	// Создаем gRPC Gateway mux
	mux := runtime.NewServeMux()

	// Настройки для подключения к gRPC серверу
	opts := []grpc.DialOption{
		grpc.WithTransportCredentials(insecure.NewCredentials()),
	}

	// Подключаемся к gRPC серверу
	// В Docker gateway и gRPC в одном контейнере, используем localhost
	// Для внешних подключений можно использовать cfg.GRPC.Host
	grpcAddr := fmt.Sprintf("localhost:%d", cfg.GRPC.Port)
	err := auth.RegisterAuthHandlerFromEndpoint(ctx, mux, grpcAddr, opts)
	if err != nil {
		return fmt.Errorf("failed to register gateway: %w", err)
	}

	// Настраиваем цепочку middleware: CORS -> Cookie -> Handler
	handler := corsMiddleware(cookieMiddleware(mux))

	// Запускаем HTTP сервер
	httpAddr := fmt.Sprintf(":%d", cfg.HTTP.Port)
	logger.Printf("Starting HTTP Gateway server on port %d\n", cfg.HTTP.Port)
	logger.Printf("REST API available at http://localhost:%d/api/v1/auth/*\n", cfg.HTTP.Port)

	if err := http.ListenAndServe(httpAddr, handler); err != nil {
		return fmt.Errorf("failed to serve HTTP Gateway: %w", err)
	}

	return nil
}

// corsMiddleware - добавляет CORS заголовки для фронтенда
func corsMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		origin := r.Header.Get("Origin")
		if origin == "" {
			origin = "*"
		}

		// Устанавливаем CORS заголовки
		w.Header().Set("Access-Control-Allow-Origin", origin)
		w.Header().Set("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS")
		w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization")
		w.Header().Set("Access-Control-Allow-Credentials", "true") // Разрешаем cookies
		// Не устанавливаем Content-Type здесь - grpc-gateway установит его сам для правильной сериализации ошибок

		// Обрабатываем preflight запросы
		if r.Method == "OPTIONS" {
			w.WriteHeader(http.StatusOK)
			return
		}

		next.ServeHTTP(w, r)
	})
}

// cookieMiddleware - устанавливает токены в cookies для /auth/login и /auth/refresh
func cookieMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Проверяем, нужно ли обрабатывать этот путь
		path := r.URL.Path
		isLoginPath := strings.HasSuffix(path, "/auth/login")
		isRefreshPath := strings.HasSuffix(path, "/auth/refresh")

		if !isLoginPath && !isRefreshPath {
			// Не наш путь, пропускаем
			next.ServeHTTP(w, r)
			return
		}

		// Создаем буферизированный ResponseWriter
		bw := &bufferedResponseWriter{
			ResponseWriter: w,
			buf:            &bytes.Buffer{},
			headers:        make(http.Header),
		}

		// Выполняем следующий handler
		next.ServeHTTP(bw, r)

		// Если статус успешный, парсим ответ и устанавливаем cookies
		if bw.statusCode == http.StatusOK || bw.statusCode == 0 {
			var response map[string]interface{}
			if err := json.Unmarshal(bw.buf.Bytes(), &response); err == nil {
				// gRPC-Gateway возвращает camelCase: accessToken, refreshToken
				// Проверяем оба варианта для совместимости
				accessToken := getStringField(response, "accessToken", "access_token")
				if accessToken != "" {
					http.SetCookie(w, &http.Cookie{
						Name:     AccessTokenCookieName,
						Value:    accessToken,
						Path:     "/",
						HttpOnly: true,
						Secure:   false, // true для HTTPS в production
						SameSite: http.SameSiteLaxMode,
						MaxAge:   AccessTokenMaxAge,
					})
				}

				// Устанавливаем refresh_token в cookie (только для login)
				// HttpOnly: false - чтобы фронтенд мог читать токен для обновления
				if isLoginPath {
					refreshToken := getStringField(response, "refreshToken", "refresh_token")
					if refreshToken != "" {
						http.SetCookie(w, &http.Cookie{
							Name:     RefreshTokenCookieName,
							Value:    refreshToken,
							Path:     "/",
							HttpOnly: false, // Доступен из JavaScript
							Secure:   false, // true для HTTPS в production
							SameSite: http.SameSiteLaxMode,
							MaxAge:   RefreshTokenMaxAge,
						})
					}
				}
			}
		}

		// Копируем заголовки из буфера (важно делать это до WriteHeader)
		// grpc-gateway устанавливает заголовки через Header(), поэтому они должны быть в bw.headers
		for key, values := range bw.headers {
			for _, value := range values {
				w.Header().Set(key, value)
			}
		}

		// Записываем статус код (важно делать это перед записью тела)
		// grpc-gateway устанавливает статус код через WriteHeader()
		if bw.statusCode != 0 {
			w.WriteHeader(bw.statusCode)
		} else {
			// Если статус не установлен, устанавливаем 200 по умолчанию
			w.WriteHeader(http.StatusOK)
		}

		// Записываем тело ответа (включая ошибки в формате gRPC с code, message, details)
		w.Write(bw.buf.Bytes())
	})
}

// bufferedResponseWriter - перехватывает ответ для чтения тела перед отправкой
type bufferedResponseWriter struct {
	http.ResponseWriter
	buf        *bytes.Buffer
	headers    http.Header
	statusCode int
}

func (bw *bufferedResponseWriter) Header() http.Header {
	return bw.headers
}

func (bw *bufferedResponseWriter) WriteHeader(code int) {
	bw.statusCode = code
}

func (bw *bufferedResponseWriter) Write(b []byte) (int, error) {
	return bw.buf.Write(b)
}

// getStringField - получает строковое поле из map, проверяя несколько возможных имён
func getStringField(m map[string]interface{}, keys ...string) string {
	for _, key := range keys {
		if val, ok := m[key].(string); ok && val != "" {
			return val
		}
	}
	return ""
}

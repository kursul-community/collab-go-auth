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
	"google.golang.org/genproto/googleapis/rpc/errdetails"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/structpb"

	"go-auth/config"
	"go-auth/gen/auth"
	redisadapter "go-auth/internal/adapter/redis"
	"go-auth/internal/adapter/token"
	userclient "go-auth/internal/adapter/user"
	"go-auth/internal/app/middleware"
	oauthhttp "go-auth/internal/controller/http/oauth"
	userrepo "go-auth/internal/repo/user"
)

// DefaultSubscriptionTier returns when DB read fails for /session-info — better
// to serve the user as "member" than 5xx and lock them out over an infra blip.
const DefaultSubscriptionTier = "member"

// Константы для cookies
const (
	AccessTokenCookieName  = "access_token"
	RefreshTokenCookieName = "refresh_token"
	AccessTokenMaxAge      = 86400          // 3 дня
	RefreshTokenMaxAge     = 30 * 24 * 3600 // 30 дней
)

// RunGateway - запускает HTTP Gateway сервер для REST API
func RunGateway(cfg *config.Config, oauthHandler *oauthhttp.Handler, tokenSvc token.JWTToken, banCache redisadapter.BanCache, userSvcClient userclient.Client, userRepo userrepo.Repository) error {
	logger := log.Default()

	ctx := context.Background()
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	// Кастомный error handler для передачи заголовков при ошибках и переформатирования details
	customErrorHandler := func(ctx context.Context, mux *runtime.ServeMux, marshaler runtime.Marshaler, w http.ResponseWriter, r *http.Request, err error) {
		// Извлекаем metadata из ServerMetadata
		md, ok := runtime.ServerMetadataFromContext(ctx)
		if ok {
			// Проверяем наличие x-http-code в заголовках (разные варианты написания)
			httpCodeHeader := md.HeaderMD.Get("x-http-code")
			if len(httpCodeHeader) == 0 {
				httpCodeHeader = md.HeaderMD.Get("X-Http-Code")
			}
			if len(httpCodeHeader) == 0 {
				httpCodeHeader = md.HeaderMD.Get("Grpc-Metadata-X-Http-Code")
			}

			if len(httpCodeHeader) > 0 {
				var code int
				if n, _ := fmt.Sscanf(httpCodeHeader[0], "%d", &code); n > 0 && code != 0 {
					// Устанавливаем статус код и пишем ответ вручную
					w.Header().Set("Content-Type", "application/json")
					w.WriteHeader(code)

					st, _ := status.FromError(err)
					errorResponse := map[string]interface{}{
						"code":    st.Code(),
						"message": st.Message(),
					}
					json.NewEncoder(w).Encode(errorResponse)
					return
				}
			}

			// Проверяем наличие user-id и request-id в заголовках
			if userID := md.HeaderMD.Get("user-id"); len(userID) > 0 {
				w.Header().Set("X-User-Id", userID[0])
			}
			if requestID := md.HeaderMD.Get("request-id"); len(requestID) > 0 {
				w.Header().Set("X-Request-Id", requestID[0])
			}
		} else {
			log.Printf("Gateway customErrorHandler: failed to extract ServerMetadata from context for error: %v", err)
		}

		// Извлекаем userId и requestId из error details
		var extractedUserId, extractedRequestId string
		if st, ok := status.FromError(err); ok {
			for _, detail := range st.Details() {
				// Проверяем ErrorInfo (для обратной совместимости)
				if errorInfo, ok := detail.(*errdetails.ErrorInfo); ok {
					if userId, exists := errorInfo.Metadata["userId"]; exists && userId != "" {
						extractedUserId = userId
						w.Header().Set("X-User-Id", userId)
					}
					if requestId, exists := errorInfo.Metadata["requestId"]; exists && requestId != "" {
						extractedRequestId = requestId
						w.Header().Set("X-Request-Id", requestId)
					}
				}
				// Проверяем Struct (новый формат с requestId и userId напрямую)
				if detailsStruct, ok := detail.(*structpb.Struct); ok {
					if userIdVal := detailsStruct.Fields["userId"]; userIdVal != nil {
						if userId := userIdVal.GetStringValue(); userId != "" {
							extractedUserId = userId
							w.Header().Set("X-User-Id", userId)
						}
					}
					if requestIdVal := detailsStruct.Fields["requestId"]; requestIdVal != nil {
						if requestId := requestIdVal.GetStringValue(); requestId != "" {
							extractedRequestId = requestId
							w.Header().Set("X-Request-Id", requestId)
						}
					}
				}
			}
		}

		// Если есть userId и requestId, переформатируем ответ
		if extractedUserId != "" && extractedRequestId != "" {
			// Создаем буфер для перехвата стандартного ответа
			buf := &bytes.Buffer{}
			// Создаем копию заголовков, чтобы не влиять на оригинальные
			headersCopy := make(http.Header)
			for key, values := range w.Header() {
				headersCopy[key] = values
			}
			writer := &bufferedErrorWriter{
				ResponseWriter: w,
				buf:            buf,
				headers:        headersCopy,
			}

			// Вызываем стандартный обработчик ошибок в буфер
			runtime.DefaultHTTPErrorHandler(ctx, mux, marshaler, writer, r, err)

			// Парсим JSON ответа
			var errorResponse map[string]interface{}
			if err := json.Unmarshal(buf.Bytes(), &errorResponse); err == nil {
				// Заменяем массив details на объект с requestId и userId
				errorResponse["details"] = map[string]interface{}{
					"requestId": extractedRequestId,
					"userId":    extractedUserId,
				}

				// Устанавливаем заголовки
				for key, values := range writer.headers {
					for _, value := range values {
						w.Header().Set(key, value)
					}
				}

				// Устанавливаем статус код
				if writer.statusCode != 0 {
					w.WriteHeader(writer.statusCode)
				} else {
					w.WriteHeader(http.StatusInternalServerError)
				}

				// Записываем переформатированный JSON
				w.Header().Set("Content-Type", "application/json")
				json.NewEncoder(w).Encode(errorResponse)
				return
			}
		}

		// Если не удалось переформатировать, используем стандартный обработчик
		runtime.DefaultHTTPErrorHandler(ctx, mux, marshaler, w, r, err)
	}

	// Функция для добавления Origin/Host в gRPC metadata
	metadataFunc := func(ctx context.Context, r *http.Request) metadata.MD {
		md := metadata.MD{}

		// Извлекаем Origin или формируем из Host
		origin := r.Header.Get("Origin")
		if origin == "" {
			// Если Origin нет, формируем из Host
			scheme := "http"
			if r.TLS != nil {
				scheme = "https"
			}
			host := r.Host
			if host != "" {
				origin = fmt.Sprintf("%s://%s", scheme, host)
			}
		}

		if origin != "" {
			md.Set("x-frontend-origin", origin)
		}

		return md
	}

	// Функция для обработки успешных ответов и установки кастомных HTTP кодов
	forwardResponseOption := func(ctx context.Context, w http.ResponseWriter, resp proto.Message) error {
		md, ok := runtime.ServerMetadataFromContext(ctx)
		if !ok {
			return nil
		}

		if codes := md.HeaderMD.Get("x-http-code"); len(codes) > 0 {
			var code int
			if n, _ := fmt.Sscanf(codes[0], "%d", &code); n > 0 && code != 0 {
				w.WriteHeader(code)
			}
		}
		return nil
	}

	// Создаем gRPC Gateway mux с кастомным error handler и metadata функцией
	grpcMux := runtime.NewServeMux(
		runtime.WithErrorHandler(customErrorHandler),
		runtime.WithMetadata(metadataFunc),
		runtime.WithForwardResponseOption(forwardResponseOption),
		runtime.WithOutgoingHeaderMatcher(func(key string) (string, bool) {
			// Пробрасываем x-http-code напрямую без префикса Grpc-Metadata-
			if strings.ToLower(key) == "x-http-code" {
				return "x-http-code", true
			}
			return runtime.DefaultHeaderMatcher(key)
		}),
	)

	// Настройки для подключения к gRPC серверу
	opts := []grpc.DialOption{
		grpc.WithTransportCredentials(insecure.NewCredentials()),
	}

	// Подключаемся к gRPC серверу
	// В Docker gateway и gRPC в одном контейнере, используем localhost
	// Для внешних подключений можно использовать cfg.GRPC.Host
	grpcAddr := fmt.Sprintf("localhost:%d", cfg.GRPC.Port)
	err := auth.RegisterAuthHandlerFromEndpoint(ctx, grpcMux, grpcAddr, opts)
	if err != nil {
		return fmt.Errorf("failed to register gateway: %w", err)
	}

	// Создаем основной HTTP mux
	mainMux := http.NewServeMux()

	// Регистрируем OAuth роуты (если OAuth включен)
	if oauthHandler != nil {
		// GET /api/v1/auth/oauth/github/start - старт привязки GitHub
		mainMux.HandleFunc("/api/v1/auth/oauth/github/start", func(w http.ResponseWriter, r *http.Request) {
			if r.Method == http.MethodGet || r.Method == http.MethodOptions {
				oauthHandler.GetGitHubStart(w, r)
			} else {
				http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			}
		})

		// GET /api/v1/auth/oauth/providers - список провайдеров
		mainMux.HandleFunc("/api/v1/auth/oauth/providers", func(w http.ResponseWriter, r *http.Request) {
			if r.Method == http.MethodGet || r.Method == http.MethodOptions {
				oauthHandler.GetProviders(w, r)
			} else {
				http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			}
		})

		// GET /api/v1/auth/oauth/{provider}/callback - OAuth callback
		mainMux.HandleFunc("/api/v1/auth/oauth/", func(w http.ResponseWriter, r *http.Request) {
			path := r.URL.Path

			// Проверяем callback
			if strings.HasSuffix(path, "/callback") {
				oauthHandler.Callback(w, r)
				return
			}

			// Иначе это запрос на получение auth URL
			if r.Method == http.MethodGet {
				oauthHandler.GetAuthURL(w, r)
				return
			}

			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		})

		logger.Printf("OAuth routes registered")
	}

	// Session info endpoint — возвращает role и status пользователя
	mainMux.HandleFunc("/api/v1/auth/session-info", func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodOptions {
			w.WriteHeader(http.StatusOK)
			return
		}
		if r.Method != http.MethodGet {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}

		// Извлекаем токен из Authorization header или cookie
		accessToken := ""
		if authHeader := r.Header.Get("Authorization"); authHeader != "" {
			parts := strings.SplitN(authHeader, " ", 2)
			if len(parts) == 2 && parts[0] == "Bearer" {
				accessToken = parts[1]
			}
		}
		if accessToken == "" {
			if cookie, err := r.Cookie(AccessTokenCookieName); err == nil {
				accessToken = cookie.Value
			}
		}
		if accessToken == "" {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusUnauthorized)
			json.NewEncoder(w).Encode(map[string]string{
				"error":   "unauthorized",
				"message": "Missing access token",
			})
			return
		}

		// Извлекаем claims (userID + role) из JWT
		claims, err := tokenSvc.GetClaimsFromToken(accessToken)
		if err != nil {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusUnauthorized)
			json.NewEncoder(w).Encode(map[string]string{
				"error":   "unauthorized",
				"message": "Invalid or expired token",
			})
			return
		}

		userID := claims.UserID
		role := claims.Role

		// Определяем status пользователя (Redis кеш → gRPC fallback)
		userStatus := "active"

		// 1. Проверяем blacklist
		if _, found, _ := banCache.IsInBanBlacklist(r.Context(), userID); found {
			userStatus = "banned"
		}

		// 2. Если не в blacklist — проверяем кеш статуса
		if userStatus == "active" {
			if cachedStatus, cached, _ := banCache.GetCachedStatus(r.Context(), userID); cached {
				userStatus = cachedStatus
			} else {
				// 3. Cache miss — gRPC вызов в user-service
				if grpcStatus, _, err := userSvcClient.GetUserStatus(r.Context(), userID); err == nil {
					userStatus = grpcStatus
					_ = banCache.SetCachedStatus(r.Context(), userID, grpcStatus)
				}
			}
		}

		// Subscription tier — точечный SELECT из локальной users-таблицы.
		// При ошибке (DB временно недоступна) — fallback на "member", чтобы
		// инфра-сбой не лочил юзера за платными фичами. Лог для on-call.
		subscriptionTier := DefaultSubscriptionTier
		if tier, err := userRepo.GetSubscriptionTier(r.Context(), userID); err == nil {
			subscriptionTier = tier
		} else {
			logger.Printf("session-info: GetSubscriptionTier failed userID=%s err=%v (falling back to %q)", userID, err, DefaultSubscriptionTier)
		}

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(map[string]string{
			"status":            userStatus,
			"role":              role,
			"subscription_tier": subscriptionTier,
		})
	})

	// Health и Ready endpoints для Kubernetes probes
	mainMux.HandleFunc("/api/v1/health", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("OK"))
	})

	mainMux.HandleFunc("/api/v1/ready", func(w http.ResponseWriter, r *http.Request) {
		// Можно добавить проверку подключения к БД/Redis, если нужно
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("OK"))
	})

	// gRPC Gateway обрабатывает остальные запросы
	mainMux.Handle("/", grpcMux)

	// Настраиваем цепочку middleware: CORS -> BanCheck -> Cookie -> Handler
	corsBanCookieChain := corsMiddleware(cfg, middleware.BanCheckMiddleware(tokenSvc, banCache, userSvcClient, cookieMiddleware(cfg, mainMux)))

	// Top-level mux: forward-auth вынесен за пределы CORS middleware,
	// т.к. это внутренний вызов Traefik, ему CORS не нужен.
	// Если Traefik вернёт ошибку клиенту — downstream сервис не участвует,
	// и CORS-заголовки auth-service не должны попасть в ответ.
	topMux := http.NewServeMux()

	topMux.HandleFunc("/api/v1/auth/forward-auth", func(w http.ResponseWriter, r *http.Request) {
		// Traefik ForwardAuth отправляет GET, оригинальный метод в X-Forwarded-Method
		originalMethod := r.Header.Get("X-Forwarded-Method")
		if originalMethod == "" {
			originalMethod = r.Method
		}

		// Пропускаем preflight — у OPTIONS нет токена
		if originalMethod == http.MethodOptions {
			w.WriteHeader(http.StatusOK)
			return
		}

		// Извлекаем токен из Authorization header или cookie
		accessToken := ""
		if authHeader := r.Header.Get("Authorization"); authHeader != "" {
			parts := strings.SplitN(authHeader, " ", 2)
			if len(parts) == 2 && parts[0] == "Bearer" {
				accessToken = parts[1]
			}
		}
		if accessToken == "" {
			if cookie, err := r.Cookie(AccessTokenCookieName); err == nil {
				accessToken = cookie.Value
			}
		}
		if accessToken == "" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}

		// Валидация JWT
		claims, err := tokenSvc.GetClaimsFromToken(accessToken)
		if err != nil {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}

		// Проверка бана
		if middleware.CheckBanStatus(r.Context(), banCache, userSvcClient, claims.UserID, claims.IssuedAt) {
			w.WriteHeader(http.StatusForbidden)
			return
		}

		// Успех — trusted headers для downstream
		w.Header().Set("X-User-ID", claims.UserID)
		w.Header().Set("X-User-Role", claims.Role)
		w.WriteHeader(http.StatusOK)
	})

	// Всё остальное идёт через CORS -> BanCheck -> Cookie chain
	topMux.Handle("/", corsBanCookieChain)

	handler := topMux

	// Запускаем HTTP сервер
	httpAddr := fmt.Sprintf(":%d", cfg.HTTP.Port)
	logger.Printf("Starting HTTP Gateway server on port %d\n", cfg.HTTP.Port)
	logger.Printf("REST API available at http://localhost:%d/api/v1/auth/*\n", cfg.HTTP.Port)
	if oauthHandler != nil {
		logger.Printf("OAuth API available at http://localhost:%d/api/v1/auth/oauth/*\n", cfg.HTTP.Port)
	}

	if err := http.ListenAndServe(httpAddr, handler); err != nil {
		return fmt.Errorf("failed to serve HTTP Gateway: %w", err)
	}

	return nil
}

// corsMiddleware - добавляет CORS заголовки для фронта
func corsMiddleware(cfg *config.Config, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		origin := r.Header.Get("Origin")
		allowedOrigins := cfg.CORS.AllowedOrigins

		isAllowed := false
		if origin != "" {
			for _, allowed := range allowedOrigins {
				if allowed == "*" || allowed == origin {
					isAllowed = true
					break
				}
			}
		}

		if isAllowed {
			w.Header().Set("Access-Control-Allow-Origin", origin)
			w.Header().Set("Access-Control-Allow-Credentials", "true")
		} else if len(allowedOrigins) > 0 && allowedOrigins[0] == "*" {
			w.Header().Set("Access-Control-Allow-Origin", "*")
		}

		w.Header().Set("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS")
		w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization, X-Request-ID")
		w.Header().Set("Access-Control-Expose-Headers", "X-Request-ID")

		// Обрабатываем preflight запросы
		if r.Method == http.MethodOptions {
			w.WriteHeader(http.StatusOK)
			return
		}

		next.ServeHTTP(w, r)
	})
}

// cookieMiddleware - управляет cookies для /auth/login, /auth/refresh и /auth/logout
func cookieMiddleware(cfg *config.Config, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Проверяем, нужно ли обрабатывать этот путь
		path := r.URL.Path
		isLoginPath := strings.HasSuffix(path, "/auth/login")
		isRefreshPath := strings.HasSuffix(path, "/auth/refresh")
		isLogoutPath := strings.HasSuffix(path, "/auth/logout")

		if !isLoginPath && !isRefreshPath && !isLogoutPath {
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

		// Если статус успешный или 209 (профиль не заполнен), парсим ответ и устанавливаем cookies
		if bw.statusCode == http.StatusOK || bw.statusCode == 0 || bw.statusCode == 209 {
			// ... (логика извлечения x-http-code остается прежней)
			httpCode := bw.headers.Get("x-http-code")
			if httpCode == "" {
				httpCode = bw.headers.Get("X-Http-Code")
			}
			if httpCode == "" {
				httpCode = bw.headers.Get("Grpc-Metadata-X-Http-Code")
			}

			if httpCode != "" {
				var code int
				if n, _ := fmt.Sscanf(httpCode, "%d", &code); n > 0 && code != 0 {
					bw.statusCode = code
				}
			}

			// Определяем настройки cookies в зависимости от окружения
			isProd := cfg.App.Env == "production"
			sameSite := http.SameSiteLaxMode
			if isProd {
				sameSite = http.SameSiteNoneMode // Для кросс-доменных запросов в прод
			}

			if isLogoutPath {
				// Для logout очищаем cookies
				http.SetCookie(w, &http.Cookie{
					Name:     AccessTokenCookieName,
					Value:    "",
					Path:     "/",
					HttpOnly: true,
					Secure:   isProd,
					SameSite: sameSite,
					MaxAge:   0,
				})
				http.SetCookie(w, &http.Cookie{
					Name:     RefreshTokenCookieName,
					Value:    "",
					Path:     "/",
					HttpOnly: true,
					Secure:   isProd,
					SameSite: sameSite,
					MaxAge:   0,
				})
			} else {
				var response map[string]interface{}
				if err := json.Unmarshal(bw.buf.Bytes(), &response); err == nil {
					accessToken := getStringField(response, "accessToken", "access_token")
					if accessToken != "" {
						http.SetCookie(w, &http.Cookie{
							Name:     AccessTokenCookieName,
							Value:    accessToken,
							Path:     "/",
							HttpOnly: true,
							Secure:   isProd, // true только для HTTPS
							SameSite: sameSite,
							MaxAge:   AccessTokenMaxAge,
						})
					}

					// Устанавливаем refresh_token в cookie для login и refresh,
					// чтобы клиент всегда получал актуальный токен после обновления
					if isLoginPath || isRefreshPath {
						refreshToken := getStringField(response, "refreshToken", "refresh_token")
						if refreshToken != "" {
							http.SetCookie(w, &http.Cookie{
								Name:     RefreshTokenCookieName,
								Value:    refreshToken,
								Path:     "/",
								HttpOnly: true, // Безопаснее сделать HttpOnly
								Secure:   isProd,
								SameSite: sameSite,
								MaxAge:   RefreshTokenMaxAge,
							})
						}
					}
				}
			}
		}

		// Копируем заголовки и записываем ответ
		for key, values := range bw.headers {
			for _, value := range values {
				w.Header().Set(key, value)
			}
		}

		if bw.statusCode != 0 {
			w.WriteHeader(bw.statusCode)
		} else {
			w.WriteHeader(http.StatusOK)
		}
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

// bufferedErrorWriter - перехватывает ответ ошибки для чтения тела перед отправкой
type bufferedErrorWriter struct {
	http.ResponseWriter
	buf        *bytes.Buffer
	headers    http.Header
	statusCode int
}

func (bw *bufferedErrorWriter) Header() http.Header {
	return bw.headers
}

func (bw *bufferedErrorWriter) WriteHeader(code int) {
	bw.statusCode = code
}

func (bw *bufferedErrorWriter) Write(b []byte) (int, error) {
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

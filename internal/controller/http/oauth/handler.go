package oauth

import (
	"encoding/json"
	"log"
	"net/http"
	"net/url"
	"strings"
	"time"

	usecase "go-auth/internal/usecase/auth"
)

// CookieConfig - конфигурация cookies
type CookieConfig struct {
	Domain    string        // Домен для cookies (пустой = текущий домен)
	Secure    bool          // Только HTTPS
	SameSite  http.SameSite // SameSite policy
	AccessTTL time.Duration // TTL для access token
}

// Handler - HTTP обработчик для OAuth
type Handler struct {
	oauth        usecase.OAuthUseCase
	frontendURL  string       // URL фронтенда для редиректов
	cookieConfig CookieConfig // Конфигурация cookies
}

// NewHandler - создает новый OAuth handler
func NewHandler(oauth usecase.OAuthUseCase, frontendURL string) *Handler {
	return &Handler{
		oauth:       oauth,
		frontendURL: frontendURL,
		cookieConfig: CookieConfig{
			Domain:    "",                   // Пустой = текущий домен
			Secure:    false,                // false для localhost, true для production
			SameSite:  http.SameSiteLaxMode, // Lax для OAuth редиректов
			AccessTTL: 30 * time.Minute,     // 30 минут
		},
	}
}

// NewHandlerWithConfig - создает OAuth handler с кастомной конфигурацией cookies
func NewHandlerWithConfig(oauth usecase.OAuthUseCase, frontendURL string, cookieConfig CookieConfig) *Handler {
	return &Handler{
		oauth:        oauth,
		frontendURL:  frontendURL,
		cookieConfig: cookieConfig,
	}
}

// GetAuthURL обрабатывает GET /api/v1/auth/oauth/{provider}
// Возвращает URL для редиректа на страницу авторизации провайдера
func (h *Handler) GetAuthURL(w http.ResponseWriter, r *http.Request) {
	// Получаем имя провайдера из URL
	provider := extractProvider(r.URL.Path)
	if provider == "" {
		writeError(w, http.StatusBadRequest, "provider is required")
		return
	}

	log.Printf("OAuth: GetAuthURL request for provider: %s", provider)

	// Получаем URL авторизации
	authURL, state, err := h.oauth.GetAuthURL(provider)
	if err != nil {
		log.Printf("OAuth: GetAuthURL error: %v", err)
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}

	// Возвращаем JSON с URL и state
	writeJSON(w, http.StatusOK, map[string]string{
		"auth_url": authURL,
		"state":    state,
	})
}

// Callback обрабатывает GET /api/v1/auth/oauth/{provider}/callback
// Вызывается OAuth провайдером после авторизации пользователя
func (h *Handler) Callback(w http.ResponseWriter, r *http.Request) {
	// Получаем имя провайдера из URL
	provider := extractProviderFromCallback(r.URL.Path)
	if provider == "" {
		redirectWithError(w, r, h.frontendURL, "invalid_provider", "Provider is required")
		return
	}

	log.Printf("OAuth: Callback request for provider: %s", provider)

	// Проверяем ошибку от провайдера
	if errParam := r.URL.Query().Get("error"); errParam != "" {
		errDesc := r.URL.Query().Get("error_description")
		log.Printf("OAuth: Provider returned error: %s - %s", errParam, errDesc)
		redirectWithError(w, r, h.frontendURL, errParam, errDesc)
		return
	}

	// Получаем code и state
	code := r.URL.Query().Get("code")
	state := r.URL.Query().Get("state")

	if code == "" {
		redirectWithError(w, r, h.frontendURL, "missing_code", "Authorization code is required")
		return
	}
	if state == "" {
		redirectWithError(w, r, h.frontendURL, "missing_state", "State is required")
		return
	}

	// Обрабатываем callback
	accessToken, refreshToken, err := h.oauth.HandleCallback(provider, code, state)
	if err != nil {
		log.Printf("OAuth: Callback error: %v", err)
		redirectWithError(w, r, h.frontendURL, "auth_failed", err.Error())
		return
	}

	// Устанавливаем access_token в HTTP-only cookie
	h.setAccessTokenCookie(w, accessToken)
	
	// Редиректим на фронтенд с refresh_token в URL
	redirectWithRefreshToken(w, r, h.frontendURL, refreshToken)
}

// GetProviders обрабатывает GET /api/v1/auth/oauth/providers
// Возвращает список доступных OAuth провайдеров
func (h *Handler) GetProviders(w http.ResponseWriter, r *http.Request) {
	providers := h.oauth.GetProviders()

	writeJSON(w, http.StatusOK, map[string]interface{}{
		"providers": providers,
	})
}

// extractProvider извлекает имя провайдера из пути /api/v1/auth/oauth/{provider}
func extractProvider(path string) string {
	// Удаляем префикс
	path = strings.TrimPrefix(path, "/api/v1/auth/oauth/")
	// Удаляем trailing slash
	path = strings.TrimSuffix(path, "/")
	// Проверяем, что это не callback
	if strings.Contains(path, "/") {
		return ""
	}
	// Проверяем, что это не providers
	if path == "providers" {
		return ""
	}
	return path
}

// extractProviderFromCallback извлекает имя провайдера из пути /api/v1/auth/oauth/{provider}/callback
func extractProviderFromCallback(path string) string {
	// Удаляем префикс
	path = strings.TrimPrefix(path, "/api/v1/auth/oauth/")
	// Удаляем суффикс callback
	path = strings.TrimSuffix(path, "/callback")
	return path
}

// setAccessTokenCookie устанавливает access_token в HTTP-only cookie
func (h *Handler) setAccessTokenCookie(w http.ResponseWriter, accessToken string) {
	http.SetCookie(w, &http.Cookie{
		Name:     "access_token",
		Value:    accessToken,
		Path:     "/",
		Domain:   h.cookieConfig.Domain,
		MaxAge:   int(h.cookieConfig.AccessTTL.Seconds()),
		HttpOnly: true,
		Secure:   h.cookieConfig.Secure,
		SameSite: h.cookieConfig.SameSite,
	})
}

// SetAccessTokenCookie - публичный метод для установки access_token cookie
func (h *Handler) SetAccessTokenCookie(w http.ResponseWriter, accessToken string) {
	h.setAccessTokenCookie(w, accessToken)
}

// ClearAccessTokenCookie очищает access_token из cookies (для logout)
func (h *Handler) ClearAccessTokenCookie(w http.ResponseWriter) {
	http.SetCookie(w, &http.Cookie{
		Name:     "access_token",
		Value:    "",
		Path:     "/",
		Domain:   h.cookieConfig.Domain,
		MaxAge:   -1, // Удаляет cookie
		HttpOnly: true,
		Secure:   h.cookieConfig.Secure,
		SameSite: h.cookieConfig.SameSite,
	})
}

// GetCookieConfig возвращает конфигурацию cookies
func (h *Handler) GetCookieConfig() CookieConfig {
	return h.cookieConfig
}

// redirectWithRefreshToken редиректит на фронтенд с refresh_token в URL
func redirectWithRefreshToken(w http.ResponseWriter, r *http.Request, frontendURL, refreshToken string) {
	u, err := url.Parse(frontendURL)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "invalid frontend URL")
		return
	}

	q := u.Query()
	q.Set("refresh_token", refreshToken)
	u.RawQuery = q.Encode()

	log.Printf("OAuth: Redirecting to frontend with access_token in cookie, refresh_token in URL")
	http.Redirect(w, r, u.String(), http.StatusFound)
}

// redirectWithError редиректит на фронтенд с ошибкой
func redirectWithError(w http.ResponseWriter, r *http.Request, frontendURL, errCode, errDesc string) {
	u, err := url.Parse(frontendURL)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "invalid frontend URL")
		return
	}

	q := u.Query()
	q.Set("error", errCode)
	if errDesc != "" {
		q.Set("error_description", errDesc)
	}
	u.RawQuery = q.Encode()

	log.Printf("OAuth: Redirecting to frontend with error: %s", errCode)
	http.Redirect(w, r, u.String(), http.StatusFound)
}

// writeJSON пишет JSON ответ
func writeJSON(w http.ResponseWriter, status int, data interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(data)
}

// writeError пишет ошибку в JSON
func writeError(w http.ResponseWriter, status int, message string) {
	writeJSON(w, status, map[string]string{
		"error": message,
	})
}



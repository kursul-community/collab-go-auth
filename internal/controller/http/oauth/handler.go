package oauth

import (
	"encoding/json"
	"log"
	"net/http"
	"net/url"
	"strings"

	usecase "go-auth/internal/usecase/auth"
)

// Handler - HTTP обработчик для OAuth
type Handler struct {
	oauth       usecase.OAuthUseCase
	frontendURL string // URL фронтенда для редиректов
}

// NewHandler - создает новый OAuth handler
func NewHandler(oauth usecase.OAuthUseCase, frontendURL string) *Handler {
	return &Handler{
		oauth:       oauth,
		frontendURL: frontendURL,
	}
}

// GetAuthURL обрабатывает GET /api/v1/auth/oauth/{provider}
// Возвращает URL для редиректа на страницу авторизации провайдера
func (h *Handler) GetAuthURL(w http.ResponseWriter, r *http.Request) {
	if h.oauth == nil {
		writeError(w, http.StatusServiceUnavailable, "OAuth is not configured")
		return
	}

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
	if h.oauth == nil {
		redirectWithError(w, r, h.frontendURL, "not_configured", "OAuth is not configured")
		return
	}

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

	// Редиректим на фронтенд с токенами
	redirectWithTokens(w, r, h.frontendURL, accessToken, refreshToken)
}

// GetProviders обрабатывает GET /api/v1/auth/oauth/providers
// Возвращает список доступных OAuth провайдеров
func (h *Handler) GetProviders(w http.ResponseWriter, r *http.Request) {
	if h.oauth == nil {
		writeJSON(w, http.StatusOK, map[string]interface{}{
			"providers": []interface{}{},
		})
		return
	}

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

// Константы для cookies (совпадают с gateway.go)
const (
	accessTokenCookieName  = "access_token"
	refreshTokenCookieName = "refresh_token"
	accessTokenMaxAge      = 30 * 60        // 30 минут
	refreshTokenMaxAge     = 30 * 24 * 3600 // 30 дней
)

// redirectWithTokens редиректит на фронтенд с токенами в cookies
func redirectWithTokens(w http.ResponseWriter, r *http.Request, frontendURL, accessToken, refreshToken string) {
	// Устанавливаем access_token в HttpOnly cookie
	http.SetCookie(w, &http.Cookie{
		Name:     accessTokenCookieName,
		Value:    accessToken,
		Path:     "/",
		HttpOnly: true, // HttpOnly для безопасности
		Secure:   false, // true для HTTPS в production
		SameSite: http.SameSiteLaxMode,
		MaxAge:   accessTokenMaxAge,
	})

	// Устанавливаем refresh_token в cookie (НЕ HttpOnly, чтобы фронтенд мог читать)
	http.SetCookie(w, &http.Cookie{
		Name:     refreshTokenCookieName,
		Value:    refreshToken,
		Path:     "/",
		HttpOnly: false, // НЕ HttpOnly, чтобы фронтенд мог читать для refresh
		Secure:   false, // true для HTTPS в production
		SameSite: http.SameSiteLaxMode,
		MaxAge:   refreshTokenMaxAge,
	})

	log.Printf("OAuth: Redirecting to frontend with tokens in cookies")
	http.Redirect(w, r, frontendURL, http.StatusFound)
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


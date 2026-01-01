package auth

import (
	"encoding/json"
	"errors"
	"log"
	"net/http"
	"time"

	usecase "go-auth/internal/usecase/auth"
)

// CookieConfig - конфигурация cookies
type CookieConfig struct {
	Domain    string
	Secure    bool
	SameSite  http.SameSite
	AccessTTL time.Duration
}

// Handler - HTTP обработчик для аутентификации
type Handler struct {
	auth         usecase.AuthUseCase
	cookieConfig CookieConfig
}

// NewHandler - создает новый Auth handler
func NewHandler(auth usecase.AuthUseCase, cookieConfig CookieConfig) *Handler {
	return &Handler{
		auth:         auth,
		cookieConfig: cookieConfig,
	}
}

// LoginRequest - запрос на логин
type LoginRequest struct {
	Email    string `json:"email"`
	Password string `json:"password"`
}

// LoginResponse - ответ на логин (только refresh_token, access_token в cookie)
type LoginResponse struct {
	RefreshToken string `json:"refresh_token"`
}

// Login обрабатывает POST /api/v1/auth/login
// Устанавливает access_token в HTTP-only cookie
// Возвращает refresh_token в JSON
func (h *Handler) Login(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeError(w, http.StatusMethodNotAllowed, "Method not allowed")
		return
	}

	var req LoginRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "Invalid request body")
		return
	}

	// Валидация
	if req.Email == "" || req.Password == "" {
		writeError(w, http.StatusBadRequest, "Email and password are required")
		return
	}

	log.Printf("Auth: Login request for email: %s", req.Email)

	// Логин
	accessToken, refreshToken, err := h.auth.Login(req.Email, req.Password)
	if err != nil {
		log.Printf("Auth: Login failed for email %s: %v", req.Email, err)
		
		if errors.Is(err, usecase.ErrInvalidCredentials) {
			writeError(w, http.StatusUnauthorized, "Invalid email or password")
			return
		}
		if errors.Is(err, usecase.ErrUserNotActive) {
			writeError(w, http.StatusForbidden, "User account is not active")
			return
		}
		
		writeError(w, http.StatusInternalServerError, "Login failed")
		return
	}

	// Устанавливаем access_token в HTTP-only cookie
	h.setAccessTokenCookie(w, accessToken)

	log.Printf("Auth: Login successful for email: %s", req.Email)

	// Возвращаем refresh_token в JSON
	writeJSON(w, http.StatusOK, LoginResponse{
		RefreshToken: refreshToken,
	})
}

// RefreshRequest - запрос на обновление токена
type RefreshRequest struct {
	RefreshToken string `json:"refresh_token"`
}

// RefreshResponse - ответ на обновление токена
type RefreshResponse struct {
	RefreshToken string `json:"refresh_token,omitempty"` // Новый refresh_token (если ротация)
}

// RefreshToken обрабатывает POST /api/v1/auth/refresh
// Устанавливает новый access_token в HTTP-only cookie
// Возвращает пустой JSON (или новый refresh_token при ротации)
func (h *Handler) RefreshToken(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeError(w, http.StatusMethodNotAllowed, "Method not allowed")
		return
	}

	var req RefreshRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "Invalid request body")
		return
	}

	if req.RefreshToken == "" {
		writeError(w, http.StatusBadRequest, "Refresh token is required")
		return
	}

	log.Printf("Auth: Refresh token request")

	// Обновление токена
	accessToken, err := h.auth.RefreshToken(req.RefreshToken)
	if err != nil {
		log.Printf("Auth: Refresh token failed: %v", err)
		
		if errors.Is(err, usecase.ErrInvalidRefreshToken) || errors.Is(err, usecase.ErrRefreshTokenNotFound) {
			writeError(w, http.StatusUnauthorized, "Invalid or expired refresh token")
			return
		}
		
		writeError(w, http.StatusInternalServerError, "Token refresh failed")
		return
	}

	// Устанавливаем новый access_token в HTTP-only cookie
	h.setAccessTokenCookie(w, accessToken)

	log.Printf("Auth: Token refreshed successfully")

	// Возвращаем пустой ответ (access_token в cookie)
	writeJSON(w, http.StatusOK, map[string]string{
		"message": "Token refreshed successfully",
	})
}

// Logout обрабатывает POST /api/v1/auth/logout
// Очищает access_token cookie
func (h *Handler) Logout(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeError(w, http.StatusMethodNotAllowed, "Method not allowed")
		return
	}

	// Очищаем access_token cookie
	h.clearAccessTokenCookie(w)

	log.Printf("Auth: Logout successful")

	writeJSON(w, http.StatusOK, map[string]string{
		"message": "Logout successful",
	})
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

// clearAccessTokenCookie очищает access_token cookie
func (h *Handler) clearAccessTokenCookie(w http.ResponseWriter) {
	http.SetCookie(w, &http.Cookie{
		Name:     "access_token",
		Value:    "",
		Path:     "/",
		Domain:   h.cookieConfig.Domain,
		MaxAge:   -1,
		HttpOnly: true,
		Secure:   h.cookieConfig.Secure,
		SameSite: h.cookieConfig.SameSite,
	})
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


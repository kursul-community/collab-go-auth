package usecase

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/url"
	"time"

	"github.com/google/uuid"

	"go-auth/internal/adapter/oauth"
	"go-auth/internal/entity"
)

// TTL для OAuth state (10 минут)
const OAuthStateTTL = 10 * time.Minute

var (
	ErrOAuthProviderNotFound   = errors.New("oauth provider not found")
	ErrOAuthProviderNotEnabled = errors.New("oauth provider not enabled")
	ErrOAuthInvalidState       = errors.New("invalid or expired oauth state")
	ErrOAuthExchangeFailed     = errors.New("failed to exchange oauth code")
	ErrOAuthUserInfoFailed     = errors.New("failed to get user info from oauth provider")
)

// OAuthUseCase - интерфейс для OAuth аутентификации
type OAuthUseCase interface {
	// GetAuthURL - получает URL для OAuth авторизации
	GetAuthURL(provider, frontendURL string) (authURL, state string, err error)
	// HandleCallback - обрабатывает callback от OAuth провайдера
	HandleCallback(provider, code, state string) (accessToken, refreshToken, redirectURL string, err error)
	// GetProviders - возвращает список доступных OAuth провайдеров с ссылками
	GetProviders(frontendURL string) ([]ProviderResponse, error)
}

// OAuthStateData - данные, сохраняемые в Redis для OAuth state
type OAuthStateData struct {
	Provider    string `json:"provider"`
	FrontendURL string `json:"frontend_url"`
}

// ProviderResponse - ответ для списка провайдеров
type ProviderResponse struct {
	DisplayName string `json:"displayName"`
	AuthURL     string `json:"auth_url"`
	State       string `json:"state"`
}

// oauthUseCase - реализация OAuthUseCase
type oauthUseCase struct {
	*auth        // встраиваем базовый auth для доступа к репозиториям и токенам
	oauthManager *oauth.Manager
	stateTTL     time.Duration
}

// NewOAuthUseCase - создает OAuth use case
func NewOAuthUseCase(baseAuth *auth, oauthManager *oauth.Manager, stateTTL time.Duration) OAuthUseCase {
	if stateTTL == 0 {
		stateTTL = OAuthStateTTL
	}

	return &oauthUseCase{
		auth:         baseAuth,
		oauthManager: oauthManager,
		stateTTL:     stateTTL,
	}
}

// GetAuthURL - генерирует URL для OAuth авторизации
func (uc *oauthUseCase) GetAuthURL(providerName, frontendURL string) (string, string, error) {
	ctx := context.Background()

	// Получаем провайдера
	provider, err := uc.oauthManager.GetProvider(providerName)
	if err != nil {
		log.Printf("OAuth: provider %s not found", providerName)
		return "", "", ErrOAuthProviderNotFound
	}

	// Генерируем state для CSRF защиты
	state, err := oauth.GenerateState()
	if err != nil {
		log.Printf("OAuth: failed to generate state: %v", err)
		return "", "", err
	}

	// Подготавливаем данные для сохранения
	stateData := OAuthStateData{
		Provider:    providerName,
		FrontendURL: frontendURL,
	}
	jsonData, _ := json.Marshal(stateData)

	// Сохраняем state в Redis
	log.Printf("OAuth: storing state '%s' for provider '%s' with TTL %v", state, providerName, uc.stateTTL)
	err = uc.tokenRepo.StoreOAuthState(ctx, state, string(jsonData), uc.stateTTL)
	if err != nil {
		log.Printf("OAuth: failed to store state in Redis: %v", err)
		return "", "", err
	}
	log.Printf("OAuth: state stored successfully")

	// Формируем callback URL
	callbackURL := uc.oauthManager.GetCallbackURL(providerName)

	// Получаем URL авторизации
	authURL := provider.GetAuthURL(state, callbackURL)

	log.Printf("OAuth: generated auth URL for provider %s", providerName)
	return authURL, state, nil
}

// HandleCallback - обрабатывает callback от OAuth провайдера
func (uc *oauthUseCase) HandleCallback(providerName, code, state string) (string, string, string, error) {
	ctx := context.Background()

	log.Printf("OAuth: handling callback for provider %s", providerName)

	// Проверяем state
	log.Printf("OAuth: checking state: %s", state)
	storedData, err := uc.tokenRepo.GetOAuthState(ctx, state)
	if err != nil {
		log.Printf("OAuth: failed to get state from Redis: %v", err)
		return "", "", "", ErrOAuthInvalidState
	}

	if storedData == "" {
		log.Printf("OAuth: empty state data for state: %s", state)
		return "", "", "", ErrOAuthInvalidState
	}

	var stateData OAuthStateData
	if err := json.Unmarshal([]byte(storedData), &stateData); err != nil {
		log.Printf("OAuth: failed to unmarshal state data: %v", err)
		return "", "", "", ErrOAuthInvalidState
	}

	if stateData.Provider != providerName {
		log.Printf("OAuth: invalid provider in state (expected '%s', got '%s')", providerName, stateData.Provider)
		return "", "", "", ErrOAuthInvalidState
	}

	// Удаляем использованный state
	uc.tokenRepo.DeleteOAuthState(ctx, state)

	// Получаем провайдера
	provider, err := uc.oauthManager.GetProvider(providerName)
	if err != nil {
		return "", "", "", ErrOAuthProviderNotFound
	}

	// Обмениваем code на access token провайдера
	callbackURL := uc.oauthManager.GetCallbackURL(providerName)
	log.Printf("OAuth: exchanging code for token, callbackURL: %s", callbackURL)

	tokenResp, err := provider.ExchangeCode(ctx, code, callbackURL)
	if err != nil {
		log.Printf("OAuth: failed to exchange code: %v", err)
		return "", "", "", fmt.Errorf("%w: %v", ErrOAuthExchangeFailed, err)
	}

	log.Printf("OAuth: successfully exchanged code for token")

	// Получаем информацию о пользователе от провайдера
	log.Printf("OAuth: fetching user info from provider")
	userInfo, err := provider.GetUserInfo(ctx, tokenResp.AccessToken)
	if err != nil {
		log.Printf("OAuth: failed to get user info: %v", err)
		log.Printf("OAuth: error details: %+v", err)
		return "", "", "", fmt.Errorf("%w: %v", ErrOAuthUserInfoFailed, err)
	}

	log.Printf("OAuth: successfully got user info - email: %s, id: %s", userInfo.Email, userInfo.ID)

	// Ищем или создаем пользователя
	user, err := uc.findOrCreateOAuthUser(ctx, userInfo)
	if err != nil {
		log.Printf("OAuth: failed to find/create user: %v", err)
		return "", "", "", err
	}

	// Генерируем JWT токены
	accessToken, err := uc.tokenService.GenerateAccessToken(user)
	if err != nil {
		return "", "", "", err
	}

	refreshToken, err := uc.tokenService.GenerateRefreshToken(user)
	if err != nil {
		return "", "", "", err
	}

	// Сохраняем токены в Redis
	err = uc.tokenRepo.StoreAccessToken(ctx, user.ID, accessToken, uc.accessTTL)
	if err != nil {
		return "", "", "", err
	}

	err = uc.tokenRepo.StoreRefreshToken(ctx, user.ID, refreshToken, uc.refreshTTL)
	if err != nil {
		return "", "", "", err
	}

	log.Printf("OAuth: successfully authenticated user %s via %s", user.ID, providerName)

	// Определяем, куда редиректить пользователя: на главную или на создание профиля
	redirectURL := stateData.FrontendURL
	if uc.userClient != nil {
		exists, err := uc.userClient.ProfileExists(ctx, user.ID)
		if err != nil {
			log.Printf("OAuth: failed to check profile existence for user %s: %v", user.ID, err)
		} else {
			targetPath := "/"
			if !exists {
				targetPath = "/auth/create-profile"
			}

			if parsed, err := url.Parse(stateData.FrontendURL); err == nil {
				parsed.Path = targetPath
				parsed.RawQuery = ""
				parsed.Fragment = ""
				redirectURL = parsed.String()
			} else {
				log.Printf("OAuth: failed to parse frontend URL '%s': %v", stateData.FrontendURL, err)
			}
		}
	}

	return accessToken, refreshToken, redirectURL, nil
}

// findOrCreateOAuthUser - ищет существующего пользователя или создает нового
func (uc *oauthUseCase) findOrCreateOAuthUser(ctx context.Context, userInfo *entity.OAuthUserInfo) (*entity.User, error) {
	// 1. Сначала ищем по OAuth провайдеру и ID
	user, err := uc.userRepo.GetUserByOAuthProvider(ctx, userInfo.Provider, userInfo.ID)
	if err == nil && user != nil {
		log.Printf("OAuth: found existing user by provider - user_id: %s", user.ID)
		return user, nil
	}

	// 2. Ищем по email
	user, err = uc.userRepo.GetUserByEmail(ctx, userInfo.Email)
	if err == nil && user != nil {
		// Пользователь найден по email - привязываем OAuth провайдера
		log.Printf("OAuth: found existing user by email, linking provider - user_id: %s", user.ID)
		err = uc.userRepo.LinkOAuthProvider(ctx, user.ID, userInfo.Provider, userInfo.ID)
		if err != nil {
			log.Printf("OAuth: failed to link provider: %v", err)
			// Не критично, продолжаем
		}
		return user, nil
	}

	// 3. Создаем нового пользователя
	log.Printf("OAuth: creating new user for email: %s", userInfo.Email)

	userID := uuid.New().String()
	provider := userInfo.Provider
	providerID := userInfo.ID

	newUser := &entity.User{
		ID:              userID,
		Email:           userInfo.Email,
		Password:        "", // Пароль не нужен для OAuth
		IsActive:        true,
		EmailVerified:   true, // Email уже подтвержден провайдером
		OAuthProvider:   &provider,
		OAuthProviderID: &providerID,
	}

	_, err = uc.userRepo.CreateOAuthUser(ctx, newUser)
	if err != nil {
		return nil, err
	}

	log.Printf("OAuth: created new user - user_id: %s", userID)
	return newUser, nil
}

// GetProviders - возвращает список доступных OAuth провайдеров с ссылками и state
func (uc *oauthUseCase) GetProviders(frontendURL string) ([]ProviderResponse, error) {
	enabledProviders := uc.oauthManager.GetEnabledProviders()
	var response []ProviderResponse

	for _, p := range enabledProviders {
		authURL, state, err := uc.GetAuthURL(p.Name, frontendURL)
		if err != nil {
			log.Printf("OAuth: failed to get auth URL for provider %s: %v", p.Name, err)
			continue
		}

		response = append(response, ProviderResponse{
			DisplayName: p.Name,
			AuthURL:     authURL,
			State:       state,
		})
	}

	return response, nil
}

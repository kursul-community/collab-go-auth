package usecase

import (
	"context"
	"errors"
	"fmt"
	"log"
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
	GetAuthURL(provider string) (authURL, state string, err error)
	// HandleCallback - обрабатывает callback от OAuth провайдера
	HandleCallback(provider, code, state string) (accessToken, refreshToken string, err error)
	// GetProviders - возвращает список доступных OAuth провайдеров
	GetProviders() []oauth.ProviderInfo
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
func (uc *oauthUseCase) GetAuthURL(providerName string) (string, string, error) {
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

	// Сохраняем state в Redis
	log.Printf("OAuth: storing state '%s' for provider '%s' with TTL %v", state, providerName, uc.stateTTL)
	err = uc.tokenRepo.StoreOAuthState(ctx, state, providerName, uc.stateTTL)
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
func (uc *oauthUseCase) HandleCallback(providerName, code, state string) (string, string, error) {
	ctx := context.Background()

	log.Printf("OAuth: handling callback for provider %s", providerName)

	// Проверяем state
	log.Printf("OAuth: checking state: %s", state)
	storedProvider, err := uc.tokenRepo.GetOAuthState(ctx, state)
	if err != nil {
		log.Printf("OAuth: failed to get state from Redis: %v", err)
		return "", "", ErrOAuthInvalidState
	}
	log.Printf("OAuth: stored provider for state: '%s'", storedProvider)
	if storedProvider == "" || storedProvider != providerName {
		log.Printf("OAuth: invalid state for provider %s (expected '%s', got '%s')", providerName, providerName, storedProvider)
		return "", "", ErrOAuthInvalidState
	}

	// Удаляем использованный state
	uc.tokenRepo.DeleteOAuthState(ctx, state)

	// Получаем провайдера
	provider, err := uc.oauthManager.GetProvider(providerName)
	if err != nil {
		return "", "", ErrOAuthProviderNotFound
	}

	// Обмениваем code на access token провайдера
	callbackURL := uc.oauthManager.GetCallbackURL(providerName)
	log.Printf("OAuth: exchanging code for token, callbackURL: %s", callbackURL)
	tokenResp, err := provider.ExchangeCode(ctx, code, callbackURL)
	if err != nil {
		log.Printf("OAuth: failed to exchange code: %v", err)
		return "", "", fmt.Errorf("%w: %v", ErrOAuthExchangeFailed, err)
	}
	log.Printf("OAuth: successfully exchanged code for token")

	// Получаем информацию о пользователе от провайдера
	log.Printf("OAuth: fetching user info from provider")
	userInfo, err := provider.GetUserInfo(ctx, tokenResp.AccessToken)
	if err != nil {
		log.Printf("OAuth: failed to get user info: %v", err)
		log.Printf("OAuth: error details: %+v", err)
		return "", "", fmt.Errorf("%w: %v", ErrOAuthUserInfoFailed, err)
	}
	log.Printf("OAuth: successfully got user info - email: %s, id: %s", userInfo.Email, userInfo.ID)

	log.Printf("OAuth: got user info - email: %s, provider_id: %s", userInfo.Email, userInfo.ID)

	// Ищем или создаем пользователя
	user, err := uc.findOrCreateOAuthUser(ctx, userInfo)
	if err != nil {
		log.Printf("OAuth: failed to find/create user: %v", err)
		return "", "", err
	}

	// Генерируем JWT токены
	accessToken, err := uc.tokenService.GenerateAccessToken(user)
	if err != nil {
		return "", "", err
	}

	refreshToken, err := uc.tokenService.GenerateRefreshToken(user)
	if err != nil {
		return "", "", err
	}

	// Сохраняем токены в Redis
	err = uc.tokenRepo.StoreAccessToken(ctx, user.ID, accessToken, uc.accessTTL)
	if err != nil {
		return "", "", err
	}

	err = uc.tokenRepo.StoreRefreshToken(ctx, user.ID, refreshToken, uc.refreshTTL)
	if err != nil {
		return "", "", err
	}

	log.Printf("OAuth: successfully authenticated user %s via %s", user.ID, providerName)
	return accessToken, refreshToken, nil
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

// GetProviders - возвращает список доступных OAuth провайдеров
func (uc *oauthUseCase) GetProviders() []oauth.ProviderInfo {
	return uc.oauthManager.GetEnabledProviders()
}



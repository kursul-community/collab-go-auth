package oauth

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"go-auth/config"
	"go-auth/internal/entity"
)

var (
	ErrProviderNotFound    = errors.New("oauth provider not found")
	ErrProviderNotEnabled  = errors.New("oauth provider not enabled")
	ErrInvalidState        = errors.New("invalid oauth state")
	ErrTokenExchange       = errors.New("failed to exchange code for token")
	ErrFetchUserInfo       = errors.New("failed to fetch user info")
	ErrInvalidUserInfo     = errors.New("invalid user info from provider")
)

// Provider - интерфейс OAuth провайдера
type Provider interface {
	// GetName - возвращает имя провайдера
	GetName() string
	// GetAuthURL - возвращает URL для авторизации
	GetAuthURL(state, redirectURI string) string
	// ExchangeCode - обменивает code на access token
	ExchangeCode(ctx context.Context, code, redirectURI string) (*TokenResponse, error)
	// GetUserInfo - получает информацию о пользователе
	GetUserInfo(ctx context.Context, accessToken string) (*entity.OAuthUserInfo, error)
}

// TokenResponse - ответ с токеном от OAuth провайдера
type TokenResponse struct {
	AccessToken  string `json:"access_token"`
	TokenType    string `json:"token_type"`
	ExpiresIn    int    `json:"expires_in"`
	RefreshToken string `json:"refresh_token,omitempty"`
	Scope        string `json:"scope,omitempty"`
}

// Manager - менеджер OAuth провайдеров
type Manager struct {
	config    *config.OAuthConfig
	providers map[string]Provider
	client    *http.Client
}

// NewManager - создает новый OAuth менеджер
func NewManager(cfg *config.OAuthConfig) *Manager {
	m := &Manager{
		config:    cfg,
		providers: make(map[string]Provider),
		client: &http.Client{
			Timeout: 30 * time.Second,
		},
	}

	// Регистрируем провайдеров
	for name, providerCfg := range cfg.Providers {
		if !providerCfg.Enabled {
			continue
		}

		switch strings.ToLower(name) {
		case "google":
			m.providers[name] = NewGoogleProvider(providerCfg, m.client)
		case "github":
			m.providers[name] = NewGitHubProvider(providerCfg, m.client)
		case "yandex":
			m.providers[name] = NewYandexProvider(providerCfg, m.client)
		case "vk":
			m.providers[name] = NewVKProvider(providerCfg, m.client)
		}
	}

	return m
}

// GetProvider - возвращает провайдера по имени
func (m *Manager) GetProvider(name string) (Provider, error) {
	provider, ok := m.providers[strings.ToLower(name)]
	if !ok {
		return nil, ErrProviderNotFound
	}
	return provider, nil
}

// GetEnabledProviders - возвращает список включенных провайдеров
func (m *Manager) GetEnabledProviders() []ProviderInfo {
	var providers []ProviderInfo
	for name, providerCfg := range m.config.Providers {
		if providerCfg.Enabled && providerCfg.ClientID != "" {
			providers = append(providers, ProviderInfo{
				Name:        name,
				DisplayName: providerCfg.DisplayName,
				Enabled:     true,
			})
		}
	}
	return providers
}

// ProviderInfo - информация о провайдере
type ProviderInfo struct {
	Name        string `json:"name"`
	DisplayName string `json:"display_name"`
	Enabled     bool   `json:"enabled"`
}

// GenerateState - генерирует случайный state для защиты от CSRF
func GenerateState() (string, error) {
	b := make([]byte, 32)
	_, err := rand.Read(b)
	if err != nil {
		return "", err
	}
	return base64.URLEncoding.EncodeToString(b), nil
}

// GetCallbackURL - формирует callback URL для провайдера
func (m *Manager) GetCallbackURL(provider string) string {
	return fmt.Sprintf("%s/api/v1/auth/oauth/%s/callback", m.config.BackendBaseURL, provider)
}

// BaseProvider - базовая реализация провайдера
type BaseProvider struct {
	name        string
	config      config.OAuthProviderConfig
	client      *http.Client
}

// GetName - возвращает имя провайдера
func (p *BaseProvider) GetName() string {
	return p.name
}

// GetAuthURL - формирует URL для авторизации
func (p *BaseProvider) GetAuthURL(state, redirectURI string) string {
	params := url.Values{}
	params.Set("client_id", p.config.ClientID)
	params.Set("redirect_uri", redirectURI)
	params.Set("response_type", "code")
	params.Set("state", state)
	params.Set("scope", strings.Join(p.config.Scopes, " "))

	return fmt.Sprintf("%s?%s", p.config.AuthURL, params.Encode())
}

// exchangeCodeBase - базовый метод обмена кода на токен
func (p *BaseProvider) exchangeCodeBase(ctx context.Context, code, redirectURI string) (*TokenResponse, error) {
	data := url.Values{}
	data.Set("client_id", p.config.ClientID)
	data.Set("client_secret", p.config.ClientSecret)
	data.Set("code", code)
	data.Set("redirect_uri", redirectURI)
	data.Set("grant_type", "authorization_code")

	req, err := http.NewRequestWithContext(ctx, "POST", p.config.TokenURL, strings.NewReader(data.Encode()))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")

	resp, err := p.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	bodyBytes, _ := io.ReadAll(resp.Body)
	bodyStr := string(bodyBytes)

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("%w: status %d, body: %s", ErrTokenExchange, resp.StatusCode, bodyStr)
	}

	var token TokenResponse
	
	// GitHub возвращает form-urlencoded, а не JSON
	contentType := resp.Header.Get("Content-Type")
	if strings.Contains(contentType, "application/x-www-form-urlencoded") || 
	   strings.Contains(contentType, "text/html") ||
	   !strings.Contains(contentType, "application/json") {
		// Парсим form-urlencoded ответ
		values, err := url.ParseQuery(bodyStr)
		if err != nil {
			return nil, fmt.Errorf("%w: failed to parse form response: %v", ErrTokenExchange, err)
		}
		
		token.AccessToken = values.Get("access_token")
		token.TokenType = values.Get("token_type")
		token.Scope = values.Get("scope")
		
		if token.AccessToken == "" {
			return nil, fmt.Errorf("%w: access_token not found in response: %s", ErrTokenExchange, bodyStr)
		}
	} else {
		// Парсим JSON ответ (для других провайдеров)
		if err := json.Unmarshal(bodyBytes, &token); err != nil {
			return nil, fmt.Errorf("%w: failed to decode JSON response: %v, body: %s", ErrTokenExchange, err, bodyStr)
		}
	}

	return &token, nil
}

// === Google Provider ===

type GoogleProvider struct {
	BaseProvider
}

func NewGoogleProvider(cfg config.OAuthProviderConfig, client *http.Client) *GoogleProvider {
	return &GoogleProvider{
		BaseProvider: BaseProvider{
			name:   "google",
			config: cfg,
			client: client,
		},
	}
}

func (p *GoogleProvider) ExchangeCode(ctx context.Context, code, redirectURI string) (*TokenResponse, error) {
	return p.exchangeCodeBase(ctx, code, redirectURI)
}

func (p *GoogleProvider) GetUserInfo(ctx context.Context, accessToken string) (*entity.OAuthUserInfo, error) {
	req, err := http.NewRequestWithContext(ctx, "GET", p.config.UserInfoURL, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+accessToken)

	resp, err := p.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, ErrFetchUserInfo
	}

	var data struct {
		ID      string `json:"id"`
		Email   string `json:"email"`
		Name    string `json:"name"`
		Picture string `json:"picture"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&data); err != nil {
		return nil, err
	}

	if data.Email == "" {
		return nil, ErrInvalidUserInfo
	}

	return &entity.OAuthUserInfo{
		ID:       data.ID,
		Email:    data.Email,
		Name:     data.Name,
		Avatar:   data.Picture,
		Provider: "google",
	}, nil
}

// === GitHub Provider ===

type GitHubProvider struct {
	BaseProvider
}

func NewGitHubProvider(cfg config.OAuthProviderConfig, client *http.Client) *GitHubProvider {
	return &GitHubProvider{
		BaseProvider: BaseProvider{
			name:   "github",
			config: cfg,
			client: client,
		},
	}
}

func (p *GitHubProvider) ExchangeCode(ctx context.Context, code, redirectURI string) (*TokenResponse, error) {
	// GitHub требует особый формат Accept заголовка для token endpoint
	data := url.Values{}
	data.Set("client_id", p.config.ClientID)
	data.Set("client_secret", p.config.ClientSecret)
	data.Set("code", code)
	data.Set("redirect_uri", redirectURI)

	req, err := http.NewRequestWithContext(ctx, "POST", p.config.TokenURL, strings.NewReader(data.Encode()))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")

	resp, err := p.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrTokenExchange, err)
	}
	defer resp.Body.Close()

	bodyBytes, _ := io.ReadAll(resp.Body)
	bodyStr := string(bodyBytes)

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("%w: status %d, body: %s", ErrTokenExchange, resp.StatusCode, bodyStr)
	}

	var token TokenResponse
	
	// GitHub возвращает JSON, но может быть и form-urlencoded
	contentType := resp.Header.Get("Content-Type")
	if strings.Contains(contentType, "application/x-www-form-urlencoded") {
		values, err := url.ParseQuery(bodyStr)
		if err != nil {
			return nil, fmt.Errorf("%w: failed to parse form response: %v", ErrTokenExchange, err)
		}
		token.AccessToken = values.Get("access_token")
		token.TokenType = values.Get("token_type")
		token.Scope = values.Get("scope")
	} else {
		if err := json.Unmarshal(bodyBytes, &token); err != nil {
			return nil, fmt.Errorf("%w: failed to decode JSON response: %v, body: %s", ErrTokenExchange, err, bodyStr)
		}
	}

	if token.AccessToken == "" {
		return nil, fmt.Errorf("%w: access_token not found in response: %s", ErrTokenExchange, bodyStr)
	}

	return &token, nil
}

func (p *GitHubProvider) GetUserInfo(ctx context.Context, accessToken string) (*entity.OAuthUserInfo, error) {
	// Получаем информацию о пользователе
	req, err := http.NewRequestWithContext(ctx, "GET", p.config.UserInfoURL, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+accessToken)
	req.Header.Set("Accept", "application/vnd.github.v3+json")

	resp, err := p.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrFetchUserInfo, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("%w: status %d, body: %s", ErrFetchUserInfo, resp.StatusCode, string(body))
	}

	var data struct {
		ID        int64  `json:"id"`
		Login     string `json:"login"`
		Name      string `json:"name"`
		Email     string `json:"email"`
		AvatarURL string `json:"avatar_url"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&data); err != nil {
		return nil, fmt.Errorf("%w: failed to decode response: %v", ErrFetchUserInfo, err)
	}

	// Если email не получен, запрашиваем отдельно
	email := data.Email
	if email == "" {
		var emailErr error
		email, emailErr = p.fetchPrimaryEmail(ctx, accessToken)
		if emailErr != nil {
			return nil, fmt.Errorf("%w: failed to fetch email: %v", ErrFetchUserInfo, emailErr)
		}
	}

	if email == "" {
		return nil, fmt.Errorf("%w: email not found in user info and email list", ErrInvalidUserInfo)
	}

	return &entity.OAuthUserInfo{
		ID:       fmt.Sprintf("%d", data.ID),
		Email:    email,
		Name:     data.Name,
		Avatar:   data.AvatarURL,
		Provider: "github",
	}, nil
}

func (p *GitHubProvider) fetchPrimaryEmail(ctx context.Context, accessToken string) (string, error) {
	req, err := http.NewRequestWithContext(ctx, "GET", "https://api.github.com/user/emails", nil)
	if err != nil {
		return "", err
	}
	req.Header.Set("Authorization", "Bearer "+accessToken)
	req.Header.Set("Accept", "application/vnd.github.v3+json")

	resp, err := p.client.Do(req)
	if err != nil {
		return "", fmt.Errorf("failed to fetch emails: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return "", fmt.Errorf("failed to fetch emails: status %d, body: %s", resp.StatusCode, string(body))
	}

	var emails []struct {
		Email    string `json:"email"`
		Primary  bool   `json:"primary"`
		Verified bool   `json:"verified"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&emails); err != nil {
		return "", fmt.Errorf("failed to decode emails: %w", err)
	}

	// Сначала ищем primary и verified
	for _, e := range emails {
		if e.Primary && e.Verified {
			return e.Email, nil
		}
	}

	// Если нет primary+verified, берем первый verified
	for _, e := range emails {
		if e.Verified {
			return e.Email, nil
		}
	}

	// Если нет verified, берем первый email
	if len(emails) > 0 {
		return emails[0].Email, nil
	}

	return "", fmt.Errorf("no emails found")
}

// === Yandex Provider ===

type YandexProvider struct {
	BaseProvider
}

func NewYandexProvider(cfg config.OAuthProviderConfig, client *http.Client) *YandexProvider {
	return &YandexProvider{
		BaseProvider: BaseProvider{
			name:   "yandex",
			config: cfg,
			client: client,
		},
	}
}

func (p *YandexProvider) ExchangeCode(ctx context.Context, code, redirectURI string) (*TokenResponse, error) {
	return p.exchangeCodeBase(ctx, code, redirectURI)
}

func (p *YandexProvider) GetUserInfo(ctx context.Context, accessToken string) (*entity.OAuthUserInfo, error) {
	req, err := http.NewRequestWithContext(ctx, "GET", p.config.UserInfoURL+"?format=json", nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "OAuth "+accessToken)

	resp, err := p.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, ErrFetchUserInfo
	}

	var data struct {
		ID           string `json:"id"`
		DefaultEmail string `json:"default_email"`
		RealName     string `json:"real_name"`
		Avatar       string `json:"default_avatar_id"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&data); err != nil {
		return nil, err
	}

	if data.DefaultEmail == "" {
		return nil, ErrInvalidUserInfo
	}

	avatarURL := ""
	if data.Avatar != "" {
		avatarURL = fmt.Sprintf("https://avatars.yandex.net/get-yapic/%s/islands-200", data.Avatar)
	}

	return &entity.OAuthUserInfo{
		ID:       data.ID,
		Email:    data.DefaultEmail,
		Name:     data.RealName,
		Avatar:   avatarURL,
		Provider: "yandex",
	}, nil
}

// === VK Provider ===

type VKProvider struct {
	BaseProvider
	apiVersion string
}

func NewVKProvider(cfg config.OAuthProviderConfig, client *http.Client) *VKProvider {
	return &VKProvider{
		BaseProvider: BaseProvider{
			name:   "vk",
			config: cfg,
			client: client,
		},
		apiVersion: "5.131",
	}
}

func (p *VKProvider) ExchangeCode(ctx context.Context, code, redirectURI string) (*TokenResponse, error) {
	return p.exchangeCodeBase(ctx, code, redirectURI)
}

func (p *VKProvider) GetUserInfo(ctx context.Context, accessToken string) (*entity.OAuthUserInfo, error) {
	// VK требует особый формат запроса
	params := url.Values{}
	params.Set("access_token", accessToken)
	params.Set("fields", "photo_200,email")
	params.Set("v", p.apiVersion)

	reqURL := fmt.Sprintf("%s?%s", p.config.UserInfoURL, params.Encode())
	req, err := http.NewRequestWithContext(ctx, "GET", reqURL, nil)
	if err != nil {
		return nil, err
	}

	resp, err := p.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, ErrFetchUserInfo
	}

	var data struct {
		Response []struct {
			ID       int64  `json:"id"`
			FirstName string `json:"first_name"`
			LastName  string `json:"last_name"`
			Photo200  string `json:"photo_200"`
		} `json:"response"`
		Error struct {
			ErrorCode int    `json:"error_code"`
			ErrorMsg  string `json:"error_msg"`
		} `json:"error"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&data); err != nil {
		return nil, err
	}

	if data.Error.ErrorCode != 0 {
		return nil, fmt.Errorf("%w: %s", ErrFetchUserInfo, data.Error.ErrorMsg)
	}

	if len(data.Response) == 0 {
		return nil, ErrInvalidUserInfo
	}

	user := data.Response[0]
	name := strings.TrimSpace(user.FirstName + " " + user.LastName)

	// VK не возвращает email в user.get, его нужно брать из token response
	// Для этого email должен быть передан через контекст или параметр
	return &entity.OAuthUserInfo{
		ID:       fmt.Sprintf("%d", user.ID),
		Email:    "", // Email передается отдельно от VK
		Name:     name,
		Avatar:   user.Photo200,
		Provider: "vk",
	}, nil
}




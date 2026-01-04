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
	ErrProviderNotFound   = errors.New("oauth provider not found")
	ErrProviderNotEnabled = errors.New("oauth provider not enabled")
	ErrInvalidResponse    = errors.New("invalid response from provider")
)

// TokenResponse - ответ от OAuth провайдера с токеном
type TokenResponse struct {
	AccessToken  string `json:"access_token"`
	TokenType    string `json:"token_type"`
	ExpiresIn    int    `json:"expires_in"`
	RefreshToken string `json:"refresh_token,omitempty"`
	Scope        string `json:"scope,omitempty"`
}

// ProviderInfo - информация о провайдере для фронтенда
type ProviderInfo struct {
	Name        string `json:"name"`
	DisplayName string `json:"display_name"`
	Enabled     bool   `json:"enabled"`
}

// Provider - интерфейс OAuth провайдера
type Provider interface {
	GetName() string
	GetAuthURL(state, redirectURL string) string
	ExchangeCode(ctx context.Context, code, redirectURL string) (*TokenResponse, error)
	GetUserInfo(ctx context.Context, accessToken string) (*entity.OAuthUserInfo, error)
}

// Manager - менеджер OAuth провайдеров
type Manager struct {
	providers   map[string]Provider
	config      *config.OAuthConfig
	httpClient  *http.Client
}

// NewManager - создает новый OAuth менеджер
func NewManager(cfg *config.OAuthConfig) *Manager {
	m := &Manager{
		providers: make(map[string]Provider),
		config:    cfg,
		httpClient: &http.Client{
			Timeout: 30 * time.Second,
		},
	}

	// Инициализируем провайдеров
	for name, providerCfg := range cfg.Providers {
		if !providerCfg.Enabled {
			continue
		}

		switch strings.ToLower(name) {
		case "google":
			m.providers[name] = newGoogleProvider(providerCfg, m.httpClient)
		case "github":
			m.providers[name] = newGitHubProvider(providerCfg, m.httpClient)
		case "yandex":
			m.providers[name] = newYandexProvider(providerCfg, m.httpClient)
		case "vk":
			m.providers[name] = newVKProvider(providerCfg, m.httpClient)
		}
	}

	return m
}

// GetProvider - получает провайдера по имени
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
		if providerCfg.Enabled && providerCfg.ClientID != "" && providerCfg.ClientSecret != "" {
			providers = append(providers, ProviderInfo{
				Name:        name,
				DisplayName: providerCfg.DisplayName,
				Enabled:     true,
			})
		}
	}
	return providers
}

// GetCallbackURL - формирует callback URL для провайдера
func (m *Manager) GetCallbackURL(provider string) string {
	return fmt.Sprintf("%s/api/v1/auth/oauth/%s/callback", m.config.BackendBaseURL, provider)
}

// GenerateState - генерирует случайный state для CSRF защиты
func GenerateState() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.URLEncoding.EncodeToString(b), nil
}

// ==================== Google Provider ====================

type googleProvider struct {
	config     config.OAuthProviderConfig
	httpClient *http.Client
}

func newGoogleProvider(cfg config.OAuthProviderConfig, client *http.Client) *googleProvider {
	return &googleProvider{
		config:     cfg,
		httpClient: client,
	}
}

func (p *googleProvider) GetName() string {
	return "google"
}

func (p *googleProvider) GetAuthURL(state, redirectURL string) string {
	params := url.Values{}
	params.Set("client_id", p.config.ClientID)
	params.Set("redirect_uri", redirectURL)
	params.Set("response_type", "code")
	params.Set("scope", strings.Join(p.config.Scopes, " "))
	params.Set("state", state)
	params.Set("access_type", "offline")
	params.Set("prompt", "consent")

	return p.config.AuthURL + "?" + params.Encode()
}

func (p *googleProvider) ExchangeCode(ctx context.Context, code, redirectURL string) (*TokenResponse, error) {
	data := url.Values{}
	data.Set("code", code)
	data.Set("client_id", p.config.ClientID)
	data.Set("client_secret", p.config.ClientSecret)
	data.Set("redirect_uri", redirectURL)
	data.Set("grant_type", "authorization_code")

	req, err := http.NewRequestWithContext(ctx, "POST", p.config.TokenURL, strings.NewReader(data.Encode()))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := p.httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("token exchange failed: %s", string(body))
	}

	var tokenResp TokenResponse
	if err := json.NewDecoder(resp.Body).Decode(&tokenResp); err != nil {
		return nil, err
	}

	return &tokenResp, nil
}

func (p *googleProvider) GetUserInfo(ctx context.Context, accessToken string) (*entity.OAuthUserInfo, error) {
	req, err := http.NewRequestWithContext(ctx, "GET", p.config.UserInfoURL, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+accessToken)

	resp, err := p.httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("failed to get user info: %s", string(body))
	}

	var data struct {
		ID            string `json:"id"`
		Email         string `json:"email"`
		VerifiedEmail bool   `json:"verified_email"`
		Name          string `json:"name"`
		Picture       string `json:"picture"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&data); err != nil {
		return nil, err
	}

	if data.Email == "" {
		return nil, errors.New("email not provided by Google")
	}

	return &entity.OAuthUserInfo{
		ID:       data.ID,
		Email:    data.Email,
		Name:     data.Name,
		Avatar:   data.Picture,
		Provider: "google",
	}, nil
}

// ==================== GitHub Provider ====================

type githubProvider struct {
	config     config.OAuthProviderConfig
	httpClient *http.Client
}

func newGitHubProvider(cfg config.OAuthProviderConfig, client *http.Client) *githubProvider {
	return &githubProvider{
		config:     cfg,
		httpClient: client,
	}
}

func (p *githubProvider) GetName() string {
	return "github"
}

func (p *githubProvider) GetAuthURL(state, redirectURL string) string {
	params := url.Values{}
	params.Set("client_id", p.config.ClientID)
	params.Set("redirect_uri", redirectURL)
	params.Set("scope", strings.Join(p.config.Scopes, " "))
	params.Set("state", state)

	return p.config.AuthURL + "?" + params.Encode()
}

func (p *githubProvider) ExchangeCode(ctx context.Context, code, redirectURL string) (*TokenResponse, error) {
	data := url.Values{}
	data.Set("code", code)
	data.Set("client_id", p.config.ClientID)
	data.Set("client_secret", p.config.ClientSecret)
	data.Set("redirect_uri", redirectURL)

	req, err := http.NewRequestWithContext(ctx, "POST", p.config.TokenURL, strings.NewReader(data.Encode()))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")

	resp, err := p.httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("token exchange failed: %s", string(body))
	}

	var tokenResp TokenResponse
	if err := json.NewDecoder(resp.Body).Decode(&tokenResp); err != nil {
		return nil, err
	}

	return &tokenResp, nil
}

func (p *githubProvider) GetUserInfo(ctx context.Context, accessToken string) (*entity.OAuthUserInfo, error) {
	// Получаем информацию о пользователе
	req, err := http.NewRequestWithContext(ctx, "GET", p.config.UserInfoURL, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+accessToken)
	req.Header.Set("Accept", "application/json")

	resp, err := p.httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("failed to get user info: %s", string(body))
	}

	var data struct {
		ID        int64  `json:"id"`
		Login     string `json:"login"`
		Name      string `json:"name"`
		Email     string `json:"email"`
		AvatarURL string `json:"avatar_url"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&data); err != nil {
		return nil, err
	}

	// Если email не получен, делаем отдельный запрос
	email := data.Email
	if email == "" {
		email, _ = p.getPrimaryEmail(ctx, accessToken)
	}

	if email == "" {
		return nil, errors.New("email not provided by GitHub")
	}

	return &entity.OAuthUserInfo{
		ID:       fmt.Sprintf("%d", data.ID),
		Email:    email,
		Name:     data.Name,
		Avatar:   data.AvatarURL,
		Provider: "github",
	}, nil
}

func (p *githubProvider) getPrimaryEmail(ctx context.Context, accessToken string) (string, error) {
	req, err := http.NewRequestWithContext(ctx, "GET", "https://api.github.com/user/emails", nil)
	if err != nil {
		return "", err
	}
	req.Header.Set("Authorization", "Bearer "+accessToken)
	req.Header.Set("Accept", "application/json")

	resp, err := p.httpClient.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return "", nil
	}

	var emails []struct {
		Email    string `json:"email"`
		Primary  bool   `json:"primary"`
		Verified bool   `json:"verified"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&emails); err != nil {
		return "", err
	}

	for _, e := range emails {
		if e.Primary && e.Verified {
			return e.Email, nil
		}
	}

	for _, e := range emails {
		if e.Verified {
			return e.Email, nil
		}
	}

	return "", nil
}

// ==================== Yandex Provider ====================

type yandexProvider struct {
	config     config.OAuthProviderConfig
	httpClient *http.Client
}

func newYandexProvider(cfg config.OAuthProviderConfig, client *http.Client) *yandexProvider {
	return &yandexProvider{
		config:     cfg,
		httpClient: client,
	}
}

func (p *yandexProvider) GetName() string {
	return "yandex"
}

func (p *yandexProvider) GetAuthURL(state, redirectURL string) string {
	params := url.Values{}
	params.Set("client_id", p.config.ClientID)
	params.Set("redirect_uri", redirectURL)
	params.Set("response_type", "code")
	params.Set("state", state)

	return p.config.AuthURL + "?" + params.Encode()
}

func (p *yandexProvider) ExchangeCode(ctx context.Context, code, redirectURL string) (*TokenResponse, error) {
	data := url.Values{}
	data.Set("code", code)
	data.Set("client_id", p.config.ClientID)
	data.Set("client_secret", p.config.ClientSecret)
	data.Set("grant_type", "authorization_code")

	req, err := http.NewRequestWithContext(ctx, "POST", p.config.TokenURL, strings.NewReader(data.Encode()))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := p.httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("token exchange failed: %s", string(body))
	}

	var tokenResp TokenResponse
	if err := json.NewDecoder(resp.Body).Decode(&tokenResp); err != nil {
		return nil, err
	}

	return &tokenResp, nil
}

func (p *yandexProvider) GetUserInfo(ctx context.Context, accessToken string) (*entity.OAuthUserInfo, error) {
	req, err := http.NewRequestWithContext(ctx, "GET", p.config.UserInfoURL+"?format=json", nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "OAuth "+accessToken)

	resp, err := p.httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("failed to get user info: %s", string(body))
	}

	var data struct {
		ID           string `json:"id"`
		DefaultEmail string `json:"default_email"`
		RealName     string `json:"real_name"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&data); err != nil {
		return nil, err
	}

	if data.DefaultEmail == "" {
		return nil, errors.New("email not provided by Yandex")
	}

	return &entity.OAuthUserInfo{
		ID:       data.ID,
		Email:    data.DefaultEmail,
		Name:     data.RealName,
		Provider: "yandex",
	}, nil
}

// ==================== VK Provider ====================

type vkProvider struct {
	config     config.OAuthProviderConfig
	httpClient *http.Client
}

func newVKProvider(cfg config.OAuthProviderConfig, client *http.Client) *vkProvider {
	return &vkProvider{
		config:     cfg,
		httpClient: client,
	}
}

func (p *vkProvider) GetName() string {
	return "vk"
}

func (p *vkProvider) GetAuthURL(state, redirectURL string) string {
	params := url.Values{}
	params.Set("client_id", p.config.ClientID)
	params.Set("redirect_uri", redirectURL)
	params.Set("response_type", "code")
	params.Set("scope", strings.Join(p.config.Scopes, ","))
	params.Set("state", state)
	params.Set("v", "5.131")

	return p.config.AuthURL + "?" + params.Encode()
}

func (p *vkProvider) ExchangeCode(ctx context.Context, code, redirectURL string) (*TokenResponse, error) {
	params := url.Values{}
	params.Set("code", code)
	params.Set("client_id", p.config.ClientID)
	params.Set("client_secret", p.config.ClientSecret)
	params.Set("redirect_uri", redirectURL)

	req, err := http.NewRequestWithContext(ctx, "GET", p.config.TokenURL+"?"+params.Encode(), nil)
	if err != nil {
		return nil, err
	}

	resp, err := p.httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("token exchange failed: %s", string(body))
	}

	var tokenResp struct {
		AccessToken string `json:"access_token"`
		ExpiresIn   int    `json:"expires_in"`
		UserID      int64  `json:"user_id"`
		Email       string `json:"email"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&tokenResp); err != nil {
		return nil, err
	}

	return &TokenResponse{
		AccessToken: tokenResp.AccessToken,
		ExpiresIn:   tokenResp.ExpiresIn,
	}, nil
}

func (p *vkProvider) GetUserInfo(ctx context.Context, accessToken string) (*entity.OAuthUserInfo, error) {
	params := url.Values{}
	params.Set("access_token", accessToken)
	params.Set("fields", "photo_200,email")
	params.Set("v", "5.131")

	req, err := http.NewRequestWithContext(ctx, "GET", p.config.UserInfoURL+"?"+params.Encode(), nil)
	if err != nil {
		return nil, err
	}

	resp, err := p.httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("failed to get user info: %s", string(body))
	}

	var data struct {
		Response []struct {
			ID        int64  `json:"id"`
			FirstName string `json:"first_name"`
			LastName  string `json:"last_name"`
			Photo200  string `json:"photo_200"`
		} `json:"response"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&data); err != nil {
		return nil, err
	}

	if len(data.Response) == 0 {
		return nil, errors.New("no user data from VK")
	}

	user := data.Response[0]

	// VK не возвращает email в userinfo, нужно получать из токена
	return &entity.OAuthUserInfo{
		ID:       fmt.Sprintf("%d", user.ID),
		Email:    "", // Email получается при обмене токена
		Name:     user.FirstName + " " + user.LastName,
		Avatar:   user.Photo200,
		Provider: "vk",
	}, nil
}


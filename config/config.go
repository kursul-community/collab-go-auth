package config

import (
	"fmt"
	"log"
	"os"
	"strings"
	"time"

	"github.com/ilyakaznacheev/cleanenv"
)

type (
	// Config - структура конфига проекта
	Config struct {
		App           AppConfig           `yaml:"app"`        // Инфа о приложении
		GRPC          GRPCConfig          `yaml:"grpc"`       // Инфа по gRPC сервера
		HTTP          HTTPConfig          `yaml:"http"`       // Инфа по HTTP Gateway
		Log           LogConfig           `yaml:"logger"`     // Уровень логгирования
		Token         TokenConfig         `yaml:"token"`      // Инфа по токену
		Migrations    MigrationsConfig    `yaml:"migrations"` // Путь к миграциям
		Database      DatabaseConfig      `yaml:"database"`   // Настройки БД из yaml
		PG            PGConfig            // Данные по Postgres из env
		Redis         RedisConfig         `yaml:"redis"`         // Данные по Redis
		SMTP          SMTPConfig          `yaml:"smtp"`          // Настройки SMTP
		Verification  VerificationConfig  `yaml:"verification"`  // Настройки верификации email
		PasswordReset PasswordResetConfig `yaml:"passwordReset"` // Настройки восстановления пароля
		Security      SecurityConfig      `yaml:"security"`      // Настройки безопасности
		RateLimit     RateLimitConfig     `yaml:"rateLimit"`     // Настройки rate limiting
		CORS          CORSConfig          `yaml:"cors"`          // Настройки CORS
		Health        HealthConfig        `yaml:"health"`        // Настройки health check
		Metrics       MetricsConfig       `yaml:"metrics"`       // Настройки метрик
		OAuth         OAuthConfig         `yaml:"oauth"`         // Настройки OAuth2
	}

	// AppConfig - структура конфига приложения
	AppConfig struct {
		Name    string `yaml:"name"`
		Version string `yaml:"version"`
		Env     string `yaml:"env" env:"APP_ENV" env-default:"development"`
	}

	// GRPCConfig - структура конфига gRPC
	GRPCConfig struct {
		Host    string `yaml:"host" env:"GRPC_HOST" env-default:"0.0.0.0"`
		Port    int    `yaml:"port" env:"GRPC_PORT" env-default:"60051"`
		Timeout int    `yaml:"timeout"`
	}

	// HTTPConfig - структура конфига HTTP (REST Gateway)
	HTTPConfig struct {
		Host         string `yaml:"host" env:"HTTP_HOST" env-default:"0.0.0.0"`
		Port         int    `yaml:"port" env:"HTTP_PORT" env-default:"8080"`
		ReadTimeout  int    `yaml:"readTimeout"`
		WriteTimeout int    `yaml:"writeTimeout"`
		IdleTimeout  int    `yaml:"idleTimeout"`
	}

	// LogConfig - структура конфига логгирования
	LogConfig struct {
		Level    string `yaml:"level" env:"LOG_LEVEL" env-default:"debug"`
		Format   string `yaml:"format" env:"LOG_FORMAT" env-default:"json"`
		Output   string `yaml:"output"`
		FilePath string `yaml:"filePath"`
	}

	// TokenConfig - структура конфига токена
	TokenConfig struct {
		Secret     string        `env:"TOKEN_SECRET"`
		AccessTTL  time.Duration `yaml:"accessTTL"`
		RefreshTTL time.Duration `yaml:"refreshTTL"`
	}

	// MigrationsConfig - структура конфига миграций
	MigrationsConfig struct {
		Path string `yaml:"path" env:"MIGRATIONS_PATH" env-default:"./migrations"`
	}

	// DatabaseConfig - дополнительные настройки БД из yaml
	DatabaseConfig struct {
		MaxConns        int           `yaml:"maxConns"`
		MinConns        int           `yaml:"minConns"`
		ConnTimeout     time.Duration `yaml:"connTimeout"`
		MaxConnLifetime time.Duration `yaml:"maxConnLifetime"`
		MaxConnIdleTime time.Duration `yaml:"maxConnIdleTime"`
		SSLMode         string        `yaml:"sslMode"`
	}

	// PGConfig - структура конфига базы данных (из env)
	PGConfig struct {
		User        string        `env:"PG_USER"`
		Password    string        `env:"PG_PASSWORD"`
		Host        string        `env:"PG_HOST"`
		Port        int           `env:"PG_PORT"`
		DbName      string        `env:"PG_DBNAME"`
		MaxConns    int32         `env:"DB_MAX_CONNS"`
		ConnTimeout time.Duration `env:"DB_CONN_TIMEOUT"`
	}

	// RedisConfig - структура конфига Redis
	RedisConfig struct {
		Host         string        `yaml:"host" env:"REDIS_HOST" env-default:"localhost"`
		Port         int           `yaml:"port" env:"REDIS_PORT" env-default:"6379"`
		Password     string        `yaml:"password" env:"REDIS_PASSWORD" env-default:""`
		DB           int           `yaml:"db" env:"REDIS_DB" env-default:"0"`
		PoolSize     int           `yaml:"poolSize"`
		MinIdleConns int           `yaml:"minIdleConns"`
		DialTimeout  time.Duration `yaml:"dialTimeout"`
		ReadTimeout  time.Duration `yaml:"readTimeout"`
		WriteTimeout time.Duration `yaml:"writeTimeout"`
	}

	// SMTPConfig - структура конфига SMTP
	SMTPConfig struct {
		Host      string        `yaml:"host" env:"SMTP_HOST" env-default:"smtp.gmail.com"`
		Port      int           `yaml:"port" env:"SMTP_PORT" env-default:"587"`
		Username  string        `yaml:"username" env:"SMTP_USERNAME"`
		Password  string        `yaml:"password" env:"SMTP_PASSWORD"`
		From      string        `yaml:"from" env:"SMTP_FROM"`
		FromName  string        `yaml:"fromName" env:"SMTP_FROM_NAME"`
		UseTLS    bool          `yaml:"useTLS"`
		UseSSL    bool          `yaml:"useSSL"`
		Timeout   time.Duration `yaml:"timeout"`
		Templates SMTPTemplates `yaml:"templates"`
	}

	// SMTPTemplates - шаблоны email писем
	SMTPTemplates struct {
		VerificationSubject  string `yaml:"verificationSubject"`
		ResetPasswordSubject string `yaml:"resetPasswordSubject"`
		WelcomeSubject       string `yaml:"welcomeSubject"`
	}

	// VerificationConfig - структура конфига верификации
	VerificationConfig struct {
		CodeLength     int           `yaml:"codeLength"`
		CodeTTL        time.Duration `yaml:"codeTTL"`
		MaxAttempts    int           `yaml:"maxAttempts"`
		ResendCooldown time.Duration `yaml:"resendCooldown"`
		LinkBaseURL    string        `yaml:"linkBaseURL" env:"VERIFICATION_BASE_URL"`
	}

	// PasswordResetConfig - структура конфига восстановления пароля
	PasswordResetConfig struct {
		TokenTTL    time.Duration `yaml:"tokenTTL"`
		FrontendURL string        `yaml:"frontendURL" env:"PASSWORD_RESET_FRONTEND_URL"`
	}

	// SecurityConfig - структура конфига безопасности
	SecurityConfig struct {
		BcryptCost               int           `yaml:"bcryptCost"`
		MaxLoginAttempts         int           `yaml:"maxLoginAttempts"`
		LockoutDuration          time.Duration `yaml:"lockoutDuration"`
		PasswordMinLength        int           `yaml:"passwordMinLength"`
		PasswordRequireUppercase bool          `yaml:"passwordRequireUppercase"`
		PasswordRequireLowercase bool          `yaml:"passwordRequireLowercase"`
		PasswordRequireDigit     bool          `yaml:"passwordRequireDigit"`
		PasswordRequireSpecial   bool          `yaml:"passwordRequireSpecial"`
		SessionMaxAge            time.Duration `yaml:"sessionMaxAge"`
		TrustedProxies           []string      `yaml:"trustedProxies"`
	}

	// RateLimitConfig - структура конфига rate limiting
	RateLimitConfig struct {
		Enabled   bool               `yaml:"enabled"`
		Global    RateLimitGlobal    `yaml:"global"`
		Endpoints RateLimitEndpoints `yaml:"endpoints"`
	}

	// RateLimitGlobal - глобальные лимиты
	RateLimitGlobal struct {
		RequestsPerSecond int `yaml:"requestsPerSecond"`
		Burst             int `yaml:"burst"`
	}

	// RateLimitEndpoints - лимиты по эндпоинтам
	RateLimitEndpoints struct {
		Login       RateLimitEndpoint `yaml:"login"`
		Register    RateLimitEndpoint `yaml:"register"`
		ResendEmail RateLimitEndpoint `yaml:"resendEmail"`
		VerifyEmail RateLimitEndpoint `yaml:"verifyEmail"`
	}

	// RateLimitEndpoint - лимит для конкретного эндпоинта
	RateLimitEndpoint struct {
		RequestsPerMinute int `yaml:"requestsPerMinute"`
		Burst             int `yaml:"burst"`
	}

	// CORSConfig - структура конфига CORS
	CORSConfig struct {
		Enabled          bool     `yaml:"enabled"`
		AllowedOrigins   []string `yaml:"allowedOrigins"`
		AllowedMethods   []string `yaml:"allowedMethods"`
		AllowedHeaders   []string `yaml:"allowedHeaders"`
		ExposedHeaders   []string `yaml:"exposedHeaders"`
		AllowCredentials bool     `yaml:"allowCredentials"`
		MaxAge           int      `yaml:"maxAge"`
	}

	// HealthConfig - структура конфига health check
	HealthConfig struct {
		Enabled       bool   `yaml:"enabled"`
		Path          string `yaml:"path"`
		LivenessPath  string `yaml:"livenessPath"`
		ReadinessPath string `yaml:"readinessPath"`
	}

	// MetricsConfig - структура конфига метрик
	MetricsConfig struct {
		Enabled bool   `yaml:"enabled"`
		Path    string `yaml:"path"`
		Port    int    `yaml:"port"`
	}

	// OAuthConfig - структура конфига OAuth2
	OAuthConfig struct {
		FrontendCallbackURL string                         `yaml:"frontendCallbackURL" env:"OAUTH_FRONTEND_CALLBACK_URL"`
		BackendBaseURL      string                         `yaml:"backendBaseURL" env:"OAUTH_BACKEND_BASE_URL"`
		StateTTL            time.Duration                  `yaml:"stateTTL"`
		Cookies             OAuthCookiesConfig             `yaml:"cookies"`
		Providers           map[string]OAuthProviderConfig `yaml:"providers"`
	}

	// OAuthCookiesConfig - конфигурация cookies для OAuth токенов
	OAuthCookiesConfig struct {
		Domain   string `yaml:"domain" env:"OAUTH_COOKIE_DOMAIN"`
		Secure   bool   `yaml:"secure" env:"OAUTH_COOKIE_SECURE"`
		SameSite string `yaml:"sameSite"` // strict, lax, none
	}

	// OAuthProviderConfig - конфигурация отдельного OAuth провайдера
	OAuthProviderConfig struct {
		Enabled      bool     `yaml:"enabled"`
		DisplayName  string   `yaml:"displayName"`
		ClientID     string   `yaml:"clientId" env:"OAUTH_{PROVIDER}_CLIENT_ID"`
		ClientSecret string   `yaml:"clientSecret" env:"OAUTH_{PROVIDER}_CLIENT_SECRET"`
		AuthURL      string   `yaml:"authURL"`
		TokenURL     string   `yaml:"tokenURL"`
		UserInfoURL  string   `yaml:"userInfoURL"`
		Scopes       []string `yaml:"scopes"`
	}
)

// URL формирует строку подключения к PostgreSQL
func (p PGConfig) URL() string {
	return fmt.Sprintf("postgresql://%s:%s@%s:%d/%s?sslmode=disable",
		p.User,
		p.Password,
		p.Host,
		p.Port,
		p.DbName,
	)
}

// MigrationsURL формирует строку подключения к PostgreSQL для миграции
func (p PGConfig) MigrationsURL() string {
	return fmt.Sprintf("pgx5://%s:%s@%s:%d/%s?sslmode=disable",
		p.User,
		p.Password,
		p.Host,
		p.Port,
		p.DbName,
	)
}

// Addr возвращает адрес Redis в формате host:port
func (r RedisConfig) Addr() string {
	return fmt.Sprintf("%s:%d", r.Host, r.Port)
}

// Addr возвращает адрес SMTP сервера в формате host:port
func (s SMTPConfig) Addr() string {
	return fmt.Sprintf("%s:%d", s.Host, s.Port)
}

// IsDevelopment проверяет, является ли окружение development
func (a AppConfig) IsDevelopment() bool {
	return a.Env == "development"
}

// IsProduction проверяет, является ли окружение production
func (a AppConfig) IsProduction() bool {
	return a.Env == "production"
}

// NewConfig - конструктор для создания Config
func NewConfig() (*Config, error) {
	// Создаем конфигурацию
	cfg := &Config{}

	// Загружаем конфигурацию с использованием cleanenv
	if err := cleanenv.ReadConfig("./config/config.yaml", cfg); err != nil {
		log.Println("Error loading config file:", err)
		return nil, err
	}

	if err := cleanenv.ReadEnv(cfg); err != nil {
		log.Println("Error loading environment variables:", err)
		return nil, err
	}

	// Загружаем OAuth credentials из переменных окружения
	cfg.loadOAuthCredentials()

	return cfg, nil
}

// loadOAuthCredentials - загрузка OAuth credentials из переменных окружения
func (c *Config) loadOAuthCredentials() {
	if c.OAuth.Providers == nil {
		return
	}

	for name, provider := range c.OAuth.Providers {
		upperName := strings.ToUpper(name)

		// Загружаем ClientID
		if clientID := os.Getenv("OAUTH_" + upperName + "_CLIENT_ID"); clientID != "" {
			provider.ClientID = clientID
		}

		// Загружаем ClientSecret
		if clientSecret := os.Getenv("OAUTH_" + upperName + "_CLIENT_SECRET"); clientSecret != "" {
			provider.ClientSecret = clientSecret
		}

		// Обновляем провайдера в map
		c.OAuth.Providers[name] = provider
	}
}

// GetEnabledOAuthProviders - возвращает список включенных OAuth провайдеров
func (c *Config) GetEnabledOAuthProviders() []string {
	var enabled []string
	for name, provider := range c.OAuth.Providers {
		if provider.Enabled && provider.ClientID != "" && provider.ClientSecret != "" {
			enabled = append(enabled, name)
		}
	}
	return enabled
}

// GetOAuthProvider - возвращает конфигурацию провайдера по имени
func (c *Config) GetOAuthProvider(name string) (OAuthProviderConfig, bool) {
	provider, ok := c.OAuth.Providers[strings.ToLower(name)]
	return provider, ok
}

// IsOAuthProviderEnabled - проверяет, включен ли провайдер
func (c *Config) IsOAuthProviderEnabled(name string) bool {
	provider, ok := c.OAuth.Providers[strings.ToLower(name)]
	if !ok {
		return false
	}
	return provider.Enabled && provider.ClientID != "" && provider.ClientSecret != ""
}

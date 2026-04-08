package token

import (
	"errors"
	"fmt"
	"github.com/golang-jwt/jwt/v5"
	"go-auth/internal/entity"
	"time"
)

var _ JWTToken = (*jwtToken)(nil)

// Ошибки токенов
var (
	ErrMissingSecret       = errors.New("missing JWT_SECRET in config")
	ErrInvalidToken        = errors.New("invalid JWT token")
	ErrAccessTokenExpired  = errors.New("access token expired")
	ErrRefreshTokenExpired = errors.New("refresh token expired")
)

// customClaims — JWT claims с ролью пользователя
type customClaims struct {
	jwt.RegisteredClaims
	Role string `json:"role,omitempty"`
}

// TokenClaims содержит извлеченные из JWT данные
type TokenClaims struct {
	UserID   string
	Role     string
	IssuedAt time.Time
}

// JWTToken - интерфейс для работы с токенами
type JWTToken interface {
	// GenerateAccessToken - генерация access токена
	GenerateAccessToken(user *entity.User) (string, error)
	// GenerateRefreshToken - генерация refresh токена
	GenerateRefreshToken(user *entity.User) (string, error)
	// ValidateToken - валидация токена
	ValidateToken(token string) (bool, error)
	// RefreshAccessToken - обновление access токена
	RefreshAccessToken(refreshToken string) (string, error)
	// GetUserIDFromToken - извлечение userID из токена
	GetUserIDFromToken(token string) (string, error)
	// GetClaimsFromToken - извлечение claims (userID + role + issuedAt) из токена
	GetClaimsFromToken(token string) (*TokenClaims, error)
}

// service - реализация интерфейса Service
type jwtToken struct {
	secret     string
	accessTTL  time.Duration
	refreshTTL time.Duration
}

// New - конструктор создает новый экземпляр Service
func New(secret string, accessTTL, refreshTTL time.Duration) (JWTToken, error) {
	if secret == "" {
		return nil, ErrMissingSecret
	}
	return &jwtToken{
		secret:     secret,
		accessTTL:  accessTTL,
		refreshTTL: refreshTTL,
	}, nil
}

// GenerateAccessToken - генерация access токена
func (s *jwtToken) GenerateAccessToken(user *entity.User) (string, error) {
	return s.generateToken(user.ID, user.Role, s.accessTTL)
}

// GenerateRefreshToken - генерация refresh токена
func (s *jwtToken) GenerateRefreshToken(user *entity.User) (string, error) {
	return s.generateToken(user.ID, user.Role, s.refreshTTL)
}

// ValidateToken - валидация токена
func (s *jwtToken) ValidateToken(token string) (bool, error) {
	claims, err := s.parseToken(token)
	if err != nil {
		return false, err
	}

	// Проверяем срок действия токена
	if claims.ExpiresAt.Before(time.Now()) {
		return false, ErrAccessTokenExpired
	}

	return true, nil
}

// RefreshAccessToken - обновление access токена
func (s *jwtToken) RefreshAccessToken(refreshToken string) (string, error) {
	claims, err := s.parseToken(refreshToken)
	if err != nil {
		return "", fmt.Errorf("failed to parse refresh token: %w", err)
	}

	// Проверяем срок действия refresh токена
	if claims.ExpiresAt.Before(time.Now()) {
		return "", ErrRefreshTokenExpired
	}

	// Генерируем новый access токен с той же ролью
	role := claims.Role
	if role == "" {
		role = "user"
	}
	return s.generateToken(claims.Subject, role, s.accessTTL)
}

// generateToken - вспомогательный метод для генерации токена
func (s *jwtToken) generateToken(userID string, role string, ttl time.Duration) (string, error) {
	if role == "" {
		role = "user"
	}
	now := time.Now()
	claims := &customClaims{
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer:    userID,
			Subject:   userID,
			IssuedAt:  jwt.NewNumericDate(now),
			ExpiresAt: jwt.NewNumericDate(now.Add(ttl)),
		},
		Role: role,
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return token.SignedString([]byte(s.secret))
}

// GetUserIDFromToken - извлечение userID из токена
func (s *jwtToken) GetUserIDFromToken(token string) (string, error) {
	claims, err := s.parseToken(token)
	if err != nil {
		return "", err
	}
	return claims.Subject, nil
}

// GetClaimsFromToken - извлечение claims (userID + role + issuedAt) из токена
func (s *jwtToken) GetClaimsFromToken(tokenStr string) (*TokenClaims, error) {
	claims, err := s.parseToken(tokenStr)
	if err != nil {
		return nil, err
	}

	role := claims.Role
	if role == "" {
		role = "user" // обратная совместимость со старыми токенами
	}

	tc := &TokenClaims{
		UserID: claims.Subject,
		Role:   role,
	}
	if claims.IssuedAt != nil {
		tc.IssuedAt = claims.IssuedAt.Time
	}
	return tc, nil
}

// parseToken - парсинг токена и валидация
func (s *jwtToken) parseToken(tokenString string) (*customClaims, error) {
	token, err := jwt.ParseWithClaims(tokenString, &customClaims{}, func(t *jwt.Token) (interface{}, error) {
		return []byte(s.secret), nil
	})
	if err != nil {
		return nil, err
	}
	claims, ok := token.Claims.(*customClaims)
	if !ok || !token.Valid {
		return nil, ErrInvalidToken
	}
	if claims.Subject == "" {
		return nil, ErrInvalidToken
	}
	return claims, nil
}

package entity

import "time"

// User - сущность пользователя
type User struct {
	ID              string    `json:"id"`                // Уникальный идентификатор пользователя (например, UUID)
	Email           string    `json:"email"`             // Уникальный email
	Password        string    `json:"password"`          // Пароль пользователя (может быть пустым для OAuth)
	CreatedAt       time.Time `json:"created_at"`        // Дата и время создания пользователя
	IsActive        bool      `json:"is_active"`         // Флаг активности пользователя
	EmailVerified   bool      `json:"email_verified"`    // Флаг подтверждения email
	OAuthProvider   *string   `json:"oauth_provider"`    // OAuth провайдер (google, github, yandex, vk) или nil
	OAuthProviderID *string   `json:"oauth_provider_id"` // ID пользователя у OAuth провайдера
}

// IsOAuthUser - проверяет, является ли пользователь OAuth пользователем
func (u *User) IsOAuthUser() bool {
	return u.OAuthProvider != nil && *u.OAuthProvider != ""
}

// OAuthUserInfo - информация о пользователе от OAuth провайдера
type OAuthUserInfo struct {
	ID       string // ID пользователя у провайдера
	Email    string // Email пользователя
	Name     string // Имя пользователя (опционально)
	Avatar   string // URL аватара (опционально)
	Provider string // Имя провайдера
}

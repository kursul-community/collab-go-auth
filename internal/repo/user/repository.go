package user

import (
	"context"

	"github.com/jackc/pgx/v5/pgxpool"

	"go-auth/internal/entity"
)

// Убедимся, что repository реализует интерфейс Repository
var _ Repository = (*repository)(nil)

type Repository interface {
	// CreateUser - создание нового пользователя
	CreateUser(ctx context.Context, user *entity.User) (string, error)
	// GetUserByEmail - получение пользователя по email
	GetUserByEmail(ctx context.Context, email string) (*entity.User, error)
	// GetUserById - получение пользователя по id
	GetUserById(ctx context.Context, id string) (*entity.User, error)
	// SetEmailVerified - установка флага email_verified
	SetEmailVerified(ctx context.Context, userID string, verified bool) error
	// UpdatePassword - обновление пароля пользователя
	UpdatePassword(ctx context.Context, userID string, hashedPassword string) error
	// GetUserByOAuthProvider - получение пользователя по OAuth провайдеру
	GetUserByOAuthProvider(ctx context.Context, provider, providerID string) (*entity.User, error)
	// CreateOAuthUser - создание OAuth пользователя
	CreateOAuthUser(ctx context.Context, user *entity.User) (string, error)
	// LinkOAuthProvider - привязка OAuth провайдера к существующему пользователю
	LinkOAuthProvider(ctx context.Context, userID, provider, providerID string) error
}

// repository - репозиторий для работы с PostgreSQL
type repository struct {
	db *pgxpool.Pool
}

// NewRepository - конструктор создания репозитория для работы с PostgreSQL
func NewRepository(db *pgxpool.Pool) Repository {
	return &repository{db: db}
}

func (r *repository) CreateUser(ctx context.Context, user *entity.User) (string, error) {
	query := `INSERT INTO users (id, email, password, email_verified) VALUES ($1, $2, $3, $4)`
	_, err := r.db.Exec(ctx, query, user.ID, user.Email, user.Password, user.EmailVerified)
	if err != nil {
		return "", err
	}

	return user.ID, nil
}

func (r *repository) GetUserByEmail(ctx context.Context, email string) (*entity.User, error) {
	query := `SELECT id, email, password, is_active, email_verified FROM users WHERE email = $1`
	row := r.db.QueryRow(ctx, query, email)

	var user entity.User

	if err := row.Scan(&user.ID, &user.Email, &user.Password, &user.IsActive, &user.EmailVerified); err != nil {
		return nil, err
	}
	return &user, nil
}

func (r *repository) GetUserById(ctx context.Context, id string) (*entity.User, error) {
	query := `SELECT id, email, password, is_active, email_verified FROM users WHERE id = $1`
	row := r.db.QueryRow(ctx, query, id)

	var user entity.User

	if err := row.Scan(&user.ID, &user.Email, &user.Password, &user.IsActive, &user.EmailVerified); err != nil {
		return nil, err
	}
	return &user, nil
}

// SetEmailVerified - установка флага email_verified для пользователя
func (r *repository) SetEmailVerified(ctx context.Context, userID string, verified bool) error {
	query := `UPDATE users SET email_verified = $1 WHERE id = $2`
	_, err := r.db.Exec(ctx, query, verified, userID)
	return err
}

// UpdatePassword - обновление пароля пользователя
func (r *repository) UpdatePassword(ctx context.Context, userID string, hashedPassword string) error {
	query := `UPDATE users SET password = $1 WHERE id = $2`
	_, err := r.db.Exec(ctx, query, hashedPassword, userID)
	return err
}

// GetUserByOAuthProvider - получение пользователя по OAuth провайдеру и ID у провайдера
func (r *repository) GetUserByOAuthProvider(ctx context.Context, provider, providerID string) (*entity.User, error) {
	query := `SELECT id, email, password, is_active, email_verified, oauth_provider, oauth_provider_id 
		FROM users WHERE oauth_provider = $1 AND oauth_provider_id = $2`
	row := r.db.QueryRow(ctx, query, provider, providerID)

	var user entity.User
	var password *string

	if err := row.Scan(&user.ID, &user.Email, &password, &user.IsActive, &user.EmailVerified,
		&user.OAuthProvider, &user.OAuthProviderID); err != nil {
		return nil, err
	}

	if password != nil {
		user.Password = *password
	}

	return &user, nil
}

// CreateOAuthUser - создание пользователя через OAuth
func (r *repository) CreateOAuthUser(ctx context.Context, user *entity.User) (string, error) {
	query := `INSERT INTO users (id, email, email_verified, oauth_provider, oauth_provider_id) 
		VALUES ($1, $2, $3, $4, $5)`
	_, err := r.db.Exec(ctx, query, user.ID, user.Email, user.EmailVerified,
		user.OAuthProvider, user.OAuthProviderID)
	if err != nil {
		return "", err
	}

	return user.ID, nil
}

// LinkOAuthProvider - привязка OAuth провайдера к существующему пользователю
func (r *repository) LinkOAuthProvider(ctx context.Context, userID, provider, providerID string) error {
	query := `UPDATE users SET oauth_provider = $1, oauth_provider_id = $2 WHERE id = $3`
	_, err := r.db.Exec(ctx, query, provider, providerID, userID)
	return err
}

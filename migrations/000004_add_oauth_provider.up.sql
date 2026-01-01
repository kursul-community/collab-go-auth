-- Добавляем поле oauth_provider для хранения провайдера OAuth
-- NULL означает обычную регистрацию по email/password
ALTER TABLE users ADD COLUMN IF NOT EXISTS oauth_provider VARCHAR(50) DEFAULT NULL;

-- Добавляем поле oauth_provider_id для хранения ID пользователя у провайдера
ALTER TABLE users ADD COLUMN IF NOT EXISTS oauth_provider_id VARCHAR(255) DEFAULT NULL;

-- Делаем пароль необязательным (для OAuth пользователей)
ALTER TABLE users ALTER COLUMN password DROP NOT NULL;

-- Создаем уникальный индекс для комбинации provider + provider_id
CREATE UNIQUE INDEX IF NOT EXISTS idx_users_oauth_provider_id 
ON users(oauth_provider, oauth_provider_id) 
WHERE oauth_provider IS NOT NULL;

-- Комментарии
COMMENT ON COLUMN users.oauth_provider IS 'OAuth provider name (google, github, yandex, vk) or NULL for email/password';
COMMENT ON COLUMN users.oauth_provider_id IS 'User ID from OAuth provider';




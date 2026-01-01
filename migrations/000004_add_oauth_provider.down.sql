-- Удаляем индекс
DROP INDEX IF EXISTS idx_users_oauth_provider_id;

-- Удаляем поля OAuth
ALTER TABLE users DROP COLUMN IF EXISTS oauth_provider;
ALTER TABLE users DROP COLUMN IF EXISTS oauth_provider_id;

-- Восстанавливаем NOT NULL для пароля (ВНИМАНИЕ: может привести к ошибке если есть OAuth пользователи!)
-- ALTER TABLE users ALTER COLUMN password SET NOT NULL;




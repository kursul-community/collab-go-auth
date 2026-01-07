-- Создаем базу данных
CREATE DATABASE db_auth;

-- Назначаем права текущему пользователю (POSTGRES_USER из docker-compose)
-- В init скриптах переменные окружения недоступны, но пользователь уже создан
-- Используем текущего пользователя сессии
GRANT ALL PRIVILEGES ON DATABASE db_auth TO CURRENT_USER;

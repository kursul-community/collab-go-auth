-- Удаляем поле email_verified
ALTER TABLE users DROP COLUMN IF EXISTS email_verified;


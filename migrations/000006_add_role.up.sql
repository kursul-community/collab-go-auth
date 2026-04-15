-- Add role column to users table
ALTER TABLE users ADD COLUMN role VARCHAR(20) NOT NULL DEFAULT 'user'
  CHECK (role IN ('user', 'admin'));

-- Set admin role for the seeded admin user
UPDATE users SET role = 'admin' WHERE email = 'collabify@adm.ru';

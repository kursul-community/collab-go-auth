-- Restore seeded admin user for admin panel login.
INSERT INTO users (
    id,
    email,
    password,
    is_active,
    email_verified,
    role,
    subscription_tier
)
VALUES (
    'a0000000-0000-0000-0000-000000000001',
    'collabify@adm.ru',
    '$2a$10$Vxa/DoBRvWnYgeDB3IZ1l.1J6kWQRp36EqD2j8ROyYnbk5Xc/QrGG',
    true,
    true,
    'admin',
    'member'
)
ON CONFLICT (email) DO UPDATE SET
    password = EXCLUDED.password,
    is_active = true,
    email_verified = true,
    role = 'admin',
    subscription_tier = 'member';

-- Seed admin user for admin panel: collabify@adm.ru / kursulDigitals!!
INSERT INTO users (id, email, password, is_active, email_verified)
VALUES (
    'a0000000-0000-0000-0000-000000000001',
    'collabify@adm.ru',
    '$2a$10$Vxa/DoBRvWnYgeDB3IZ1l.1J6kWQRp36EqD2j8ROyYnbk5Xc/QrGG',
    true,
    true
)
ON CONFLICT (email) DO NOTHING;

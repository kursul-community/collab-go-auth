ALTER TABLE users
    ADD COLUMN subscription_tier VARCHAR(32) NOT NULL DEFAULT 'member';

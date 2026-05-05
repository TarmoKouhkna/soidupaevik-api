-- Migration: lisa admin-tugi
ALTER TABLE users ADD COLUMN is_admin INTEGER NOT NULL DEFAULT 0;
ALTER TABLE users ADD COLUMN last_login_at TEXT;

-- Märgi tarmokouhkna@icloud.com administraatoriks
-- (kui kasutaja pole veel registreerunud, käivita see hiljem)
UPDATE users SET is_admin = 1 WHERE email = 'tarmokouhkna@icloud.com';

-- Migration: parooli taastamine e-postiga
--
-- password_changed_at (unix-sekundid): JWT-d, mis on välja antud enne seda
-- hetke, lükatakse tagasi — parooli vahetus või taastamine logib teised
-- seadmed välja. NULL = parooli pole pärast seda migratsiooni muudetud.
ALTER TABLE users ADD COLUMN password_changed_at INTEGER;

-- Ühekordsed taastamislingid. Andmebaasis on ainult tokeni SHA-256 räsi,
-- nii et andmebaasi leke ei anna kasutatavaid linke.
CREATE TABLE IF NOT EXISTS password_resets (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  user_id INTEGER NOT NULL,
  token_hash TEXT NOT NULL UNIQUE,
  created_at INTEGER NOT NULL,
  expires_at INTEGER NOT NULL,
  used_at INTEGER,
  FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_password_resets_user ON password_resets(user_id, created_at);

-- Lernportal: Nutzer (Name + PIN) und Fortschritt in Cloudflare D1.
CREATE TABLE IF NOT EXISTS users (
  name_key     TEXT PRIMARY KEY,
  name         TEXT NOT NULL,
  hue          INTEGER NOT NULL,
  pin_hash     TEXT NOT NULL,
  pin_salt     TEXT NOT NULL,
  prog         TEXT NOT NULL DEFAULT '{}',
  fails        INTEGER NOT NULL DEFAULT 0,
  locked_until INTEGER NOT NULL DEFAULT 0,
  created_at   INTEGER NOT NULL
);

-- Anmeldungen pro Gerät: nur der Hash des Tokens wird gespeichert.
CREATE TABLE IF NOT EXISTS tokens (
  token_hash TEXT PRIMARY KEY,
  name_key   TEXT NOT NULL,
  created_at INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS tokens_user ON tokens (name_key);

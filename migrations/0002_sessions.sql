-- Dashboard login sessions (Google sign-in). The cookie carries 32 random
-- bytes; only their SHA-256 is stored here, so a read of this table cannot be
-- replayed as a login. Sign-out is a row delete, effective next request.
CREATE TABLE sessions (
  token_hash TEXT PRIMARY KEY,
  email TEXT NOT NULL,
  created_at INTEGER NOT NULL,
  expires_at INTEGER NOT NULL
);

CREATE INDEX idx_sessions_expires ON sessions (expires_at);
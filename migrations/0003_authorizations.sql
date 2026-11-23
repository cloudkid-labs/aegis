CREATE TABLE IF NOT EXISTS scan_authorizations (
  scan_id TEXT PRIMARY KEY,
  email TEXT NOT NULL,
  targets TEXT NOT NULL,       -- JSON array of absolute http(s) URLs
  tools TEXT NOT NULL,         -- JSON array of tool names
  active INTEGER NOT NULL,     -- 1 iff zap-full selected
  confirmed_at TEXT NOT NULL
);
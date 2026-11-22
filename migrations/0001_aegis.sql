-- Phase 1 schema. Applied by `wrangler d1 migrations apply AEGIS_DB --remote`
-- before deploy, and by the workers vitest project against a local D1.

CREATE TABLE IF NOT EXISTS scans (
  id TEXT PRIMARY KEY,
  target TEXT NOT NULL,
  phase TEXT NOT NULL,              -- 'explore' | 'invasion'
  status TEXT NOT NULL,             -- queued|running|completed|failed|cancelled
  parent_scan_id TEXT,              -- chained invasion -> explore
  executor TEXT NOT NULL DEFAULT 'github',
  external_url TEXT,
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL,
  completed_at TEXT,
  error TEXT,
  options TEXT                      -- JSON: {depth, severity, ...}
);
CREATE INDEX IF NOT EXISTS idx_scans_status_created ON scans(status, created_at);

CREATE TABLE IF NOT EXISTS assets (
  id TEXT PRIMARY KEY,
  scan_id TEXT NOT NULL,
  type TEXT NOT NULL,               -- subdomain|url|endpoint|technology|...
  value TEXT NOT NULL,
  metadata TEXT,                    -- JSON: {status_code, title, tech, ...}
  created_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_assets_scan ON assets(scan_id);

CREATE TABLE IF NOT EXISTS findings (
  id TEXT PRIMARY KEY,
  scan_id TEXT NOT NULL,
  tool TEXT NOT NULL,
  severity TEXT NOT NULL,
  confidence TEXT NOT NULL DEFAULT 'medium',
  title TEXT NOT NULL,
  description TEXT NOT NULL DEFAULT '',
  url TEXT NOT NULL,
  parameter TEXT,
  evidence TEXT,
  cwe INTEGER,
  remediation TEXT,
  raw_ref TEXT,
  created_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_findings_scan ON findings(scan_id);

CREATE TABLE IF NOT EXISTS scan_events (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  scan_id TEXT NOT NULL,
  event TEXT NOT NULL,
  detail TEXT,
  created_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_scan_events_scan ON scan_events(scan_id);
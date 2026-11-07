
CREATE TABLE IF NOT EXISTS services (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  slug TEXT NOT NULL UNIQUE,
  name TEXT NOT NULL,
  origin TEXT NOT NULL,
  allowed_paths TEXT NOT NULL DEFAULT '["/"]',
  enabled INTEGER NOT NULL DEFAULT 1,
  created_at TEXT DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS service_members (
  service_id INTEGER NOT NULL,
  email TEXT NOT NULL,
  PRIMARY KEY (service_id, email),
  FOREIGN KEY (service_id)
    REFERENCES services(id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS access_events (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  email TEXT NOT NULL,
  service_slug TEXT NOT NULL,
  method TEXT NOT NULL,
  status INTEGER NOT NULL,
  created_at TEXT DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_access_events
ON access_events(created_at);

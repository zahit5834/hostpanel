-- Per-site uptime/health checks (Faz 5). One row per site; the scheduler
-- only checks running sites.
CREATE TABLE health_checks (
    site_id       INTEGER PRIMARY KEY REFERENCES sites(id) ON DELETE CASCADE,
    enabled       INTEGER NOT NULL DEFAULT 1,
    path          TEXT NOT NULL DEFAULT '/',
    expect_status INTEGER NOT NULL DEFAULT 0,      -- 0 = any status < 500
    interval_sec  INTEGER NOT NULL DEFAULT 300,
    state         TEXT NOT NULL DEFAULT 'unknown', -- unknown | up | down
    fails         INTEGER NOT NULL DEFAULT 0,      -- consecutive failures
    last_checked  INTEGER NOT NULL DEFAULT 0,
    last_ms       INTEGER NOT NULL DEFAULT 0,
    last_code     INTEGER NOT NULL DEFAULT 0,
    last_error    TEXT NOT NULL DEFAULT '',
    changed_at    INTEGER NOT NULL DEFAULT 0,
    restarts      INTEGER NOT NULL DEFAULT -1,     -- last seen systemd NRestarts (-1 = unknown)
    restart_log   TEXT NOT NULL DEFAULT '[]'       -- JSON unix times of recent restarts (crash-loop detection)
);

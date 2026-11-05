-- Backup plans: schedule is a standard 5-field cron expression (server local time).
CREATE TABLE backup_plans (
    id               INTEGER PRIMARY KEY,
    name             TEXT NOT NULL,
    scope            TEXT NOT NULL,                  -- all | sites
    site_ids         TEXT NOT NULL DEFAULT '[]',     -- JSON array (scope = sites)
    components       TEXT NOT NULL,                  -- JSON array: files, db, config, ssl
    schedule         TEXT NOT NULL,
    destination      TEXT NOT NULL,                  -- local | remote | both
    keep_local       INTEGER NOT NULL DEFAULT 7,     -- last N per site (0 = keep none locally after upload)
    keep_remote      INTEGER NOT NULL DEFAULT 0,     -- last M per site on the remote (0 = no count limit)
    keep_remote_days INTEGER NOT NULL DEFAULT 0,     -- remote copies older than X days are deleted (0 = no age limit)
    enabled          INTEGER NOT NULL DEFAULT 1,
    last_run_at      INTEGER NOT NULL DEFAULT 0,
    next_run_at      INTEGER NOT NULL DEFAULT 0,
    created_at       INTEGER NOT NULL,
    updated_at       INTEGER NOT NULL
);

-- One backup of one site. Files live in /var/backups/hostpanel/<domain>/<name>/
-- (root only) and/or on the remote. domain is kept so a deleted site's backup
-- can still be restored elsewhere.
CREATE TABLE backups (
    id          INTEGER PRIMARY KEY,
    plan_id     INTEGER REFERENCES backup_plans(id) ON DELETE SET NULL,
    site_id     INTEGER REFERENCES sites(id) ON DELETE SET NULL,
    domain      TEXT NOT NULL,
    name        TEXT NOT NULL,
    kind        TEXT NOT NULL,                       -- manual | scheduled | pre-restore | imported
    components  TEXT NOT NULL DEFAULT '[]',
    status      TEXT NOT NULL,                       -- running | success | failed
    size_bytes  INTEGER NOT NULL DEFAULT 0,
    local       INTEGER NOT NULL DEFAULT 0,
    remote      INTEGER NOT NULL DEFAULT 0,
    remote_server TEXT NOT NULL DEFAULT '',          -- folder under the remote: hp:<remote_server>/<domain>/<name>/
    job_id      INTEGER,
    error       TEXT NOT NULL DEFAULT '',
    created_at  INTEGER NOT NULL,
    finished_at INTEGER NOT NULL DEFAULT 0,
    UNIQUE (domain, name)
);
CREATE INDEX idx_backups_site ON backups(site_id, id DESC);
CREATE INDEX idx_backups_plan ON backups(plan_id, domain, id DESC);

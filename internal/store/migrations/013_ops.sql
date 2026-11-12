-- Faz 12: server metric history, domain registration expiry, backup verification.

-- One row per 5-minute sample (CPU busy %, bytes, load ×100, network bytes
-- in the interval). 30 days ≈ 8 640 rows; purged by the daily maintenance.
CREATE TABLE metrics (
    ts        INTEGER PRIMARY KEY,           -- unix seconds
    cpu       INTEGER NOT NULL DEFAULT 0,    -- busy %, ×10
    mem_used  INTEGER NOT NULL DEFAULT 0,    -- bytes (total − available)
    mem_total INTEGER NOT NULL DEFAULT 0,
    swap_used INTEGER NOT NULL DEFAULT 0,
    disk_pct  INTEGER NOT NULL DEFAULT 0,    -- root filesystem used %, ×10
    load1     INTEGER NOT NULL DEFAULT 0,    -- ×100
    rx        INTEGER NOT NULL DEFAULT 0,    -- bytes received since the previous sample
    tx        INTEGER NOT NULL DEFAULT 0
);

-- Registration expiry of the registrable domains the panel serves (sites,
-- zones, mail domains). source: rdap (looked up daily) | manual (e.g. .tr,
-- which has no RDAP service).
CREATE TABLE domain_expiry (
    name       TEXT PRIMARY KEY,
    expires_at INTEGER NOT NULL DEFAULT 0,   -- unix seconds, 0 = unknown
    source     TEXT NOT NULL DEFAULT 'rdap',
    registrar  TEXT NOT NULL DEFAULT '',
    checked_at INTEGER NOT NULL DEFAULT 0,
    error      TEXT NOT NULL DEFAULT '',
    notified   INTEGER NOT NULL DEFAULT 0    -- smallest threshold (days) already notified for expires_at
) WITHOUT ROWID;

-- Backup restore drills (download + checksums + archive and database checks).
CREATE TABLE backup_verifications (
    id         INTEGER PRIMARY KEY,
    backup_id  INTEGER REFERENCES backups(id) ON DELETE SET NULL,
    domain     TEXT NOT NULL,
    name       TEXT NOT NULL,
    source     TEXT NOT NULL,                -- local | remote
    status     TEXT NOT NULL,                -- success | failed
    detail     TEXT NOT NULL DEFAULT '',     -- one line per check
    job_id     INTEGER NOT NULL DEFAULT 0,
    created_at INTEGER NOT NULL
);
CREATE INDEX backup_verifications_created ON backup_verifications(created_at);

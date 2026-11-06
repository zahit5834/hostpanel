-- Faz 5b: site crons, git deploy, release origin.

CREATE TABLE site_crons (
    id          INTEGER PRIMARY KEY,
    site_id     INTEGER NOT NULL REFERENCES sites(id) ON DELETE CASCADE,
    name        TEXT NOT NULL,
    schedule    TEXT NOT NULL,                 -- 5-field cron expression (server local time)
    command     TEXT NOT NULL,                 -- one line, run with bash as the site user
    enabled     INTEGER NOT NULL DEFAULT 1,
    timeout_sec INTEGER NOT NULL DEFAULT 600,
    next_run_at INTEGER NOT NULL DEFAULT 0,
    last_run_at INTEGER NOT NULL DEFAULT 0,
    last_status TEXT NOT NULL DEFAULT '',      -- ok | failed | timeout | skipped
    last_exit   INTEGER NOT NULL DEFAULT 0,
    last_ms     INTEGER NOT NULL DEFAULT 0,
    created_at  INTEGER NOT NULL
);
CREATE INDEX idx_site_crons_site ON site_crons(site_id);

-- One row per run (not in jobs/activity_log: a minutely cron would flood them).
CREATE TABLE cron_runs (
    id          INTEGER PRIMARY KEY,
    cron_id     INTEGER NOT NULL REFERENCES site_crons(id) ON DELETE CASCADE,
    site_id     INTEGER NOT NULL REFERENCES sites(id) ON DELETE CASCADE,
    started_at  INTEGER NOT NULL,
    duration_ms INTEGER NOT NULL DEFAULT 0,
    exit_code   INTEGER NOT NULL DEFAULT 0,
    status      TEXT NOT NULL,                 -- ok | failed | timeout | skipped
    output      TEXT NOT NULL DEFAULT '',      -- last 16 KB
    source      TEXT NOT NULL DEFAULT 'system' -- system (schedule) | user (run now)
);
CREATE INDEX idx_cron_runs_cron ON cron_runs(cron_id, id DESC);
CREATE INDEX idx_cron_runs_started ON cron_runs(started_at);

-- Git deploy settings. The deploy key itself stays root-only on disk
-- (/etc/hostpanel/git/<domain>/); only its fingerprint is kept here.
CREATE TABLE site_git (
    site_id         INTEGER PRIMARY KEY REFERENCES sites(id) ON DELETE CASCADE,
    repo_url        TEXT NOT NULL,
    branch          TEXT NOT NULL DEFAULT 'main',
    build_command   TEXT NOT NULL DEFAULT '',
    output_dir      TEXT NOT NULL DEFAULT '.',
    build_timeout   INTEGER NOT NULL DEFAULT 900,
    public_key      TEXT NOT NULL DEFAULT '',
    last_commit     TEXT NOT NULL DEFAULT '',
    last_subject    TEXT NOT NULL DEFAULT '',
    updated_at      INTEGER NOT NULL
);

ALTER TABLE releases ADD COLUMN source TEXT NOT NULL DEFAULT 'zip'; -- zip | git | backup
ALTER TABLE releases ADD COLUMN commit_sha TEXT NOT NULL DEFAULT '';

-- Single admin account (id = 1).
CREATE TABLE users (
    id            INTEGER PRIMARY KEY,
    username      TEXT NOT NULL UNIQUE,
    password_hash TEXT NOT NULL,
    totp_secret   TEXT NOT NULL DEFAULT '',   -- AES-GCM sealed
    totp_enabled  INTEGER NOT NULL DEFAULT 0,
    created_at    INTEGER NOT NULL,
    updated_at    INTEGER NOT NULL
);

CREATE TABLE recovery_codes (
    id        INTEGER PRIMARY KEY,
    user_id   INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    code_hash TEXT NOT NULL,
    used_at   INTEGER
);

-- Session id is stored as SHA-256 hash so a DB leak does not leak live sessions.
CREATE TABLE sessions (
    id_hash     TEXT PRIMARY KEY,
    user_id     INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    csrf_token  TEXT NOT NULL,
    stage       TEXT NOT NULL DEFAULT 'full',  -- 'mfa' = password ok, TOTP pending
    ip          TEXT NOT NULL,
    user_agent  TEXT NOT NULL,
    created_at  INTEGER NOT NULL,
    last_seen   INTEGER NOT NULL,
    expires_at  INTEGER NOT NULL
);
CREATE INDEX idx_sessions_expires ON sessions(expires_at);

CREATE TABLE login_attempts (
    id      INTEGER PRIMARY KEY,
    ts      INTEGER NOT NULL,
    ip      TEXT NOT NULL,
    success INTEGER NOT NULL
);
CREATE INDEX idx_login_attempts_ip_ts ON login_attempts(ip, ts);

CREATE TABLE settings (
    key   TEXT PRIMARY KEY,
    value TEXT NOT NULL
);

CREATE TABLE activity_log (
    id          INTEGER PRIMARY KEY,
    ts          INTEGER NOT NULL,             -- unix millis
    source      TEXT NOT NULL,                -- 'user' | 'system'
    ip          TEXT NOT NULL DEFAULT '',
    action      TEXT NOT NULL,                -- site.create, login.failed, ...
    target_type TEXT NOT NULL DEFAULT '',
    target_id   TEXT NOT NULL DEFAULT '',
    status      TEXT NOT NULL,                -- 'success' | 'failed' | 'running'
    duration_ms INTEGER NOT NULL DEFAULT 0,
    summary     TEXT NOT NULL DEFAULT '',
    params      TEXT NOT NULL DEFAULT '',     -- masked JSON
    diff        TEXT NOT NULL DEFAULT '',
    error       TEXT NOT NULL DEFAULT '',
    job_id      INTEGER
);
CREATE INDEX idx_activity_ts      ON activity_log(ts DESC);
CREATE INDEX idx_activity_action  ON activity_log(action, ts DESC);
CREATE INDEX idx_activity_target  ON activity_log(target_type, target_id, ts DESC);
CREATE INDEX idx_activity_status  ON activity_log(status, ts DESC);

CREATE TABLE jobs (
    id          INTEGER PRIMARY KEY,
    kind        TEXT NOT NULL,
    target_type TEXT NOT NULL DEFAULT '',
    target_id   TEXT NOT NULL DEFAULT '',
    status      TEXT NOT NULL,                -- queued | running | success | failed | canceled
    progress    INTEGER NOT NULL DEFAULT 0,   -- 0..100
    params      TEXT NOT NULL DEFAULT '',     -- masked JSON
    error       TEXT NOT NULL DEFAULT '',
    retryable   INTEGER NOT NULL DEFAULT 0,
    activity_id INTEGER,
    created_at  INTEGER NOT NULL,
    started_at  INTEGER,
    finished_at INTEGER
);
CREATE INDEX idx_jobs_created ON jobs(created_at DESC);
CREATE INDEX idx_jobs_status  ON jobs(status);

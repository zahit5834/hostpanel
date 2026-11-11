-- Faz 10: site traffic statistics and uptime history.

-- One row per site and complete day, aggregated from the nginx access log
-- by the daily maintenance (today is computed live, never stored).
CREATE TABLE traffic_daily (
    site_id   INTEGER NOT NULL REFERENCES sites(id) ON DELETE CASCADE,
    day       TEXT NOT NULL,                 -- YYYY-MM-DD, server local time
    requests  INTEGER NOT NULL DEFAULT 0,
    bytes     INTEGER NOT NULL DEFAULT 0,
    visitors  INTEGER NOT NULL DEFAULT 0,    -- distinct IPs of non-bot requests
    bots      INTEGER NOT NULL DEFAULT 0,
    s2xx      INTEGER NOT NULL DEFAULT 0,
    s3xx      INTEGER NOT NULL DEFAULT 0,
    s4xx      INTEGER NOT NULL DEFAULT 0,
    s5xx      INTEGER NOT NULL DEFAULT 0,
    top_paths TEXT NOT NULL DEFAULT '[]',    -- JSON [{"p":path,"n":count}], top 10
    capped    INTEGER NOT NULL DEFAULT 0,    -- visitor/page tracking hit its limit
    PRIMARY KEY (site_id, day)
) WITHOUT ROWID;

-- Health check results per site and day (written by the monitor).
CREATE TABLE uptime_daily (
    site_id INTEGER NOT NULL REFERENCES sites(id) ON DELETE CASCADE,
    day     TEXT NOT NULL,
    checks  INTEGER NOT NULL DEFAULT 0,
    fails   INTEGER NOT NULL DEFAULT 0,
    ms_sum  INTEGER NOT NULL DEFAULT 0,      -- response time sum of successful checks
    ms_max  INTEGER NOT NULL DEFAULT 0,
    PRIMARY KEY (site_id, day)
) WITHOUT ROWID;

-- Down periods (opened by the "down" transition, closed by "up" or when the
-- site is stopped on purpose).
CREATE TABLE uptime_incidents (
    id         INTEGER PRIMARY KEY,
    site_id    INTEGER NOT NULL REFERENCES sites(id) ON DELETE CASCADE,
    started_at INTEGER NOT NULL,
    ended_at   INTEGER NOT NULL DEFAULT 0,   -- 0 = still down
    reason     TEXT NOT NULL DEFAULT '',
    end_note   TEXT NOT NULL DEFAULT ''
);
CREATE INDEX uptime_incidents_site ON uptime_incidents(site_id, started_at);

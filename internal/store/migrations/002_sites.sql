CREATE TABLE customers (
    id         INTEGER PRIMARY KEY,
    name       TEXT NOT NULL,
    company    TEXT NOT NULL DEFAULT '',
    phone      TEXT NOT NULL DEFAULT '',
    email      TEXT NOT NULL DEFAULT '',
    notes      TEXT NOT NULL DEFAULT '',
    created_at INTEGER NOT NULL,
    updated_at INTEGER NOT NULL
);

CREATE TABLE sites (
    id              INTEGER PRIMARY KEY,
    customer_id     INTEGER NOT NULL REFERENCES customers(id),
    domain          TEXT NOT NULL UNIQUE,
    short_name      TEXT NOT NULL UNIQUE,          -- linux user is site_<short_name>
    aliases         TEXT NOT NULL DEFAULT '[]',    -- JSON array
    www_mode        TEXT NOT NULL DEFAULT 'none',  -- none | to_www | to_apex
    runtime_id      TEXT NOT NULL,
    runtime_version TEXT NOT NULL DEFAULT '',
    fields          TEXT NOT NULL DEFAULT '{}',    -- runtime-specific settings (JSON)
    port            INTEGER UNIQUE,                -- NULL for static sites
    memory_max_mb   INTEGER NOT NULL DEFAULT 512,
    cpu_quota_pct   INTEGER NOT NULL DEFAULT 100,
    status          TEXT NOT NULL,
    persistent_dirs TEXT NOT NULL DEFAULT '[]',    -- JSON array of relative dirs under shared/
    health_path     TEXT NOT NULL DEFAULT '/',
    max_upload_mb   INTEGER NOT NULL DEFAULT 50,
    gzip            INTEGER NOT NULL DEFAULT 1,
    hsts            INTEGER NOT NULL DEFAULT 0,
    force_https     INTEGER NOT NULL DEFAULT 0,
    custom_snippet  TEXT NOT NULL DEFAULT '',
    created_at      INTEGER NOT NULL,
    updated_at      INTEGER NOT NULL
);
CREATE INDEX idx_sites_customer ON sites(customer_id);

-- Values are AES-GCM sealed.
CREATE TABLE site_env (
    site_id      INTEGER NOT NULL REFERENCES sites(id) ON DELETE CASCADE,
    key          TEXT NOT NULL,
    value_sealed TEXT NOT NULL,
    PRIMARY KEY (site_id, key)
);

CREATE TABLE releases (
    id         INTEGER PRIMARY KEY,
    site_id    INTEGER NOT NULL REFERENCES sites(id) ON DELETE CASCADE,
    name       TEXT NOT NULL,                      -- YYYYMMDD-HHMMSS
    size       INTEGER NOT NULL DEFAULT 0,          -- uploaded zip bytes
    status     TEXT NOT NULL,                      -- active | previous | failed | pruned
    job_id     INTEGER,
    created_at INTEGER NOT NULL,
    UNIQUE (site_id, name)
);
CREATE INDEX idx_releases_site ON releases(site_id, id DESC);

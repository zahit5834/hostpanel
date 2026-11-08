-- PostgreSQL (Faz 8): one container managed by hp-pg.sh. The panel never
-- connects to it itself and holds no superuser password (socket + peer
-- inside the container only).
CREATE TABLE pg_servers (
    id          INTEGER PRIMARY KEY,
    image       TEXT NOT NULL,
    memory_mb   INTEGER NOT NULL,
    external    INTEGER NOT NULL DEFAULT 0,      -- listen on * (+ pg_hba + UFW allow rules)
    allow_ips   TEXT NOT NULL DEFAULT '[]',      -- JSON array of IPs/CIDRs
    version     TEXT NOT NULL DEFAULT '',        -- server_version after install
    status      TEXT NOT NULL,                   -- installing | running | stopped | error
    last_error  TEXT NOT NULL DEFAULT '',
    created_at  INTEGER NOT NULL,
    updated_at  INTEGER NOT NULL
);

-- One login role per customer: c_<slug> (NOSUPERUSER NOCREATEDB …).
CREATE TABLE pg_roles (
    id              INTEGER PRIMARY KEY,
    customer_id     INTEGER NOT NULL UNIQUE REFERENCES customers(id),
    name            TEXT NOT NULL UNIQUE,
    password_sealed TEXT NOT NULL,
    disabled        INTEGER NOT NULL DEFAULT 0,
    created_at      INTEGER NOT NULL,
    updated_at      INTEGER NOT NULL
);

-- Databases owned by the customer's role; CONNECT revoked from PUBLIC.
CREATE TABLE pg_databases (
    id          INTEGER PRIMARY KEY,
    customer_id INTEGER NOT NULL REFERENCES customers(id),
    role_id     INTEGER NOT NULL REFERENCES pg_roles(id),
    site_id     INTEGER REFERENCES sites(id) ON DELETE SET NULL,
    name        TEXT NOT NULL UNIQUE,
    env_key     TEXT NOT NULL DEFAULT '',
    status      TEXT NOT NULL,                   -- creating | ready | error | dropping
    size_bytes  INTEGER NOT NULL DEFAULT 0,
    size_at     INTEGER NOT NULL DEFAULT 0,
    created_at  INTEGER NOT NULL
);
CREATE INDEX idx_pg_databases_customer ON pg_databases(customer_id);
CREATE INDEX idx_pg_databases_site ON pg_databases(site_id);

-- Database servers managed by the panel (Faz 3: one MSSQL container).
-- Passwords are AES-GCM sealed; sa_pending_sealed holds a new SA password
-- between "ALTER LOGIN sa" and the commit here, so a crash mid-rotation
-- never loses the working password.
CREATE TABLE db_servers (
    id                 INTEGER PRIMARY KEY,
    engine             TEXT NOT NULL,                  -- mssql
    image              TEXT NOT NULL,
    edition            TEXT NOT NULL,                  -- Express | Developer | key
    product_key_sealed TEXT NOT NULL DEFAULT '',
    memory_mb          INTEGER NOT NULL,
    external           INTEGER NOT NULL DEFAULT 0,     -- listen on 0.0.0.0 (+ UFW allow rules)
    allow_ips          TEXT NOT NULL DEFAULT '[]',     -- JSON array of IPs/CIDRs for external access
    sa_sealed          TEXT NOT NULL,
    sa_pending_sealed  TEXT NOT NULL DEFAULT '',
    status             TEXT NOT NULL,                  -- installing | running | stopped | error
    last_error         TEXT NOT NULL DEFAULT '',
    created_at         INTEGER NOT NULL,
    updated_at         INTEGER NOT NULL
);

-- One SQL login per customer: c_<slug>, DENY VIEW ANY DATABASE.
CREATE TABLE db_logins (
    id              INTEGER PRIMARY KEY,
    server_id       INTEGER NOT NULL REFERENCES db_servers(id),
    customer_id     INTEGER NOT NULL UNIQUE REFERENCES customers(id),
    name            TEXT NOT NULL UNIQUE,
    password_sealed TEXT NOT NULL,
    disabled        INTEGER NOT NULL DEFAULT 0,
    created_at      INTEGER NOT NULL,
    updated_at      INTEGER NOT NULL
);

-- Databases are owned by the customer's login (ALTER AUTHORIZATION).
-- env_key: the site env variable the connection string was written to (kept
-- up to date on password reset).
CREATE TABLE databases (
    id          INTEGER PRIMARY KEY,
    server_id   INTEGER NOT NULL REFERENCES db_servers(id),
    customer_id INTEGER NOT NULL REFERENCES customers(id),
    login_id    INTEGER NOT NULL REFERENCES db_logins(id),
    site_id     INTEGER REFERENCES sites(id) ON DELETE SET NULL,
    name        TEXT NOT NULL UNIQUE,
    env_key     TEXT NOT NULL DEFAULT '',
    status      TEXT NOT NULL,                         -- creating | ready | error | dropping
    size_bytes  INTEGER NOT NULL DEFAULT 0,
    size_at     INTEGER NOT NULL DEFAULT 0,
    created_at  INTEGER NOT NULL
);
CREATE INDEX idx_databases_customer ON databases(customer_id);
CREATE INDEX idx_databases_site ON databases(site_id);

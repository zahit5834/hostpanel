-- Certificates served by nginx. cert_pem is the (public) fullchain; for custom
-- certificates the private key is kept AES-GCM sealed so it can be exported
-- and backed up. Let's Encrypt keys stay in /etc/letsencrypt (root only).
CREATE TABLE certificates (
    id            INTEGER PRIMARY KEY,
    site_id       INTEGER REFERENCES sites(id) ON DELETE CASCADE,
    domain        TEXT NOT NULL,
    kind          TEXT NOT NULL,                  -- letsencrypt | custom
    challenge     TEXT NOT NULL DEFAULT '',       -- http-01 (dns-01 later)
    names         TEXT NOT NULL DEFAULT '[]',     -- JSON array (SANs)
    issuer        TEXT NOT NULL DEFAULT '',
    serial        TEXT NOT NULL DEFAULT '',
    fingerprint   TEXT NOT NULL DEFAULT '',       -- SHA-256 of the leaf, hex
    key_type      TEXT NOT NULL DEFAULT '',
    not_before    INTEGER NOT NULL DEFAULT 0,
    not_after     INTEGER NOT NULL DEFAULT 0,
    status        TEXT NOT NULL,                  -- pending | active | error | replaced | removed
    staging       INTEGER NOT NULL DEFAULT 0,
    cert_pem      TEXT NOT NULL DEFAULT '',
    key_sealed    TEXT NOT NULL DEFAULT '',
    last_error    TEXT NOT NULL DEFAULT '',
    notified_days INTEGER NOT NULL DEFAULT 0,     -- smallest expiry threshold already reported
    created_at    INTEGER NOT NULL,
    updated_at    INTEGER NOT NULL
);
CREATE INDEX idx_cert_site ON certificates(site_id);
CREATE UNIQUE INDEX idx_cert_active ON certificates(site_id) WHERE status = 'active';

CREATE TABLE csrs (
    id          INTEGER PRIMARY KEY,
    site_id     INTEGER REFERENCES sites(id) ON DELETE SET NULL,
    common_name TEXT NOT NULL,
    sans        TEXT NOT NULL DEFAULT '[]',
    subject     TEXT NOT NULL DEFAULT '{}',
    key_type    TEXT NOT NULL,
    key_sealed  TEXT NOT NULL,
    csr_pem     TEXT NOT NULL,
    cert_id     INTEGER REFERENCES certificates(id) ON DELETE SET NULL,
    created_at  INTEGER NOT NULL
);

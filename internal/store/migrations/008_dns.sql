-- Authoritative DNS (Faz 7): zones served by the local BIND 9. Records for
-- sites (A/AAAA of domain, www and aliases) are derived at render time and
-- not stored here.
CREATE TABLE dns_zones (
    id          INTEGER PRIMARY KEY,
    name        TEXT NOT NULL UNIQUE,                       -- lower case, no trailing dot
    customer_id INTEGER REFERENCES customers(id) ON DELETE SET NULL,
    serial      INTEGER NOT NULL DEFAULT 0,                 -- YYYYMMDDnn, bumped on every apply
    default_ttl INTEGER NOT NULL DEFAULT 3600,
    soa_refresh INTEGER NOT NULL DEFAULT 3600,
    soa_retry   INTEGER NOT NULL DEFAULT 900,
    soa_expire  INTEGER NOT NULL DEFAULT 1209600,
    soa_minimum INTEGER NOT NULL DEFAULT 300,
    dnssec      INTEGER NOT NULL DEFAULT 0,
    auto_sites  INTEGER NOT NULL DEFAULT 1,
    created_at  INTEGER NOT NULL,
    updated_at  INTEGER NOT NULL
);

CREATE TABLE dns_records (
    id         INTEGER PRIMARY KEY,
    zone_id    INTEGER NOT NULL REFERENCES dns_zones(id) ON DELETE CASCADE,
    name       TEXT NOT NULL,              -- "@", "*", relative labels ("www", "_dmarc", "*.app")
    type       TEXT NOT NULL,              -- A AAAA CNAME MX TXT SRV CAA NS
    ttl        INTEGER NOT NULL DEFAULT 0, -- 0 = zone default
    prio       INTEGER NOT NULL DEFAULT 0, -- MX/SRV priority, CAA flag
    weight     INTEGER NOT NULL DEFAULT 0, -- SRV
    port       INTEGER NOT NULL DEFAULT 0, -- SRV
    tag        TEXT NOT NULL DEFAULT '',   -- CAA tag
    value      TEXT NOT NULL,
    created_at INTEGER NOT NULL
);
CREATE INDEX dns_records_zone ON dns_records(zone_id, name);

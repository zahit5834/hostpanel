-- E-mail (Faz 9): one docker-mailserver container managed by hp-mail.sh. The
-- panel never connects to it and stores no mailbox passwords: accounts,
-- aliases and quotas live only in the container's config files (root), which
-- the helper reads and writes.
CREATE TABLE mail_servers (
    id            INTEGER PRIMARY KEY,
    image         TEXT NOT NULL,
    hostname      TEXT NOT NULL,                   -- mail.example.com (MX target, PTR, certificate name)
    le_email      TEXT NOT NULL,
    memory_mb     INTEGER NOT NULL,
    clamav        INTEGER NOT NULL DEFAULT 0,
    msg_limit_mb  INTEGER NOT NULL DEFAULT 25,     -- largest attachment (the SMTP limit is ×1.4)
    status        TEXT NOT NULL,                   -- installing | running | stopped | error
    last_error    TEXT NOT NULL DEFAULT '',
    created_at    INTEGER NOT NULL,
    updated_at    INTEGER NOT NULL
);

-- Domains the panel lets mailboxes and aliases be created in. The mail server
-- itself has no domain object (it derives them from the accounts).
CREATE TABLE mail_domains (
    id            INTEGER PRIMARY KEY,
    customer_id   INTEGER REFERENCES customers(id) ON DELETE SET NULL,
    name          TEXT NOT NULL UNIQUE,
    dkim_selector TEXT NOT NULL DEFAULT 'mail',
    dkim_txt      TEXT NOT NULL DEFAULT '',        -- public key record (v=DKIM1; k=rsa; p=…)
    created_at    INTEGER NOT NULL
);
CREATE INDEX idx_mail_domains_customer ON mail_domains(customer_id);

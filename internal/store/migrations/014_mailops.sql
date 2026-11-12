-- Faz 13: outgoing mail limits, DMARC policy and reports, wildcard sites.

ALTER TABLE mail_servers ADD COLUMN rate_per_hour INTEGER NOT NULL DEFAULT 200; -- per mailbox, 0 = no limit
ALTER TABLE mail_servers ADD COLUMN queue_alert INTEGER NOT NULL DEFAULT 50;    -- queued messages, 0 = off
ALTER TABLE mail_domains ADD COLUMN dmarc_policy TEXT NOT NULL DEFAULT 'quarantine'; -- none | quarantine | reject

-- Report mails copied from the dmarc@ mailbox (hp-mail.sh dmarc-sync); each
-- file is parsed once.
CREATE TABLE dmarc_files (
    name    TEXT PRIMARY KEY,
    seen_at INTEGER NOT NULL,
    status  TEXT NOT NULL,                  -- ok | skipped | error
    detail  TEXT NOT NULL DEFAULT ''
) WITHOUT ROWID;

-- Aggregate reports (RFC 7489 appendix C), kept 180 days.
CREATE TABLE dmarc_reports (
    id         INTEGER PRIMARY KEY,
    org        TEXT NOT NULL,
    report_id  TEXT NOT NULL,
    domain     TEXT NOT NULL,
    begin_at   INTEGER NOT NULL,
    end_at     INTEGER NOT NULL,
    policy     TEXT NOT NULL DEFAULT '',
    created_at INTEGER NOT NULL,
    UNIQUE (org, report_id)
);
CREATE INDEX dmarc_reports_domain ON dmarc_reports(domain, end_at);

CREATE TABLE dmarc_records (
    report      INTEGER NOT NULL REFERENCES dmarc_reports(id) ON DELETE CASCADE,
    source_ip   TEXT NOT NULL,
    count       INTEGER NOT NULL,
    disposition TEXT NOT NULL,              -- none | quarantine | reject
    dkim        TEXT NOT NULL,              -- policy evaluated: pass | fail
    spf         TEXT NOT NULL,
    header_from TEXT NOT NULL
);
CREATE INDEX dmarc_records_report ON dmarc_records(report);

-- Sites answering every subdomain (*.domain; certificate via DNS-01).
ALTER TABLE sites ADD COLUMN wildcard INTEGER NOT NULL DEFAULT 0;

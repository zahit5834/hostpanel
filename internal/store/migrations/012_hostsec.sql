-- Faz 11: re-authentication ("sudo mode") for critical actions. A full
-- session is elevated until this unix time (set at login and by /reauth).
ALTER TABLE sessions ADD COLUMN elevated_until INTEGER NOT NULL DEFAULT 0;

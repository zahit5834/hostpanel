package ssl

import (
	"context"
	"database/sql"
	"encoding/json"
	"strconv"
	"time"
)

// Certificate kinds and statuses.
const (
	KindLE     = "letsencrypt"
	KindCustom = "custom"

	StatusPending  = "pending"
	StatusActive   = "active"
	StatusError    = "error"
	StatusReplaced = "replaced"
	StatusRemoved  = "removed"
)

// Certificate is a row of certificates.
type Certificate struct {
	ID           int64
	SiteID       int64
	Domain       string
	Kind         string
	Challenge    string
	Names        []string
	Issuer       string
	Serial       string
	Fingerprint  string
	KeyType      string
	NotBefore    time.Time
	NotAfter     time.Time
	Status       string
	Staging      bool
	CertPEM      string
	KeySealed    string
	LastError    string
	NotifiedDays int
	CreatedAt    time.Time
	UpdatedAt    time.Time
}

// DaysLeft is the whole days until expiry (negative when expired).
func (c Certificate) DaysLeft() int {
	if c.NotAfter.IsZero() {
		return 0
	}
	d := time.Until(c.NotAfter)
	if d < 0 {
		return int(d.Hours()/24) - 1
	}
	return int(d.Hours() / 24)
}

// Paths returns where nginx reads the certificate and key.
func (c Certificate) Paths() (cert, key string) {
	if c.Kind == KindLE {
		return LEPaths(c.Domain)
	}
	return CustomPaths(c.Domain, c.ID)
}

// LEPaths is certbot's lineage for --cert-name <domain>.
func LEPaths(domain string) (string, string) {
	d := "/etc/letsencrypt/live/" + domain + "/"
	return d + "fullchain.pem", d + "privkey.pem"
}

// CustomPaths keeps every installed custom certificate in its own directory so
// a failed install never overwrites the one nginx is using.
func CustomPaths(domain string, id int64) (string, string) {
	d := "/etc/hostpanel/ssl/" + domain + "/" + strconv.FormatInt(id, 10) + "/"
	return d + "fullchain.pem", d + "privkey.pem"
}

func jsonStr(v any) string {
	b, _ := json.Marshal(v)
	return string(b)
}

// Store persists certificates and CSRs.
type Store struct{ db *sql.DB }

// NewStore wraps db.
func NewStore(db *sql.DB) *Store { return &Store{db: db} }

const certCols = `id, COALESCE(site_id,0), domain, kind, challenge, names, issuer, serial, fingerprint, key_type,
	not_before, not_after, status, staging, cert_pem, key_sealed, last_error, notified_days, created_at, updated_at`

func scanCert(sc interface{ Scan(...any) error }) (Certificate, error) {
	var c Certificate
	var names string
	var nb, na, cr, up int64
	err := sc.Scan(&c.ID, &c.SiteID, &c.Domain, &c.Kind, &c.Challenge, &names, &c.Issuer, &c.Serial, &c.Fingerprint,
		&c.KeyType, &nb, &na, &c.Status, &c.Staging, &c.CertPEM, &c.KeySealed, &c.LastError, &c.NotifiedDays, &cr, &up)
	if err != nil {
		return c, err
	}
	json.Unmarshal([]byte(names), &c.Names)
	if nb > 0 {
		c.NotBefore = time.Unix(nb, 0)
	}
	if na > 0 {
		c.NotAfter = time.Unix(na, 0)
	}
	c.CreatedAt, c.UpdatedAt = time.Unix(cr, 0), time.Unix(up, 0)
	return c, nil
}

func (st *Store) list(ctx context.Context, where string, args ...any) ([]Certificate, error) {
	rows, err := st.db.QueryContext(ctx, `SELECT `+certCols+` FROM certificates `+where, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Certificate
	for rows.Next() {
		c, err := scanCert(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, c)
	}
	return out, rows.Err()
}

// Get loads one certificate.
func (st *Store) Get(ctx context.Context, id int64) (Certificate, error) {
	return scanCert(st.db.QueryRowContext(ctx, `SELECT `+certCols+` FROM certificates WHERE id=?`, id))
}

// Active returns the site's active certificate (sql.ErrNoRows if none).
func (st *Store) Active(ctx context.Context, siteID int64) (Certificate, error) {
	return scanCert(st.db.QueryRowContext(ctx, `SELECT `+certCols+` FROM certificates WHERE site_id=? AND status='active'`, siteID))
}

// All returns every certificate that is active or failed, newest first.
func (st *Store) All(ctx context.Context) ([]Certificate, error) {
	return st.list(ctx, `WHERE status IN ('active','error','pending') ORDER BY (status='active') DESC, not_after`)
}

// ActiveAll returns all active certificates.
func (st *Store) ActiveAll(ctx context.Context) ([]Certificate, error) {
	return st.list(ctx, `WHERE status='active' ORDER BY not_after`)
}

// ForSite returns the site's certificate history, newest first.
func (st *Store) ForSite(ctx context.Context, siteID int64) ([]Certificate, error) {
	return st.list(ctx, `WHERE site_id=? ORDER BY id DESC LIMIT 20`, siteID)
}

// Insert stores c and sets c.ID.
func (st *Store) Insert(ctx context.Context, c *Certificate) error {
	now := time.Now().Unix()
	res, err := st.db.ExecContext(ctx, `INSERT INTO certificates(site_id, domain, kind, challenge, names, issuer, serial,
		fingerprint, key_type, not_before, not_after, status, staging, cert_pem, key_sealed, last_error, created_at, updated_at)
		VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`,
		nullID(c.SiteID), c.Domain, c.Kind, c.Challenge, jsonStr(c.Names), c.Issuer, c.Serial, c.Fingerprint, c.KeyType,
		unix(c.NotBefore), unix(c.NotAfter), c.Status, c.Staging, c.CertPEM, c.KeySealed, c.LastError, now, now)
	if err != nil {
		return err
	}
	c.ID, _ = res.LastInsertId()
	return nil
}

func unix(t time.Time) int64 {
	if t.IsZero() {
		return 0
	}
	return t.Unix()
}

// SetInfo updates the parsed certificate data (after issue/renew) and resets
// the expiry notification state.
func (st *Store) SetInfo(ctx context.Context, id int64, info Info, certPEM string) error {
	_, err := st.db.ExecContext(ctx, `UPDATE certificates SET names=?, issuer=?, serial=?, fingerprint=?, key_type=?,
		not_before=?, not_after=?, cert_pem=?, notified_days=0, last_error='', updated_at=? WHERE id=?`,
		jsonStr(info.Names), info.Issuer, info.Serial, info.Fingerprint, info.KeyType,
		unix(info.NotBefore), unix(info.NotAfter), certPEM, time.Now().Unix(), id)
	return err
}

// SetStatus sets status and the error text.
func (st *Store) SetStatus(ctx context.Context, id int64, status, errText string) error {
	_, err := st.db.ExecContext(ctx, `UPDATE certificates SET status=?, last_error=?, updated_at=? WHERE id=?`,
		status, errText, time.Now().Unix(), id)
	return err
}

// SetNotified records the smallest expiry threshold already reported.
func (st *Store) SetNotified(ctx context.Context, id int64, days int) error {
	_, err := st.db.ExecContext(ctx, `UPDATE certificates SET notified_days=? WHERE id=?`, days, id)
	return err
}

// Activate makes id the site's active certificate and returns the previously
// active one (0 if none), which becomes "replaced".
func (st *Store) Activate(ctx context.Context, siteID, id int64) (int64, error) {
	tx, err := st.db.BeginTx(ctx, nil)
	if err != nil {
		return 0, err
	}
	defer tx.Rollback()
	var prev int64
	tx.QueryRowContext(ctx, `SELECT id FROM certificates WHERE site_id=? AND status='active'`, siteID).Scan(&prev)
	now := time.Now().Unix()
	if prev != 0 && prev != id {
		if _, err := tx.ExecContext(ctx, `UPDATE certificates SET status='replaced', updated_at=? WHERE id=?`, now, prev); err != nil {
			return 0, err
		}
	}
	if _, err := tx.ExecContext(ctx, `UPDATE certificates SET status='active', last_error='', updated_at=? WHERE id=?`, now, id); err != nil {
		return 0, err
	}
	if prev == id {
		prev = 0
	}
	return prev, tx.Commit()
}

// Revert undoes Activate after the nginx config could not be applied.
func (st *Store) Revert(ctx context.Context, id, prev int64, errText string) error {
	tx, err := st.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	now := time.Now().Unix()
	if _, err := tx.ExecContext(ctx, `UPDATE certificates SET status='error', last_error=?, updated_at=? WHERE id=?`, errText, now, id); err != nil {
		return err
	}
	if prev != 0 {
		if _, err := tx.ExecContext(ctx, `UPDATE certificates SET status='active', updated_at=? WHERE id=?`, now, prev); err != nil {
			return err
		}
	}
	return tx.Commit()
}

// --- CSRs ---

// CSR is a generated signing request with its sealed private key.
type CSR struct {
	ID         int64
	SiteID     int64
	CommonName string
	SANs       []string
	Subject    Subject
	KeyType    string
	KeySealed  string
	PEM        string
	CertID     int64
	CreatedAt  time.Time
}

const csrCols = `id, COALESCE(site_id,0), common_name, sans, subject, key_type, key_sealed, csr_pem, COALESCE(cert_id,0), created_at`

func scanCSR(sc interface{ Scan(...any) error }) (CSR, error) {
	var c CSR
	var sans, subj string
	var cr int64
	err := sc.Scan(&c.ID, &c.SiteID, &c.CommonName, &sans, &subj, &c.KeyType, &c.KeySealed, &c.PEM, &c.CertID, &cr)
	if err != nil {
		return c, err
	}
	json.Unmarshal([]byte(sans), &c.SANs)
	json.Unmarshal([]byte(subj), &c.Subject)
	c.CreatedAt = time.Unix(cr, 0)
	return c, nil
}

// InsertCSR stores c and sets c.ID.
func (st *Store) InsertCSR(ctx context.Context, c *CSR) error {
	res, err := st.db.ExecContext(ctx, `INSERT INTO csrs(site_id, common_name, sans, subject, key_type, key_sealed, csr_pem, created_at)
		VALUES(?,?,?,?,?,?,?,?)`, nullID(c.SiteID), c.CommonName, jsonStr(c.SANs), jsonStr(c.Subject), c.KeyType, c.KeySealed, c.PEM, time.Now().Unix())
	if err != nil {
		return err
	}
	c.ID, _ = res.LastInsertId()
	return nil
}

func nullID(id int64) any {
	if id == 0 {
		return nil
	}
	return id
}

// GetCSR loads one CSR.
func (st *Store) GetCSR(ctx context.Context, id int64) (CSR, error) {
	return scanCSR(st.db.QueryRowContext(ctx, `SELECT `+csrCols+` FROM csrs WHERE id=?`, id))
}

// CSRs lists CSRs, newest first.
func (st *Store) CSRs(ctx context.Context) ([]CSR, error) {
	rows, err := st.db.QueryContext(ctx, `SELECT `+csrCols+` FROM csrs ORDER BY id DESC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []CSR
	for rows.Next() {
		c, err := scanCSR(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, c)
	}
	return out, rows.Err()
}

// LinkCSR records which certificate was issued for a CSR.
func (st *Store) LinkCSR(ctx context.Context, csrID, certID int64) error {
	_, err := st.db.ExecContext(ctx, `UPDATE csrs SET cert_id=? WHERE id=?`, certID, csrID)
	return err
}

// DeleteCSR removes a CSR (and its key).
func (st *Store) DeleteCSR(ctx context.Context, id int64) error {
	_, err := st.db.ExecContext(ctx, `DELETE FROM csrs WHERE id=?`, id)
	return err
}

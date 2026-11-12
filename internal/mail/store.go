package mail

import (
	"context"
	"database/sql"
	"time"
)

// Server states (same values as the database servers).
const (
	StatusInstalling = "installing"
	StatusRunning    = "running"
	StatusStopped    = "stopped"
	StatusError      = "error"
)

// Server is the (single) mail container.
type Server struct {
	ID         int64
	Image      string
	Hostname   string
	LEEmail    string
	MemoryMB   int
	ClamAV     bool
	MsgLimitMB int
	// RatePerHour is the sending limit per mailbox (0 = none); QueueAlert the
	// queue length that raises an alarm (0 = off).
	RatePerHour int
	QueueAlert  int
	Status      string
	LastError   string
	CreatedAt   time.Time
	UpdatedAt   time.Time
}

// Domain is a mail domain; its mailboxes and aliases are not stored here.
type Domain struct {
	ID           int64
	CustomerID   int64 // 0 = none
	CustomerName string
	Name         string
	DKIMSelector string
	DKIMTXT      string
	DMARCPolicy  string // none | quarantine | reject
	CreatedAt    time.Time
}

// Store is the panel-side record of the server and its domains.
type Store struct{ db *sql.DB }

// NewStore returns a Store on db.
func NewStore(db *sql.DB) *Store { return &Store{db: db} }

// Server returns the server; sql.ErrNoRows if none is installed.
func (st *Store) Server(ctx context.Context) (Server, error) {
	var s Server
	var created, updated int64
	err := st.db.QueryRowContext(ctx, `SELECT id, image, hostname, le_email, memory_mb, clamav, msg_limit_mb, rate_per_hour, queue_alert, status, last_error, created_at, updated_at
		FROM mail_servers ORDER BY id LIMIT 1`).Scan(&s.ID, &s.Image, &s.Hostname, &s.LEEmail, &s.MemoryMB, &s.ClamAV, &s.MsgLimitMB,
		&s.RatePerHour, &s.QueueAlert, &s.Status, &s.LastError, &created, &updated)
	if err != nil {
		return s, err
	}
	s.CreatedAt, s.UpdatedAt = time.Unix(created, 0), time.Unix(updated, 0)
	return s, nil
}

// InsertServer stores a new server row.
func (st *Store) InsertServer(ctx context.Context, s *Server) error {
	now := time.Now().Unix()
	res, err := st.db.ExecContext(ctx, `INSERT INTO mail_servers(image, hostname, le_email, memory_mb, clamav, msg_limit_mb, status, created_at, updated_at)
		VALUES (?,?,?,?,?,?,?,?,?)`, s.Image, s.Hostname, s.LEEmail, s.MemoryMB, s.ClamAV, s.MsgLimitMB, s.Status, now, now)
	if err != nil {
		return err
	}
	s.ID, _ = res.LastInsertId()
	return nil
}

// DeleteServer removes the server row.
func (st *Store) DeleteServer(ctx context.Context, id int64) error {
	_, err := st.db.ExecContext(ctx, `DELETE FROM mail_servers WHERE id=?`, id)
	return err
}

// SetServerStatus records the state (and the last error, "" when fine).
func (st *Store) SetServerStatus(ctx context.Context, id int64, status, lastErr string) error {
	_, err := st.db.ExecContext(ctx, `UPDATE mail_servers SET status=?, last_error=?, updated_at=? WHERE id=?`,
		status, lastErr, time.Now().Unix(), id)
	return err
}

// UpdateServerSettings stores memory, ClamAV and the message size limit.
func (st *Store) UpdateServerSettings(ctx context.Context, s Server) error {
	_, err := st.db.ExecContext(ctx, `UPDATE mail_servers SET memory_mb=?, clamav=?, msg_limit_mb=?, updated_at=? WHERE id=?`,
		s.MemoryMB, s.ClamAV, s.MsgLimitMB, time.Now().Unix(), s.ID)
	return err
}

const domainSelect = `SELECT d.id, COALESCE(d.customer_id, 0), COALESCE(c.name, ''), d.name, d.dkim_selector, d.dkim_txt, d.dmarc_policy, d.created_at
	FROM mail_domains d LEFT JOIN customers c ON c.id = d.customer_id`

func scanDomain(row interface{ Scan(...any) error }) (Domain, error) {
	var d Domain
	var created int64
	err := row.Scan(&d.ID, &d.CustomerID, &d.CustomerName, &d.Name, &d.DKIMSelector, &d.DKIMTXT, &d.DMARCPolicy, &created)
	d.CreatedAt = time.Unix(created, 0)
	return d, err
}

// Domains lists mail domains by name; customerID 0 = all.
func (st *Store) Domains(ctx context.Context, customerID int64) ([]Domain, error) {
	q, args := domainSelect, []any{}
	if customerID > 0 {
		q += ` WHERE d.customer_id = ?`
		args = append(args, customerID)
	}
	rows, err := st.db.QueryContext(ctx, q+` ORDER BY d.name`, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Domain
	for rows.Next() {
		d, err := scanDomain(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, d)
	}
	return out, rows.Err()
}

// Domain returns one domain by id.
func (st *Store) Domain(ctx context.Context, id int64) (Domain, error) {
	return scanDomain(st.db.QueryRowContext(ctx, domainSelect+` WHERE d.id = ?`, id))
}

// DomainByName returns one domain by name.
func (st *Store) DomainByName(ctx context.Context, name string) (Domain, error) {
	return scanDomain(st.db.QueryRowContext(ctx, domainSelect+` WHERE d.name = ?`, name))
}

// InsertDomain stores a new domain.
func (st *Store) InsertDomain(ctx context.Context, d *Domain) error {
	var cust any
	if d.CustomerID > 0 {
		cust = d.CustomerID
	}
	if d.DKIMSelector == "" {
		d.DKIMSelector = DKIMSelector
	}
	res, err := st.db.ExecContext(ctx, `INSERT INTO mail_domains(customer_id, name, dkim_selector, dkim_txt, created_at) VALUES (?,?,?,?,?)`,
		cust, d.Name, d.DKIMSelector, d.DKIMTXT, time.Now().Unix())
	if err != nil {
		return err
	}
	d.ID, _ = res.LastInsertId()
	return nil
}

// SetDKIM stores the public key record of a domain.
func (st *Store) SetDKIM(ctx context.Context, id int64, txt string) error {
	_, err := st.db.ExecContext(ctx, `UPDATE mail_domains SET dkim_txt=? WHERE id=?`, txt, id)
	return err
}

// DeleteDomain removes a domain row.
func (st *Store) DeleteDomain(ctx context.Context, id int64) error {
	_, err := st.db.ExecContext(ctx, `DELETE FROM mail_domains WHERE id=?`, id)
	return err
}

// SetLimits stores the sending limit and the queue alarm threshold.
func (st *Store) SetLimits(ctx context.Context, id int64, ratePerHour, queueAlert int) error {
	_, err := st.db.ExecContext(ctx, `UPDATE mail_servers SET rate_per_hour=?, queue_alert=?, updated_at=? WHERE id=?`,
		ratePerHour, queueAlert, time.Now().Unix(), id)
	return err
}

// SetDMARCPolicy stores the published DMARC policy of a domain.
func (st *Store) SetDMARCPolicy(ctx context.Context, id int64, policy string) error {
	_, err := st.db.ExecContext(ctx, `UPDATE mail_domains SET dmarc_policy=? WHERE id=?`, policy, id)
	return err
}

// SetImage records the container image (image update / rollback).
func (st *Store) SetImage(ctx context.Context, id int64, image string) error {
	_, err := st.db.ExecContext(ctx, `UPDATE mail_servers SET image=?, updated_at=? WHERE id=?`, image, time.Now().Unix(), id)
	return err
}

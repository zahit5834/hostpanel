package databases

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"time"
)

// Server statuses.
const (
	StatusInstalling = "installing"
	StatusRunning    = "running"
	StatusStopped    = "stopped"
	StatusError      = "error"
)

// Database statuses.
const (
	DBCreating = "creating"
	DBReady    = "ready"
	DBError    = "error"
	DBDropping = "dropping"
)

// Server is the managed database server (one MSSQL container).
type Server struct {
	ID               int64
	Engine           string
	Image            string
	Edition          string // Express | Developer | key
	ProductKeySealed string
	MemoryMB         int
	External         bool
	AllowIPs         []string
	SASealed         string
	SAPendingSealed  string
	Status           string
	LastError        string
	CreatedAt        time.Time
	UpdatedAt        time.Time
}

// Login is a customer's SQL login.
type Login struct {
	ID             int64
	ServerID       int64
	CustomerID     int64
	CustomerName   string
	Name           string
	PasswordSealed string
	Disabled       bool
	CreatedAt      time.Time
	DBCount        int
}

// Database is a customer database.
type Database struct {
	ID           int64
	ServerID     int64
	CustomerID   int64
	CustomerName string
	LoginID      int64
	LoginName    string
	SiteID       int64 // 0 = not linked
	SiteDomain   string
	Name         string
	EnvKey       string
	Status       string
	SizeBytes    int64
	SizeAt       time.Time
	CreatedAt    time.Time
}

// Store accesses the db_* tables.
type Store struct{ db *sql.DB }

// NewStore wraps db.
func NewStore(db *sql.DB) *Store { return &Store{db: db} }

const serverCols = `id, engine, image, edition, product_key_sealed, memory_mb, external, allow_ips, sa_sealed,
	sa_pending_sealed, status, last_error, created_at, updated_at`

// Server returns the (single) server; sql.ErrNoRows if none is installed.
func (st *Store) Server(ctx context.Context) (Server, error) {
	var s Server
	var ips string
	var created, updated int64
	err := st.db.QueryRowContext(ctx, `SELECT `+serverCols+` FROM db_servers ORDER BY id LIMIT 1`).Scan(
		&s.ID, &s.Engine, &s.Image, &s.Edition, &s.ProductKeySealed, &s.MemoryMB, &s.External, &ips, &s.SASealed,
		&s.SAPendingSealed, &s.Status, &s.LastError, &created, &updated)
	if err != nil {
		return s, err
	}
	json.Unmarshal([]byte(ips), &s.AllowIPs)
	s.CreatedAt, s.UpdatedAt = time.Unix(created, 0), time.Unix(updated, 0)
	return s, nil
}

func ipsJSON(ips []string) string {
	if ips == nil {
		ips = []string{}
	}
	b, _ := json.Marshal(ips)
	return string(b)
}

// InsertServer stores a new server row.
func (st *Store) InsertServer(ctx context.Context, s *Server) error {
	now := time.Now().Unix()
	res, err := st.db.ExecContext(ctx, `INSERT INTO db_servers(engine, image, edition, product_key_sealed, memory_mb,
		external, allow_ips, sa_sealed, status, created_at, updated_at) VALUES (?,?,?,?,?,?,?,?,?,?,?)`,
		s.Engine, s.Image, s.Edition, s.ProductKeySealed, s.MemoryMB, s.External, ipsJSON(s.AllowIPs), s.SASealed, s.Status, now, now)
	if err != nil {
		return err
	}
	s.ID, _ = res.LastInsertId()
	return nil
}

// DeleteServer removes the server row (only when it never got logins).
func (st *Store) DeleteServer(ctx context.Context, id int64) error {
	_, err := st.db.ExecContext(ctx, `DELETE FROM db_servers WHERE id=?`, id)
	return err
}

// SetServerStatus updates status and last_error.
func (st *Store) SetServerStatus(ctx context.Context, id int64, status, lastErr string) error {
	_, err := st.db.ExecContext(ctx, `UPDATE db_servers SET status=?, last_error=?, updated_at=? WHERE id=?`,
		status, lastErr, time.Now().Unix(), id)
	return err
}

// UpdateServerSettings stores memory and external access settings.
func (st *Store) UpdateServerSettings(ctx context.Context, s Server) error {
	_, err := st.db.ExecContext(ctx, `UPDATE db_servers SET memory_mb=?, external=?, allow_ips=?, updated_at=? WHERE id=?`,
		s.MemoryMB, s.External, ipsJSON(s.AllowIPs), time.Now().Unix(), s.ID)
	return err
}

// SetSAPending records a new SA password before it is applied on the server.
func (st *Store) SetSAPending(ctx context.Context, id int64, sealed string) error {
	_, err := st.db.ExecContext(ctx, `UPDATE db_servers SET sa_pending_sealed=?, updated_at=? WHERE id=?`, sealed, time.Now().Unix(), id)
	return err
}

// PromoteSA makes the pending SA password the current one.
func (st *Store) PromoteSA(ctx context.Context, id int64) error {
	_, err := st.db.ExecContext(ctx, `UPDATE db_servers SET sa_sealed=sa_pending_sealed, sa_pending_sealed='', updated_at=?
		WHERE id=? AND sa_pending_sealed<>''`, time.Now().Unix(), id)
	return err
}

// ClearSAPending drops a pending password that was never applied.
func (st *Store) ClearSAPending(ctx context.Context, id int64) error {
	return st.SetSAPending(ctx, id, "")
}

// --- logins ---

const loginCols = `l.id, l.server_id, l.customer_id, c.name, l.name, l.password_sealed, l.disabled, l.created_at,
	(SELECT COUNT(*) FROM databases d WHERE d.login_id = l.id)`

func scanLogin(sc interface{ Scan(...any) error }) (Login, error) {
	var l Login
	var created int64
	err := sc.Scan(&l.ID, &l.ServerID, &l.CustomerID, &l.CustomerName, &l.Name, &l.PasswordSealed, &l.Disabled, &created, &l.DBCount)
	l.CreatedAt = time.Unix(created, 0)
	return l, err
}

// Login returns a login by id.
func (st *Store) Login(ctx context.Context, id int64) (Login, error) {
	return scanLogin(st.db.QueryRowContext(ctx, `SELECT `+loginCols+` FROM db_logins l JOIN customers c ON c.id = l.customer_id WHERE l.id=?`, id))
}

// LoginForCustomer returns the customer's login (sql.ErrNoRows if none).
func (st *Store) LoginForCustomer(ctx context.Context, customerID int64) (Login, error) {
	return scanLogin(st.db.QueryRowContext(ctx, `SELECT `+loginCols+` FROM db_logins l JOIN customers c ON c.id = l.customer_id WHERE l.customer_id=?`, customerID))
}

// Logins lists all logins.
func (st *Store) Logins(ctx context.Context) ([]Login, error) {
	rows, err := st.db.QueryContext(ctx, `SELECT `+loginCols+` FROM db_logins l JOIN customers c ON c.id = l.customer_id ORDER BY c.name, l.name`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Login
	for rows.Next() {
		l, err := scanLogin(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, l)
	}
	return out, rows.Err()
}

// LoginNameTaken reports whether name is used by a login.
func (st *Store) LoginNameTaken(ctx context.Context, name string) bool {
	var n int
	st.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM db_logins WHERE name=?`, name).Scan(&n)
	return n > 0
}

// InsertLogin stores a login.
func (st *Store) InsertLogin(ctx context.Context, l *Login) error {
	now := time.Now().Unix()
	res, err := st.db.ExecContext(ctx, `INSERT INTO db_logins(server_id, customer_id, name, password_sealed, disabled, created_at, updated_at)
		VALUES (?,?,?,?,0,?,?)`, l.ServerID, l.CustomerID, l.Name, l.PasswordSealed, now, now)
	if err != nil {
		return err
	}
	l.ID, _ = res.LastInsertId()
	return nil
}

// SetLoginPassword stores a new sealed password.
func (st *Store) SetLoginPassword(ctx context.Context, id int64, sealed string) error {
	_, err := st.db.ExecContext(ctx, `UPDATE db_logins SET password_sealed=?, updated_at=? WHERE id=?`, sealed, time.Now().Unix(), id)
	return err
}

// SetLoginDisabled stores the enabled flag.
func (st *Store) SetLoginDisabled(ctx context.Context, id int64, disabled bool) error {
	_, err := st.db.ExecContext(ctx, `UPDATE db_logins SET disabled=?, updated_at=? WHERE id=?`, disabled, time.Now().Unix(), id)
	return err
}

// ErrLoginHasDatabases prevents dropping a login that still owns databases.
var ErrLoginHasDatabases = errors.New("login'in veritabanları var; önce veritabanlarını silin")

// DeleteLogin removes the login row.
func (st *Store) DeleteLogin(ctx context.Context, id int64) error {
	_, err := st.db.ExecContext(ctx, `DELETE FROM db_logins WHERE id=?`, id)
	return err
}

// --- databases ---

const dbCols = `d.id, d.server_id, d.customer_id, c.name, d.login_id, l.name, COALESCE(d.site_id, 0), COALESCE(s.domain, ''),
	d.name, d.env_key, d.status, d.size_bytes, d.size_at, d.created_at`

const dbFrom = ` FROM databases d JOIN customers c ON c.id = d.customer_id JOIN db_logins l ON l.id = d.login_id
	LEFT JOIN sites s ON s.id = d.site_id`

func scanDB(sc interface{ Scan(...any) error }) (Database, error) {
	var d Database
	var sizeAt, created int64
	err := sc.Scan(&d.ID, &d.ServerID, &d.CustomerID, &d.CustomerName, &d.LoginID, &d.LoginName, &d.SiteID, &d.SiteDomain,
		&d.Name, &d.EnvKey, &d.Status, &d.SizeBytes, &sizeAt, &created)
	if sizeAt > 0 {
		d.SizeAt = time.Unix(sizeAt, 0)
	}
	d.CreatedAt = time.Unix(created, 0)
	return d, err
}

// Database returns a database by id.
func (st *Store) Database(ctx context.Context, id int64) (Database, error) {
	return scanDB(st.db.QueryRowContext(ctx, `SELECT `+dbCols+dbFrom+` WHERE d.id=?`, id))
}

// DBFilter narrows Databases.
type DBFilter struct {
	CustomerID int64
	SiteID     int64
	LoginID    int64
}

// Databases lists databases, optionally filtered.
func (st *Store) Databases(ctx context.Context, f DBFilter) ([]Database, error) {
	q := `SELECT ` + dbCols + dbFrom + ` WHERE 1=1`
	var args []any
	if f.CustomerID > 0 {
		q += ` AND d.customer_id=?`
		args = append(args, f.CustomerID)
	}
	if f.SiteID > 0 {
		q += ` AND d.site_id=?`
		args = append(args, f.SiteID)
	}
	if f.LoginID > 0 {
		q += ` AND d.login_id=?`
		args = append(args, f.LoginID)
	}
	rows, err := st.db.QueryContext(ctx, q+` ORDER BY d.name`, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Database
	for rows.Next() {
		d, err := scanDB(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, d)
	}
	return out, rows.Err()
}

// DBNameTaken reports whether a database name is used.
func (st *Store) DBNameTaken(ctx context.Context, name string) bool {
	var n int
	st.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM databases WHERE name=?`, name).Scan(&n)
	return n > 0
}

func nullID(id int64) any {
	if id == 0 {
		return nil
	}
	return id
}

// InsertDatabase stores a database row.
func (st *Store) InsertDatabase(ctx context.Context, d *Database) error {
	res, err := st.db.ExecContext(ctx, `INSERT INTO databases(server_id, customer_id, login_id, site_id, name, env_key, status, created_at)
		VALUES (?,?,?,?,?,?,?,?)`, d.ServerID, d.CustomerID, d.LoginID, nullID(d.SiteID), d.Name, d.EnvKey, d.Status, time.Now().Unix())
	if err != nil {
		return err
	}
	d.ID, _ = res.LastInsertId()
	return nil
}

// SetDBStatus updates a database's status.
func (st *Store) SetDBStatus(ctx context.Context, id int64, status string) error {
	_, err := st.db.ExecContext(ctx, `UPDATE databases SET status=? WHERE id=?`, status, id)
	return err
}

// SetDBEnvKey records which site env variable holds the connection string.
func (st *Store) SetDBEnvKey(ctx context.Context, id int64, key string) error {
	_, err := st.db.ExecContext(ctx, `UPDATE databases SET env_key=? WHERE id=?`, key, id)
	return err
}

// SetDBSite links a database to a site.
func (st *Store) SetDBSite(ctx context.Context, id, siteID int64) error {
	_, err := st.db.ExecContext(ctx, `UPDATE databases SET site_id=? WHERE id=?`, nullID(siteID), id)
	return err
}

// SetSizes stores sizes by database name.
func (st *Store) SetSizes(ctx context.Context, sizes map[string]int64) error {
	now := time.Now().Unix()
	for name, n := range sizes {
		if _, err := st.db.ExecContext(ctx, `UPDATE databases SET size_bytes=?, size_at=? WHERE name=?`, n, now, name); err != nil {
			return err
		}
	}
	return nil
}

// DeleteDatabase removes the row.
func (st *Store) DeleteDatabase(ctx context.Context, id int64) error {
	_, err := st.db.ExecContext(ctx, `DELETE FROM databases WHERE id=?`, id)
	return err
}

// CountForCustomer counts a customer's databases.
func (st *Store) CountForCustomer(ctx context.Context, customerID int64) int {
	var n int
	st.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM databases WHERE customer_id=?`, customerID).Scan(&n)
	return n
}

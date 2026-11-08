package pgsql

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"time"
)

// Server states (same values as the MSSQL server).
const (
	StatusInstalling = "installing"
	StatusRunning    = "running"
	StatusStopped    = "stopped"
	StatusError      = "error"
)

// Database states.
const (
	DBCreating = "creating"
	DBReady    = "ready"
	DBError    = "error"
	DBDropping = "dropping"
)

// Server is the (single) PostgreSQL container.
type Server struct {
	ID        int64
	Image     string
	MemoryMB  int
	External  bool
	AllowIPs  []string
	Version   string
	Status    string
	LastError string
	CreatedAt time.Time
	UpdatedAt time.Time
}

// Role is a customer's login role.
type Role struct {
	ID             int64
	CustomerID     int64
	CustomerName   string
	Name           string
	PasswordSealed string
	Disabled       bool
	CreatedAt      time.Time
	DBCount        int
}

// Database is a database owned by a customer's role.
type Database struct {
	ID           int64
	CustomerID   int64
	CustomerName string
	RoleID       int64
	RoleName     string
	SiteID       int64 // 0 = not linked
	SiteDomain   string
	Name         string
	EnvKey       string
	Status       string
	SizeBytes    int64
	SizeAt       time.Time
	CreatedAt    time.Time
}

// Store is the panel-side record of the server, roles and databases.
type Store struct{ db *sql.DB }

// NewStore returns a Store on db.
func NewStore(db *sql.DB) *Store { return &Store{db: db} }

const serverCols = `id, image, memory_mb, external, allow_ips, version, status, last_error, created_at, updated_at`

// Server returns the server; sql.ErrNoRows if none is installed.
func (st *Store) Server(ctx context.Context) (Server, error) {
	var s Server
	var ips string
	var created, updated int64
	err := st.db.QueryRowContext(ctx, `SELECT `+serverCols+` FROM pg_servers ORDER BY id LIMIT 1`).Scan(
		&s.ID, &s.Image, &s.MemoryMB, &s.External, &ips, &s.Version, &s.Status, &s.LastError, &created, &updated)
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
	res, err := st.db.ExecContext(ctx, `INSERT INTO pg_servers(image, memory_mb, external, allow_ips, status, created_at, updated_at)
		VALUES (?,?,?,?,?,?,?)`, s.Image, s.MemoryMB, s.External, ipsJSON(s.AllowIPs), s.Status, now, now)
	if err != nil {
		return err
	}
	s.ID, _ = res.LastInsertId()
	return nil
}

// DeleteServer removes the server row.
func (st *Store) DeleteServer(ctx context.Context, id int64) error {
	_, err := st.db.ExecContext(ctx, `DELETE FROM pg_servers WHERE id=?`, id)
	return err
}

// SetServerStatus records the state (and the last error, "" when fine).
func (st *Store) SetServerStatus(ctx context.Context, id int64, status, lastErr string) error {
	_, err := st.db.ExecContext(ctx, `UPDATE pg_servers SET status=?, last_error=?, updated_at=? WHERE id=?`,
		status, lastErr, time.Now().Unix(), id)
	return err
}

// SetVersion records server_version.
func (st *Store) SetVersion(ctx context.Context, id int64, v string) error {
	_, err := st.db.ExecContext(ctx, `UPDATE pg_servers SET version=? WHERE id=?`, v, id)
	return err
}

// UpdateServerSettings stores memory and external access.
func (st *Store) UpdateServerSettings(ctx context.Context, s Server) error {
	_, err := st.db.ExecContext(ctx, `UPDATE pg_servers SET memory_mb=?, external=?, allow_ips=?, updated_at=? WHERE id=?`,
		s.MemoryMB, s.External, ipsJSON(s.AllowIPs), time.Now().Unix(), s.ID)
	return err
}

// --- roles ---

const roleCols = `r.id, r.customer_id, c.name, r.name, r.password_sealed, r.disabled, r.created_at,
	(SELECT COUNT(*) FROM pg_databases d WHERE d.role_id = r.id)`

const roleFrom = ` FROM pg_roles r JOIN customers c ON c.id = r.customer_id`

func scanRole(sc interface{ Scan(...any) error }) (Role, error) {
	var r Role
	var created int64
	err := sc.Scan(&r.ID, &r.CustomerID, &r.CustomerName, &r.Name, &r.PasswordSealed, &r.Disabled, &created, &r.DBCount)
	r.CreatedAt = time.Unix(created, 0)
	return r, err
}

// Role returns a role by id.
func (st *Store) Role(ctx context.Context, id int64) (Role, error) {
	return scanRole(st.db.QueryRowContext(ctx, `SELECT `+roleCols+roleFrom+` WHERE r.id=?`, id))
}

// RoleForCustomer returns the customer's role (sql.ErrNoRows if none).
func (st *Store) RoleForCustomer(ctx context.Context, customerID int64) (Role, error) {
	return scanRole(st.db.QueryRowContext(ctx, `SELECT `+roleCols+roleFrom+` WHERE r.customer_id=?`, customerID))
}

// Roles lists all roles.
func (st *Store) Roles(ctx context.Context) ([]Role, error) {
	rows, err := st.db.QueryContext(ctx, `SELECT `+roleCols+roleFrom+` ORDER BY c.name, r.name`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Role
	for rows.Next() {
		r, err := scanRole(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

// RoleNameTaken reports whether name is used by a role.
func (st *Store) RoleNameTaken(ctx context.Context, name string) bool {
	var n int
	st.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM pg_roles WHERE name=?`, name).Scan(&n)
	return n > 0
}

// InsertRole stores a role.
func (st *Store) InsertRole(ctx context.Context, r *Role) error {
	now := time.Now().Unix()
	res, err := st.db.ExecContext(ctx, `INSERT INTO pg_roles(customer_id, name, password_sealed, disabled, created_at, updated_at)
		VALUES (?,?,?,0,?,?)`, r.CustomerID, r.Name, r.PasswordSealed, now, now)
	if err != nil {
		return err
	}
	r.ID, _ = res.LastInsertId()
	return nil
}

// SetRolePassword stores a new sealed password.
func (st *Store) SetRolePassword(ctx context.Context, id int64, sealed string) error {
	_, err := st.db.ExecContext(ctx, `UPDATE pg_roles SET password_sealed=?, updated_at=? WHERE id=?`, sealed, time.Now().Unix(), id)
	return err
}

// SetRoleDisabled stores the enabled flag.
func (st *Store) SetRoleDisabled(ctx context.Context, id int64, disabled bool) error {
	_, err := st.db.ExecContext(ctx, `UPDATE pg_roles SET disabled=?, updated_at=? WHERE id=?`, disabled, time.Now().Unix(), id)
	return err
}

// ErrRoleHasDatabases prevents dropping a role that still owns databases.
var ErrRoleHasDatabases = errors.New("rolün veritabanları var; önce veritabanlarını silin")

// DeleteRole removes the role row.
func (st *Store) DeleteRole(ctx context.Context, id int64) error {
	_, err := st.db.ExecContext(ctx, `DELETE FROM pg_roles WHERE id=?`, id)
	return err
}

// --- databases ---

const dbCols = `d.id, d.customer_id, c.name, d.role_id, r.name, COALESCE(d.site_id, 0), COALESCE(s.domain, ''),
	d.name, d.env_key, d.status, d.size_bytes, d.size_at, d.created_at`

const dbFrom = ` FROM pg_databases d JOIN customers c ON c.id = d.customer_id JOIN pg_roles r ON r.id = d.role_id
	LEFT JOIN sites s ON s.id = d.site_id`

func scanDB(sc interface{ Scan(...any) error }) (Database, error) {
	var d Database
	var sizeAt, created int64
	err := sc.Scan(&d.ID, &d.CustomerID, &d.CustomerName, &d.RoleID, &d.RoleName, &d.SiteID, &d.SiteDomain,
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

// DatabaseByName returns a database by name.
func (st *Store) DatabaseByName(ctx context.Context, name string) (Database, error) {
	return scanDB(st.db.QueryRowContext(ctx, `SELECT `+dbCols+dbFrom+` WHERE d.name=?`, name))
}

// DBFilter narrows Databases.
type DBFilter struct {
	CustomerID int64
	SiteID     int64
	RoleID     int64
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
	if f.RoleID > 0 {
		q += ` AND d.role_id=?`
		args = append(args, f.RoleID)
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
	st.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM pg_databases WHERE name=?`, name).Scan(&n)
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
	res, err := st.db.ExecContext(ctx, `INSERT INTO pg_databases(customer_id, role_id, site_id, name, env_key, status, created_at)
		VALUES (?,?,?,?,?,?,?)`, d.CustomerID, d.RoleID, nullID(d.SiteID), d.Name, d.EnvKey, d.Status, time.Now().Unix())
	if err != nil {
		return err
	}
	d.ID, _ = res.LastInsertId()
	return nil
}

// SetDBStatus updates a database's status.
func (st *Store) SetDBStatus(ctx context.Context, id int64, status string) error {
	_, err := st.db.ExecContext(ctx, `UPDATE pg_databases SET status=? WHERE id=?`, status, id)
	return err
}

// SetDBEnvKey records which site env variable holds the connection string.
func (st *Store) SetDBEnvKey(ctx context.Context, id int64, key string) error {
	_, err := st.db.ExecContext(ctx, `UPDATE pg_databases SET env_key=? WHERE id=?`, key, id)
	return err
}

// SetDBSite links a database to a site.
func (st *Store) SetDBSite(ctx context.Context, id, siteID int64) error {
	_, err := st.db.ExecContext(ctx, `UPDATE pg_databases SET site_id=? WHERE id=?`, nullID(siteID), id)
	return err
}

// SetSizes stores sizes by database name.
func (st *Store) SetSizes(ctx context.Context, sizes map[string]int64) error {
	now := time.Now().Unix()
	for name, n := range sizes {
		if _, err := st.db.ExecContext(ctx, `UPDATE pg_databases SET size_bytes=?, size_at=? WHERE name=?`, n, now, name); err != nil {
			return err
		}
	}
	return nil
}

// DeleteDatabase removes the row.
func (st *Store) DeleteDatabase(ctx context.Context, id int64) error {
	_, err := st.db.ExecContext(ctx, `DELETE FROM pg_databases WHERE id=?`, id)
	return err
}

// CountForCustomer counts a customer's databases.
func (st *Store) CountForCustomer(ctx context.Context, customerID int64) int {
	var n int
	st.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM pg_databases WHERE customer_id=?`, customerID).Scan(&n)
	return n
}

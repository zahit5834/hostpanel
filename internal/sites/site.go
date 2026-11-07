// Package sites implements site provisioning, deployment and lifecycle.
package sites

import (
	"context"
	"database/sql"
	"encoding/json"
	"path"
	"time"
)

// Site statuses.
const (
	StatusProvisioning   = "provisioning"
	StatusAwaitingDeploy = "awaiting_deploy"
	StatusRunning        = "running"
	StatusStopped        = "stopped"
	StatusMaintenance    = "maintenance"
	StatusDisabled       = "disabled"
	StatusError          = "error"
	StatusDeleting       = "deleting"
)

// www handling.
const (
	WWWNone   = "none"
	WWWToWWW  = "to_www"
	WWWToApex = "to_apex"
)

// SitesRoot is where site directories live on the server.
const SitesRoot = "/var/www/sites"

// Site is one hosted website.
type Site struct {
	ID             int64
	CustomerID     int64
	CustomerName   string
	Domain         string
	ShortName      string
	Aliases        []string
	WWWMode        string
	RuntimeID      string
	RuntimeVersion string
	Fields         map[string]string
	Port           int
	MemoryMaxMB    int
	CPUQuotaPct    int
	Status         string
	PersistentDirs []string
	HealthPath     string
	MaxUploadMB    int
	Gzip           bool
	HSTS           bool
	ForceHTTPS     bool
	CustomSnippet  string
	CreatedAt      time.Time
	UpdatedAt      time.Time
}

// User is the site's Linux account.
func (s Site) User() string { return "site_" + s.ShortName }

// Unit is the systemd unit name (without .service).
func (s Site) Unit() string { return "hp-site-" + s.ShortName }

// Dir is the site's root directory.
func (s Site) Dir() string { return path.Join(SitesRoot, s.Domain) }

// HostNames returns every name the site answers to: domain, www (unless the
// www mode is "none") and aliases.
func (s Site) HostNames() []string {
	names := []string{s.Domain}
	if s.WWWMode != WWWNone {
		names = append(names, s.WWWName())
	}
	return append(names, s.Aliases...)
}

// WWWName returns the www. variant of the domain.
func (s Site) WWWName() string { return "www." + s.Domain }

// Release is one deployed version.
type Release struct {
	ID        int64
	SiteID    int64
	Name      string
	Size      int64
	Status    string
	JobID     int64
	CreatedAt time.Time
	Source    string // zip | git | backup
	Commit    string // git commit SHA (git releases)
}

// Release sources.
const (
	SourceZip    = "zip"
	SourceGit    = "git"
	SourceBackup = "backup"
)

// ShortCommit is the first 7 characters of the commit.
func (r Release) ShortCommit() string {
	if len(r.Commit) > 7 {
		return r.Commit[:7]
	}
	return r.Commit
}

// Release statuses.
const (
	ReleaseActive   = "active"
	ReleasePrevious = "previous"
	ReleaseFailed   = "failed"
	ReleasePruned   = "pruned"
)

// PlaceholderRelease holds the "coming soon" page until the first deploy.
const PlaceholderRelease = "00000000-000000"

// Store is the sites data access layer.
type Store struct{ db *sql.DB }

// NewStore wraps db.
func NewStore(db *sql.DB) *Store { return &Store{db: db} }

const siteCols = `s.id, s.customer_id, c.name, s.domain, s.short_name, s.aliases, s.www_mode, s.runtime_id, s.runtime_version,
	s.fields, COALESCE(s.port,0), s.memory_max_mb, s.cpu_quota_pct, s.status, s.persistent_dirs, s.health_path,
	s.max_upload_mb, s.gzip, s.hsts, s.force_https, s.custom_snippet, s.created_at, s.updated_at`

func scanSite(sc interface{ Scan(...any) error }) (Site, error) {
	var s Site
	var aliases, fields, dirs string
	var created, updated int64
	err := sc.Scan(&s.ID, &s.CustomerID, &s.CustomerName, &s.Domain, &s.ShortName, &aliases, &s.WWWMode, &s.RuntimeID,
		&s.RuntimeVersion, &fields, &s.Port, &s.MemoryMaxMB, &s.CPUQuotaPct, &s.Status, &dirs, &s.HealthPath,
		&s.MaxUploadMB, &s.Gzip, &s.HSTS, &s.ForceHTTPS, &s.CustomSnippet, &created, &updated)
	if err != nil {
		return s, err
	}
	json.Unmarshal([]byte(aliases), &s.Aliases)
	json.Unmarshal([]byte(fields), &s.Fields)
	json.Unmarshal([]byte(dirs), &s.PersistentDirs)
	if s.Fields == nil {
		s.Fields = map[string]string{}
	}
	s.CreatedAt, s.UpdatedAt = time.Unix(created, 0), time.Unix(updated, 0)
	return s, nil
}

// Get loads a site by id.
func (st *Store) Get(ctx context.Context, id int64) (Site, error) {
	return scanSite(st.db.QueryRowContext(ctx, `SELECT `+siteCols+` FROM sites s JOIN customers c ON c.id=s.customer_id WHERE s.id=?`, id))
}

// GetByDomain loads a site by domain.
func (st *Store) GetByDomain(ctx context.Context, domain string) (Site, error) {
	return scanSite(st.db.QueryRowContext(ctx, `SELECT `+siteCols+` FROM sites s JOIN customers c ON c.id=s.customer_id WHERE s.domain=?`, domain))
}

// List returns sites, optionally only those of one customer.
func (st *Store) List(ctx context.Context, customerID int64) ([]Site, error) {
	q := `SELECT ` + siteCols + ` FROM sites s JOIN customers c ON c.id=s.customer_id`
	var args []any
	if customerID > 0 {
		q += ` WHERE s.customer_id=?`
		args = append(args, customerID)
	}
	q += ` ORDER BY s.domain`
	rows, err := st.db.QueryContext(ctx, q, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Site
	for rows.Next() {
		s, err := scanSite(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, s)
	}
	return out, rows.Err()
}

func jsonStr(v any) string {
	b, _ := json.Marshal(v)
	return string(b)
}

func nullPort(p int) any {
	if p == 0 {
		return nil
	}
	return p
}

// Insert creates the row and sets s.ID.
func (st *Store) Insert(ctx context.Context, s *Site) error {
	now := time.Now().Unix()
	res, err := st.db.ExecContext(ctx, `INSERT INTO sites(customer_id, domain, short_name, aliases, www_mode, runtime_id,
		runtime_version, fields, port, memory_max_mb, cpu_quota_pct, status, persistent_dirs, health_path, max_upload_mb,
		gzip, hsts, force_https, custom_snippet, created_at, updated_at) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`,
		s.CustomerID, s.Domain, s.ShortName, jsonStr(s.Aliases), s.WWWMode, s.RuntimeID, s.RuntimeVersion, jsonStr(s.Fields),
		nullPort(s.Port), s.MemoryMaxMB, s.CPUQuotaPct, s.Status, jsonStr(s.PersistentDirs), s.HealthPath, s.MaxUploadMB,
		s.Gzip, s.HSTS, s.ForceHTTPS, s.CustomSnippet, now, now)
	if err != nil {
		return err
	}
	s.ID, _ = res.LastInsertId()
	return nil
}

// UpdateSettings saves editable settings (not identity fields).
func (st *Store) UpdateSettings(ctx context.Context, s Site) error {
	_, err := st.db.ExecContext(ctx, `UPDATE sites SET aliases=?, www_mode=?, runtime_version=?, fields=?, memory_max_mb=?,
		cpu_quota_pct=?, persistent_dirs=?, health_path=?, max_upload_mb=?, gzip=?, hsts=?, force_https=?, custom_snippet=?,
		updated_at=? WHERE id=?`, jsonStr(s.Aliases), s.WWWMode, s.RuntimeVersion, jsonStr(s.Fields), s.MemoryMaxMB,
		s.CPUQuotaPct, jsonStr(s.PersistentDirs), s.HealthPath, s.MaxUploadMB, s.Gzip, s.HSTS, s.ForceHTTPS, s.CustomSnippet,
		time.Now().Unix(), s.ID)
	return err
}

// SetStatus updates the lifecycle status.
func (st *Store) SetStatus(ctx context.Context, id int64, status string) error {
	_, err := st.db.ExecContext(ctx, `UPDATE sites SET status=?, updated_at=? WHERE id=?`, status, time.Now().Unix(), id)
	return err
}

// Delete removes the site row (env and releases cascade).
func (st *Store) Delete(ctx context.Context, id int64) error {
	_, err := st.db.ExecContext(ctx, `DELETE FROM sites WHERE id=?`, id)
	return err
}

// UsedPorts returns all ports assigned to sites.
func (st *Store) UsedPorts(ctx context.Context) (map[int]bool, error) {
	rows, err := st.db.QueryContext(ctx, `SELECT port FROM sites WHERE port IS NOT NULL`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := map[int]bool{}
	for rows.Next() {
		var p int
		rows.Scan(&p)
		out[p] = true
	}
	return out, rows.Err()
}

// ShortNameTaken reports whether a short name is in use.
func (st *Store) ShortNameTaken(ctx context.Context, short string) bool {
	var n int
	st.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM sites WHERE short_name=?`, short).Scan(&n)
	return n > 0
}

// CountByRuntimeVersion counts sites using runtime+version (blocks uninstall).
func (st *Store) CountByRuntimeVersion(ctx context.Context, runtimeID, version string) int {
	var n int
	st.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM sites WHERE runtime_id=? AND runtime_version=?`, runtimeID, version).Scan(&n)
	return n
}

// --- releases ---

// AddRelease records a new release.
func (st *Store) AddRelease(ctx context.Context, r *Release) error {
	if r.Source == "" {
		r.Source = SourceZip
	}
	res, err := st.db.ExecContext(ctx, `INSERT INTO releases(site_id, name, size, status, job_id, created_at, source, commit_sha) VALUES (?,?,?,?,?,?,?,?)`,
		r.SiteID, r.Name, r.Size, r.Status, r.JobID, time.Now().Unix(), r.Source, r.Commit)
	if err != nil {
		return err
	}
	r.ID, _ = res.LastInsertId()
	return nil
}

// SetReleaseCommit stores the git commit of a release.
func (st *Store) SetReleaseCommit(ctx context.Context, siteID int64, name, sha string) error {
	_, err := st.db.ExecContext(ctx, `UPDATE releases SET commit_sha=? WHERE site_id=? AND name=?`, sha, siteID, name)
	return err
}

// Releases lists a site's releases newest first.
func (st *Store) Releases(ctx context.Context, siteID int64) ([]Release, error) {
	rows, err := st.db.QueryContext(ctx, `SELECT id, site_id, name, size, status, COALESCE(job_id,0), created_at, source, commit_sha
		FROM releases WHERE site_id=? ORDER BY name DESC`, siteID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Release
	for rows.Next() {
		var r Release
		var c int64
		if err := rows.Scan(&r.ID, &r.SiteID, &r.Name, &r.Size, &r.Status, &r.JobID, &c, &r.Source, &r.Commit); err != nil {
			return nil, err
		}
		r.CreatedAt = time.Unix(c, 0)
		out = append(out, r)
	}
	return out, rows.Err()
}

// ActiveRelease returns the current release name ("" if none).
func (st *Store) ActiveRelease(ctx context.Context, siteID int64) string {
	var n string
	st.db.QueryRowContext(ctx, `SELECT name FROM releases WHERE site_id=? AND status=?`, siteID, ReleaseActive).Scan(&n)
	return n
}

// MarkActive makes name the active release and demotes the previous one.
func (st *Store) MarkActive(ctx context.Context, siteID int64, name string) error {
	tx, err := st.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if _, err := tx.ExecContext(ctx, `UPDATE releases SET status=? WHERE site_id=? AND status=?`, ReleasePrevious, siteID, ReleaseActive); err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, `UPDATE releases SET status=? WHERE site_id=? AND name=?`, ReleaseActive, siteID, name); err != nil {
		return err
	}
	return tx.Commit()
}

// SetReleaseStatus updates one release.
func (st *Store) SetReleaseStatus(ctx context.Context, siteID int64, name, status string) {
	st.db.ExecContext(ctx, `UPDATE releases SET status=? WHERE site_id=? AND name=?`, status, siteID, name)
}

// --- env ---

// EnvSealed returns the sealed env values keyed by name.
func (st *Store) EnvSealed(ctx context.Context, siteID int64) (map[string]string, error) {
	rows, err := st.db.QueryContext(ctx, `SELECT key, value_sealed FROM site_env WHERE site_id=? ORDER BY key`, siteID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := map[string]string{}
	for rows.Next() {
		var k, v string
		rows.Scan(&k, &v)
		out[k] = v
	}
	return out, rows.Err()
}

// ReplaceEnv atomically replaces all env values of a site.
func (st *Store) ReplaceEnv(ctx context.Context, siteID int64, sealed map[string]string) error {
	tx, err := st.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if _, err := tx.ExecContext(ctx, `DELETE FROM site_env WHERE site_id=?`, siteID); err != nil {
		return err
	}
	for k, v := range sealed {
		if _, err := tx.ExecContext(ctx, `INSERT INTO site_env(site_id, key, value_sealed) VALUES (?,?,?)`, siteID, k, v); err != nil {
			return err
		}
	}
	return tx.Commit()
}

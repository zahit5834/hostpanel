package databases

import (
	"context"
	"database/sql"
	"fmt"
	"net/url"
	"strings"

	mssql "github.com/microsoft/go-mssqldb"
)

// MSSQL implements DatabaseProvider and LoginSession with go-mssqldb.
//
// DDL statements cannot take parameters, so every statement that needs a
// name is built *inside T-SQL* with QUOTENAME(@name) and run with EXEC(@sql);
// names and passwords travel as real parameters (sp_executesql). There is no
// string concatenation of user data in Go. Names are also whitelisted.
//
// A connection is opened per operation and closed right after: the panel
// keeps no idle sockets or buffers for the database server.
type MSSQL struct {
	Addr     string // host:port
	User     string
	Password string
	Database string // "" = master

	// exec replaces the server in tests: it receives the batch and its args.
	exec func(ctx context.Context, q string, args []sql.NamedArg) error
	// files replaces RESTORE FILELISTONLY in tests.
	files func(path string) ([]restoreFile, error)
}

// ServerDataDir is where restored database files are placed (inside the server).
const ServerDataDir = "/var/opt/mssql/data"

var (
	_ DatabaseProvider = (*MSSQL)(nil)
	_ LoginSession     = (*MSSQL)(nil)
)

func (m *MSSQL) open() (*sql.DB, error) {
	db := m.Database
	if db == "" {
		db = "master"
	}
	q := url.Values{}
	q.Set("database", db)
	// Loopback to a container with a self-signed certificate: encrypt, but
	// don't verify (there is no CA to verify against).
	q.Set("encrypt", "true")
	q.Set("TrustServerCertificate", "true")
	q.Set("app name", "hostpanel")
	q.Set("dial timeout", "5")
	u := url.URL{Scheme: "sqlserver", User: url.UserPassword(m.User, m.Password), Host: m.Addr, RawQuery: q.Encode()}
	c, err := mssql.NewConnector(u.String())
	if err != nil {
		return nil, err
	}
	d := sql.OpenDB(c)
	d.SetMaxOpenConns(1)
	d.SetMaxIdleConns(0)
	return d, nil
}

func (m *MSSQL) run(ctx context.Context, q string, args ...sql.NamedArg) error {
	if m.exec != nil {
		return m.exec(ctx, q, args)
	}
	d, err := m.open()
	if err != nil {
		return err
	}
	defer d.Close()
	a := make([]any, len(args))
	for i := range args {
		a[i] = args[i]
	}
	_, err = d.ExecContext(ctx, q, a...)
	return err
}

// checkName re-validates identifiers (defense in depth; QUOTENAME already
// makes them inert). Isolation-test names are allowed here.
func checkName(names ...string) error {
	for _, n := range names {
		if !nameRe.MatchString(n) || reserved[n] {
			return fmt.Errorf("geçersiz ad: %q", n)
		}
	}
	return nil
}

func checkPassword(pw string) error {
	if !ValidPassword(pw) {
		return fmt.Errorf("geçersiz şifre biçimi")
	}
	return nil
}

// Ping opens a connection and logs in.
func (m *MSSQL) Ping(ctx context.Context) error {
	if m.exec != nil {
		return m.exec(ctx, "PING", nil)
	}
	d, err := m.open()
	if err != nil {
		return err
	}
	defer d.Close()
	return d.PingContext(ctx)
}

const sqlChangeSA = `DECLARE @sql nvarchar(max) = N'ALTER LOGIN [sa] WITH PASSWORD = ' + QUOTENAME(@pw, N'''');
EXEC (@sql);`

// ChangeSA rotates the sa password (the container's initial one stays
// visible in `docker inspect`, so it is replaced right after setup).
func (m *MSSQL) ChangeSA(ctx context.Context, pw string) error {
	if err := checkPassword(pw); err != nil {
		return err
	}
	return m.run(ctx, sqlChangeSA, sql.Named("pw", pw))
}

const sqlMaxMemory = `EXEC sp_configure 'show advanced options', 1; RECONFIGURE;
EXEC sp_configure 'max server memory (MB)', @mb; RECONFIGURE;`

// SetMaxMemory sets "max server memory" (buffer pool cap, applied live).
func (m *MSSQL) SetMaxMemory(ctx context.Context, mb int) error {
	if mb < 256 || mb > 1<<20 {
		return fmt.Errorf("geçersiz bellek değeri: %d", mb)
	}
	return m.run(ctx, sqlMaxMemory, sql.Named("mb", mb))
}

// sqlCreateLogin is idempotent (a retried job finds the login and just sets
// the password). DENY VIEW ANY DATABASE hides every database except the ones
// the login owns; new databases keep guest disabled, so it cannot USE them either.
const sqlCreateLogin = `DECLARE @sql nvarchar(max);
IF SUSER_ID(@name) IS NULL
    SET @sql = N'CREATE LOGIN ' + QUOTENAME(@name) + N' WITH PASSWORD = ' + QUOTENAME(@pw, N'''') +
               N', DEFAULT_DATABASE = [master], CHECK_POLICY = ON, CHECK_EXPIRATION = OFF';
ELSE
    SET @sql = N'ALTER LOGIN ' + QUOTENAME(@name) + N' WITH PASSWORD = ' + QUOTENAME(@pw, N'''');
EXEC (@sql);
SET @sql = N'DENY VIEW ANY DATABASE TO ' + QUOTENAME(@name);
EXEC (@sql);`

// CreateLogin creates an isolated login.
func (m *MSSQL) CreateLogin(ctx context.Context, name, pw string) error {
	if err := checkName(name); err != nil {
		return err
	}
	if err := checkPassword(pw); err != nil {
		return err
	}
	return m.run(ctx, sqlCreateLogin, sql.Named("name", name), sql.Named("pw", pw))
}

// UNLOCK clears a policy lockout (too many failed logins) together with the reset.
const sqlSetPassword = `DECLARE @sql nvarchar(max) = N'ALTER LOGIN ' + QUOTENAME(@name) + N' WITH PASSWORD = ' + QUOTENAME(@pw, N'''') + N' UNLOCK';
EXEC (@sql);`

// SetPassword resets a login's password.
func (m *MSSQL) SetPassword(ctx context.Context, name, pw string) error {
	if err := checkName(name); err != nil {
		return err
	}
	if err := checkPassword(pw); err != nil {
		return err
	}
	return m.run(ctx, sqlSetPassword, sql.Named("name", name), sql.Named("pw", pw))
}

const sqlKillSessions = `DECLARE @k nvarchar(max) = N'';
SELECT @k = @k + N'KILL ' + CAST(session_id AS nvarchar(12)) + N';'
  FROM sys.dm_exec_sessions WHERE login_name = @name AND session_id <> @@SPID;
IF @k <> N'' EXEC (@k);`

const sqlEnable = `DECLARE @sql nvarchar(max) = N'ALTER LOGIN ' + QUOTENAME(@name) + N' ENABLE';
EXEC (@sql);`

const sqlDisable = `DECLARE @sql nvarchar(max) = N'ALTER LOGIN ' + QUOTENAME(@name) + N' DISABLE';
EXEC (@sql);
` + sqlKillSessions

// SetLoginEnabled enables or disables a login; disabling also ends its sessions.
func (m *MSSQL) SetLoginEnabled(ctx context.Context, name string, enabled bool) error {
	if err := checkName(name); err != nil {
		return err
	}
	q := sqlDisable
	if enabled {
		q = sqlEnable
	}
	return m.run(ctx, q, sql.Named("name", name))
}

const sqlDropLogin = `IF SUSER_ID(@name) IS NOT NULL
BEGIN
` + sqlKillSessions + `
    DECLARE @sql nvarchar(max) = N'DROP LOGIN ' + QUOTENAME(@name);
    EXEC (@sql);
END`

// DropLogin ends the login's sessions and drops it (fails while it owns databases).
func (m *MSSQL) DropLogin(ctx context.Context, name string) error {
	if err := checkName(name); err != nil {
		return err
	}
	return m.run(ctx, sqlDropLogin, sql.Named("name", name))
}

// sqlCreateDB refuses to take over an existing database owned by someone else.
const sqlCreateDB = `DECLARE @sql nvarchar(max);
IF DB_ID(@db) IS NOT NULL
BEGIN
    IF ISNULL(SUSER_SNAME((SELECT owner_sid FROM sys.databases WHERE name = @db)), N'') <> @owner
        THROW 50002, N'Bu adda başka bir sahibe ait veritabanı var', 1;
END
ELSE
BEGIN
    SET @sql = N'CREATE DATABASE ' + QUOTENAME(@db);
    EXEC (@sql);
END
SET @sql = N'ALTER AUTHORIZATION ON DATABASE::' + QUOTENAME(@db) + N' TO ' + QUOTENAME(@owner);
EXEC (@sql);
SET @sql = N'ALTER DATABASE ' + QUOTENAME(@db) + N' SET RECOVERY SIMPLE';
EXEC (@sql);`

// CreateDatabase creates db owned by owner. Recovery is SIMPLE: backups are
// full backups (Faz 4); FULL recovery without log backups only grows the log.
func (m *MSSQL) CreateDatabase(ctx context.Context, db, owner string) error {
	if err := checkName(db, owner); err != nil {
		return err
	}
	return m.run(ctx, sqlCreateDB, sql.Named("db", db), sql.Named("owner", owner))
}

// BACKUP accepts variables for both the database and the device, so no dynamic SQL.
// Express has no backup compression.
const sqlBackup = `BACKUP DATABASE @db TO DISK = @path WITH COPY_ONLY, INIT, CHECKSUM;`

const sqlDrop = `DECLARE @sql nvarchar(max);
IF DB_ID(@db) IS NOT NULL
BEGIN
    IF @path <> N'' BACKUP DATABASE @db TO DISK = @path WITH COPY_ONLY, INIT, CHECKSUM;
    SET @sql = N'ALTER DATABASE ' + QUOTENAME(@db) + N' SET SINGLE_USER WITH ROLLBACK IMMEDIATE';
    EXEC (@sql);
    SET @sql = N'DROP DATABASE ' + QUOTENAME(@db);
    EXEC (@sql);
END`

// Drop backs up (optional) and drops db. A failed backup aborts the drop.
func (m *MSSQL) Drop(ctx context.Context, db, backupPath string) error {
	if err := checkName(db); err != nil {
		return err
	}
	if backupPath != "" && !ValidBackupPath(backupPath) {
		return fmt.Errorf("geçersiz yedek yolu: %s", backupPath)
	}
	return m.run(ctx, sqlDrop, sql.Named("db", db), sql.Named("path", backupPath))
}

// Backup writes a COPY_ONLY full backup to path (inside the server).
func (m *MSSQL) Backup(ctx context.Context, db, path string) error {
	if err := checkName(db); err != nil {
		return err
	}
	if !ValidBackupPath(path) {
		return fmt.Errorf("geçersiz yedek yolu: %s", path)
	}
	return m.run(ctx, sqlBackup, sql.Named("db", db), sql.Named("path", path))
}

// VerifyBackup checks that the backup set is complete and readable (and its
// page checksums, when it was taken WITH CHECKSUM).
func (m *MSSQL) VerifyBackup(ctx context.Context, path string) error {
	if !ValidBackupPath(path) {
		return fmt.Errorf("geçersiz yedek yolu: %s", path)
	}
	return m.run(ctx, `RESTORE VERIFYONLY FROM DISK = @path`, sql.Named("path", path))
}

// restoreFile is one row of RESTORE FILELISTONLY.
type restoreFile struct {
	Logical string
	Type    string // D data, L log (S filestream / F full-text are not supported)
}

// restorePlan maps the backup's files to physical paths for db.
func restorePlan(db string, files []restoreFile) ([]string, error) {
	if len(files) == 0 {
		return nil, fmt.Errorf("yedekte dosya bulunamadı")
	}
	var out []string
	nd, nl := 0, 0
	for _, f := range files {
		switch f.Type {
		case "D":
			nd++
			if nd == 1 {
				out = append(out, ServerDataDir+"/"+db+".mdf")
			} else {
				out = append(out, fmt.Sprintf("%s/%s_%d.ndf", ServerDataDir, db, nd))
			}
		case "L":
			nl++
			if nl == 1 {
				out = append(out, ServerDataDir+"/"+db+"_log.ldf")
			} else {
				out = append(out, fmt.Sprintf("%s/%s_log%d.ldf", ServerDataDir, db, nl))
			}
		default:
			return nil, fmt.Errorf("desteklenmeyen dosya türü (%s): FILESTREAM/full-text içeren yedekler geri yüklenemez", f.Type)
		}
	}
	return out, nil
}

// restoreSQL builds the restore batch for n files. The text contains only
// fixed keywords and numbered parameter names (@l1/@p1…); names and paths
// travel as parameters.
//
// After the restore: the owner's login is unmapped from any non-dbo user (it
// would block ALTER AUTHORIZATION), guest loses CONNECT (a restored database
// from elsewhere might allow it, which would break customer isolation) and
// TRUSTWORTHY is forced off.
func restoreSQL(n int) string {
	var b strings.Builder
	b.WriteString(`DECLARE @sql nvarchar(max);
IF DB_ID(@db) IS NOT NULL
BEGIN
    SET @sql = N'ALTER DATABASE ' + QUOTENAME(@db) + N' SET SINGLE_USER WITH ROLLBACK IMMEDIATE';
    EXEC (@sql);
END
RESTORE DATABASE @db FROM DISK = @path WITH REPLACE, RECOVERY`)
	for i := 1; i <= n; i++ {
		fmt.Fprintf(&b, ", MOVE @l%d TO @p%d", i, i)
	}
	b.WriteString(`;
SET @sql = N'ALTER DATABASE ' + QUOTENAME(@db) + N' SET MULTI_USER';
EXEC (@sql);
SET @sql = N'USE ' + QUOTENAME(@db) + N';
DECLARE @u sysname = (SELECT TOP 1 name FROM sys.database_principals WHERE sid = SUSER_SID(@o) AND name <> N''dbo'');
IF @u IS NOT NULL BEGIN DECLARE @d nvarchar(400) = N''DROP USER '' + QUOTENAME(@u); EXEC (@d); END
REVOKE CONNECT FROM guest;';
EXEC sp_executesql @sql, N'@o sysname', @o = @owner;
SET @sql = N'ALTER AUTHORIZATION ON DATABASE::' + QUOTENAME(@db) + N' TO ' + QUOTENAME(@owner);
EXEC (@sql);
SET @sql = N'ALTER DATABASE ' + QUOTENAME(@db) + N' SET TRUSTWORTHY OFF';
EXEC (@sql);
SET @sql = N'ALTER DATABASE ' + QUOTENAME(@db) + N' SET RECOVERY SIMPLE';
EXEC (@sql);`)
	return b.String()
}

// Restore restores path as db (REPLACE) owned by owner.
func (m *MSSQL) Restore(ctx context.Context, db, path, owner string) error {
	if err := checkName(db, owner); err != nil {
		return err
	}
	if !ValidBackupPath(path) {
		return fmt.Errorf("geçersiz yedek yolu: %s", path)
	}
	files, err := m.fileList(ctx, path)
	if err != nil {
		return fmt.Errorf("yedek dosyası okunamadı (geçerli bir SQL Server .bak mı?): %w", err)
	}
	phys, err := restorePlan(db, files)
	if err != nil {
		return err
	}
	args := []sql.NamedArg{sql.Named("db", db), sql.Named("path", path), sql.Named("owner", owner)}
	for i, f := range files {
		args = append(args, sql.Named(fmt.Sprintf("l%d", i+1), f.Logical), sql.Named(fmt.Sprintf("p%d", i+1), phys[i]))
	}
	return m.run(ctx, restoreSQL(len(files)), args...)
}

// fileList runs RESTORE FILELISTONLY; its column set differs between
// versions, so columns are looked up by name.
func (m *MSSQL) fileList(ctx context.Context, path string) ([]restoreFile, error) {
	if m.files != nil {
		return m.files(path)
	}
	d, err := m.open()
	if err != nil {
		return nil, err
	}
	defer d.Close()
	rows, err := d.QueryContext(ctx, `RESTORE FILELISTONLY FROM DISK = @path`, sql.Named("path", path))
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	cols, err := rows.Columns()
	if err != nil {
		return nil, err
	}
	li, ti := -1, -1
	for i, c := range cols {
		switch c {
		case "LogicalName":
			li = i
		case "Type":
			ti = i
		}
	}
	if li < 0 || ti < 0 {
		return nil, fmt.Errorf("FILELISTONLY çıktısı beklenmedik")
	}
	var out []restoreFile
	for rows.Next() {
		vals := make([]any, len(cols))
		raw := make([]sql.RawBytes, len(cols))
		for i := range vals {
			vals[i] = &raw[i]
		}
		if err := rows.Scan(vals...); err != nil {
			return nil, err
		}
		out = append(out, restoreFile{Logical: string(raw[li]), Type: strings.TrimSpace(string(raw[ti]))})
	}
	return out, rows.Err()
}

const sqlSizes = `SELECT d.name, CAST(SUM(CAST(mf.size AS bigint)) * 8192 AS bigint)
FROM sys.master_files mf JOIN sys.databases d ON d.database_id = mf.database_id
WHERE d.database_id > 4 GROUP BY d.name`

// GetSize returns data+log file sizes per user database in bytes.
func (m *MSSQL) GetSize(ctx context.Context) (map[string]int64, error) {
	out := map[string]int64{}
	err := m.query(ctx, sqlSizes, nil, func(rows *sql.Rows) error {
		var name string
		var n int64
		if err := rows.Scan(&name, &n); err != nil {
			return err
		}
		out[name] = n
		return nil
	})
	return out, err
}

func (m *MSSQL) query(ctx context.Context, q string, args []any, fn func(*sql.Rows) error) error {
	if m.exec != nil {
		return m.exec(ctx, q, nil)
	}
	d, err := m.open()
	if err != nil {
		return err
	}
	defer d.Close()
	rows, err := d.QueryContext(ctx, q, args...)
	if err != nil {
		return err
	}
	defer rows.Close()
	for rows.Next() {
		if err := fn(rows); err != nil {
			return err
		}
	}
	return rows.Err()
}

// --- LoginSession ---

// VisibleDatabases lists the databases this login can see.
func (m *MSSQL) VisibleDatabases(ctx context.Context) ([]string, error) {
	var out []string
	err := m.query(ctx, `SELECT name FROM sys.databases ORDER BY name`, nil, func(rows *sql.Rows) error {
		var n string
		if err := rows.Scan(&n); err != nil {
			return err
		}
		out = append(out, n)
		return nil
	})
	return out, err
}

const sqlTryAccess = `DECLARE @sql nvarchar(max) = N'SELECT COUNT(*) FROM ' + QUOTENAME(@db) + N'.sys.tables';
EXEC (@sql);`

// TryAccess reads db's catalog through a three-part name.
func (m *MSSQL) TryAccess(ctx context.Context, db string) error {
	if err := checkName(db); err != nil {
		return err
	}
	return m.run(ctx, sqlTryAccess, sql.Named("db", db))
}

const sqlWriteProbe = `CREATE TABLE dbo.hp_probe (id int NOT NULL PRIMARY KEY, v nvarchar(20) NOT NULL);
INSERT INTO dbo.hp_probe (id, v) VALUES (1, N'ok');
IF (SELECT COUNT(*) FROM dbo.hp_probe) <> 1 THROW 50003, N'probe', 1;
DROP TABLE dbo.hp_probe;`

// WriteProbe connects to db directly and creates/reads/drops a table.
func (m *MSSQL) WriteProbe(ctx context.Context, db string) error {
	if err := checkName(db); err != nil {
		return err
	}
	c := *m
	c.Database = db
	return c.run(ctx, sqlWriteProbe)
}

// IsSysadmin reports whether the session has the sysadmin role.
func (m *MSSQL) IsSysadmin(ctx context.Context) (bool, error) {
	var v int
	err := m.query(ctx, `SELECT ISNULL(IS_SRVROLEMEMBER('sysadmin'), 0)`, nil, func(rows *sql.Rows) error { return rows.Scan(&v) })
	return v == 1, err
}

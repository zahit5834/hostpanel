package backups

import (
	"context"
	"errors"
	"fmt"
	"math/rand/v2"
	"strings"
	"time"

	"github.com/zahit5834/hostpanel/internal/jobs"
	"github.com/zahit5834/hostpanel/internal/logs"
	"github.com/zahit5834/hostpanel/internal/notify"
	"github.com/zahit5834/hostpanel/internal/store"
)

// --- Y1: restore drills (download + checksums + archive/database checks) ---

const (
	// SetVerifyWeekly switches the weekly drill ("1" default, "0" off).
	SetVerifyWeekly = "backup_verify_weekly"
	setVerifyAt     = "backup_verify_at" // unix time of the last automatic drill
	verifyEvery     = 7 * 24 * time.Hour
)

// Verification is one drill result.
type Verification struct {
	ID        int64
	BackupID  int64
	Domain    string
	Name      string
	Source    string // local | remote
	Status    string // success | failed
	Detail    string
	JobID     int64
	CreatedAt time.Time
}

// Lines splits the detail into check lines.
func (v Verification) Lines() []string {
	if v.Detail == "" {
		return nil
	}
	return strings.Split(v.Detail, "\n")
}

// Verifications lists the newest drills.
func (st *Store) Verifications(ctx context.Context, limit int) ([]Verification, error) {
	rows, err := st.db.QueryContext(ctx, `SELECT id, COALESCE(backup_id, 0), domain, name, source, status, detail, job_id, created_at
		FROM backup_verifications ORDER BY id DESC LIMIT ?`, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Verification
	for rows.Next() {
		var v Verification
		var created int64
		if err := rows.Scan(&v.ID, &v.BackupID, &v.Domain, &v.Name, &v.Source, &v.Status, &v.Detail, &v.JobID, &created); err != nil {
			return nil, err
		}
		v.CreatedAt = time.Unix(created, 0)
		out = append(out, v)
	}
	return out, rows.Err()
}

func (st *Store) insertVerification(ctx context.Context, v Verification) error {
	var bid any
	if v.BackupID > 0 {
		bid = v.BackupID
	}
	_, err := st.db.ExecContext(ctx, `INSERT INTO backup_verifications(backup_id, domain, name, source, status, detail, job_id, created_at)
		VALUES(?,?,?,?,?,?,?,?)`, bid, v.Domain, v.Name, v.Source, v.Status, v.Detail, v.JobID, v.CreatedAt.Unix())
	return err
}

// purgeVerifications keeps the last 100 drills.
func (st *Store) purgeVerifications(ctx context.Context) {
	st.db.ExecContext(ctx, `DELETE FROM backup_verifications WHERE id NOT IN (SELECT id FROM backup_verifications ORDER BY id DESC LIMIT 100)`)
}

// VerifyCandidates are the newest successful backup of each site (and the
// mail server); a drill picks one at random.
func (s *Service) VerifyCandidates(ctx context.Context) ([]Backup, error) {
	all, err := s.Store.Backups(ctx, Filter{Limit: 5000})
	if err != nil {
		return nil, err
	}
	seen := map[string]bool{}
	var out []Backup
	for _, b := range all { // newest first
		if b.Status != StatusSuccess || (!b.Local && !b.Remote) || seen[b.Domain] {
			continue
		}
		seen[b.Domain] = true
		out = append(out, b)
	}
	return out, nil
}

// StartVerify queues a drill of one backup (0 = a random candidate).
func (s *Service) StartVerify(ctx context.Context, backupID int64) (int64, error) {
	var b Backup
	if backupID > 0 {
		var err error
		if b, err = s.Store.Backup(ctx, backupID); err != nil {
			return 0, errors.New("yedek bulunamadı")
		}
		if b.Status != StatusSuccess || (!b.Local && !b.Remote) {
			return 0, errors.New("yalnızca tamamlanmış ve bir kopyası duran yedek doğrulanabilir")
		}
	} else {
		list, err := s.VerifyCandidates(ctx)
		if err != nil {
			return 0, err
		}
		if len(list) == 0 {
			return 0, errors.New("doğrulanacak yedek yok")
		}
		b = list[rand.IntN(len(list))]
	}
	remote := b.Remote && s.Remote(ctx).Configured()
	where := "yerel"
	if remote {
		where = "Drive"
	}
	return s.Jobs.Submit(ctx, jobs.Spec{Kind: "backup.verify", TargetType: "backup", TargetID: b.Domain,
		Summary: "Yedek doğrulama: " + b.Domain + " / " + b.Name + " (" + where + ")", Retryable: true,
		Params: map[string]any{"backup_id": b.ID, "remote": remote}})
}

// parseVerify reads the helper's "check=…" and "mssql=<db> <staged>" lines.
func parseVerify(out string) (checks []string, staged [][2]string) {
	for _, line := range strings.Split(out, "\n") {
		line = strings.TrimSpace(line)
		switch {
		case strings.HasPrefix(line, "check="):
			checks = append(checks, strings.TrimPrefix(line, "check="))
		case strings.HasPrefix(line, "mssql="):
			if db, f, ok := strings.Cut(strings.TrimPrefix(line, "mssql="), " "); ok {
				staged = append(staged, [2]string{db, f})
			}
		}
	}
	return checks, staged
}

func (s *Service) jobVerify(ctx context.Context, l *jobs.Log, p map[string]any) error {
	b, err := s.Store.Backup(ctx, paramID(p, "backup_id"))
	if err != nil {
		return errors.New("yedek bulunamadı")
	}
	remote, _ := p["remote"].(bool)
	src, server := "local", "-"
	if remote {
		src, server = "remote", b.RemoteSrv
		if server == "" {
			server = s.serverName(ctx)
		}
	} else if !b.Local {
		return errors.New("yedeğin yerel kopyası yok ve Drive yapılandırılmamış")
	}
	v := Verification{BackupID: b.ID, Domain: b.Domain, Name: b.Name, Source: src, JobID: l.ID(), CreatedAt: s.now()}
	l.Printf("Doğrulanıyor: %s / %s (%s)", b.Domain, b.Name, map[bool]string{true: "Drive'dan indirilerek", false: "yerel kopya"}[remote])
	res, herr := s.helper(ctx, l, nil, nil, 6*time.Hour, "verify-deep", server, b.Domain, b.Name)
	checks, staged := parseVerify(res.Stdout)
	for _, st := range staged {
		db, file := st[0], st[1]
		verr := errors.New("MSSQL sunucusu çalışmıyor")
		if s.DBs != nil && s.DBs.Available(ctx) {
			verr = s.DBs.VerifyBackup(ctx, l, mssqlBackupDir+"/"+file)
		}
		s.helper(context.WithoutCancel(ctx), l, nil, nil, time.Minute, "unstage", file)
		if verr != nil {
			checks = append(checks, "mssql "+db+" HATA "+verr.Error())
			if herr == nil {
				herr = fmt.Errorf("MSSQL yedeği doğrulanamadı (%s): %w", db, verr)
			}
		} else {
			checks = append(checks, "mssql "+db+" ok RESTORE VERIFYONLY")
		}
	}
	if s.DryRun && len(checks) == 0 {
		checks = []string{"dry-run: kontrol yapılmadı"}
	}
	if herr != nil {
		checks = append(checks, "HATA: "+herr.Error())
		v.Status = StatusFailed
	} else {
		v.Status = StatusSuccess
	}
	v.Detail = strings.Join(checks, "\n")
	s.Store.insertVerification(ctx, v)
	s.Store.purgeVerifications(ctx)
	sum := "Yedek doğrulandı: " + b.Domain + " / " + b.Name
	act := logs.Entry{Action: "backup.verify", TargetType: "backup", TargetID: b.Domain, Summary: sum}
	if herr != nil {
		sum = "Yedek doğrulanamadı: " + b.Domain + " / " + b.Name
		act.Summary, act.Status, act.Error = sum, logs.StatusFailed, herr.Error()
	}
	s.Activity.Record(ctx, act, map[string]any{"job_id": l.ID(), "source": src})
	if s.Notify != nil {
		s.Notify(ctx, notify.Event{Kind: notify.KindVerify, Key: "verify:" + b.Domain + ":" + b.Name, NoDedupe: true,
			Title: sum, Text: v.Detail})
	}
	l.Progress(100)
	return herr
}

// VerifyWeeklyOn reports whether the weekly drill is enabled (default on).
func (s *Service) VerifyWeeklyOn(ctx context.Context) bool {
	return s.setting(ctx, SetVerifyWeekly, "1") == "1"
}

// SetVerifyWeeklyOn switches the weekly drill.
func (s *Service) SetVerifyWeeklyOn(ctx context.Context, on bool) error {
	v := "0"
	if on {
		v = "1"
	}
	return store.SetSetting(ctx, s.DB, SetVerifyWeekly, v)
}

// MaintainVerify (daily maintenance) starts the weekly drill when due. The
// first run only records the time, so a fresh install is not drilled at once.
func (s *Service) MaintainVerify(ctx context.Context) {
	if !s.VerifyWeeklyOn(ctx) {
		return
	}
	now := s.now()
	last := s.setting(ctx, setVerifyAt, "")
	if last == "" {
		store.SetSetting(ctx, s.DB, setVerifyAt, fmt.Sprint(now.Unix()))
		return
	}
	var t int64
	fmt.Sscan(last, &t)
	if now.Sub(time.Unix(t, 0)) < verifyEvery-time.Hour {
		return
	}
	if _, err := s.StartVerify(ctx, 0); err != nil {
		if s.Log != nil {
			s.Log.Info("weekly backup verification skipped", "err", err)
		}
	}
	store.SetSetting(ctx, s.DB, setVerifyAt, fmt.Sprint(now.Unix()))
}

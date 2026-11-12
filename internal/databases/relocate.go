package databases

import (
	"context"
	"errors"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/zahit5834/hostpanel/internal/jobs"
	"github.com/zahit5834/hostpanel/internal/store"
)

// --- T2 (Faz 13): data directory under a root-owned parent ---
//
// /var/lib/hostpanel belongs to the panel user, so a database directory there
// could be swapped for a symlink between root's check and its use. The helper
// moves it (a rename on the same filesystem) to /var/lib/hostpanel-db.

const (
	// OldDBRoot is the panel-owned parent used before Faz 13.
	OldDBRoot = "/var/lib/hostpanel/"
	// NewDBRoot is the root-owned parent.
	NewDBRoot = "/var/lib/hostpanel-db/"
	// NewDataDir is the SQL Server data directory after the move.
	NewDataDir = NewDBRoot + "mssql"

	settingRelocated = "db_relocated_mssql" // dry-run only: simulated location
)

// OldLocation reports a data directory still under the panel-owned parent.
func (st Status) OldLocation() bool { return strings.HasPrefix(st.DataDir, OldDBRoot) }

// AtOldLocation reports an installed server whose data directory is still
// under the panel-owned parent. The panel can lstat its own directory, so no
// helper call is needed (the security audit uses this on every page open).
func (s *Service) AtOldLocation(ctx context.Context) bool {
	if _, err := s.Store.Server(ctx); err != nil {
		return false
	}
	if s.DryRun {
		return store.GetSetting(ctx, s.DB, settingRelocated, "") != "1"
	}
	return pathPresent(DataDir) && !pathPresent(NewDataDir)
}

// pathPresent reports whether p exists (without following a final symlink;
// the panel may not be able to enter the directory itself).
func pathPresent(p string) bool { _, err := os.Lstat(p); return err == nil }

// StartRelocate queues the move of the SQL Server data directory.
func (s *Service) StartRelocate(ctx context.Context) (int64, error) {
	srv, err := s.Store.Server(ctx)
	if err != nil {
		return 0, ErrNoServer
	}
	if srv.Status != StatusRunning && srv.Status != StatusStopped {
		return 0, errors.New("sunucu çalışır ya da durdurulmuş durumda olmalı")
	}
	if st := s.LiveStatus(ctx); !st.OldLocation() {
		if st.Err != "" {
			return 0, errors.New("sunucu durumu okunamadı: " + st.Err)
		}
		return 0, errors.New("veri dizini zaten güvenli konumda")
	}
	return s.Jobs.Submit(ctx, jobs.Spec{Kind: "db.server.relocate", TargetType: "db_server", TargetID: "mssql",
		Summary: "MSSQL veri dizini " + NewDataDir + " konumuna taşınıyor", Params: map[string]any{"server_id": srv.ID}})
}

// jobRelocate: remove the container, move the directory, create the container
// on the new path. If SQL Server does not come up there, everything is moved
// back and the container recreated on the old path.
func (s *Service) jobRelocate(ctx context.Context, l *jobs.Log, p map[string]any) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	srv, err := s.Store.Server(ctx)
	if err != nil || srv.ID != paramID(p, "server_id") {
		return errors.New("sunucu kaydı bulunamadı")
	}
	saPW, err := s.Box.OpenString(srv.SASealed)
	if err != nil {
		return err
	}
	wasStopped := srv.Status == StatusStopped
	l.Printf("Container kaldırılıyor (veri korunur); SQL Server birkaç dakika erişilemez…")
	if _, err := s.helper(ctx, l, nil, nil, 3*time.Minute, "remove-container"); err != nil {
		return fmt.Errorf("container kaldırılamadı, hiçbir şey taşınmadı: %w", err)
	}
	bg := context.WithoutCancel(ctx) // from here on the server must end up on some path
	l.Progress(20)
	if _, err := s.helper(bg, l, nil, nil, 5*time.Minute, "relocate", "to-new"); err != nil {
		l.Printf("Taşınamadı (%v); container eski konumla yeniden oluşturuluyor…", err)
		if rerr := s.recreateHere(bg, l, srv, saPW, wasStopped); rerr != nil {
			return s.failServer(bg, srv.ID, fmt.Errorf("taşınamadı (%v) ve eski konumla da açılamadı: %w", err, rerr))
		}
		return fmt.Errorf("veri dizini taşınamadı, eski konumda çalışmaya devam ediyor: %w", err)
	}
	l.Progress(50)
	if err := s.recreateHere(bg, l, srv, saPW, wasStopped); err != nil {
		l.Printf("Yeni konumda açılmadı (%v); eski konuma geri dönülüyor…", err)
		s.helper(bg, l, nil, nil, 3*time.Minute, "remove-container")
		if _, merr := s.helper(bg, l, nil, nil, 5*time.Minute, "relocate", "to-old"); merr != nil {
			return s.failServer(bg, srv.ID, fmt.Errorf("yeni konumda açılmadı (%v) ve geri taşınamadı: %w", err, merr))
		}
		if rerr := s.recreateHere(bg, l, srv, saPW, wasStopped); rerr != nil {
			return s.failServer(bg, srv.ID, fmt.Errorf("yeni konumda açılmadı (%v), eski konumda da açılamadı: %w", err, rerr))
		}
		return fmt.Errorf("yeni konumda açılmadı, eski konuma dönüldü: %w", err)
	}
	if s.DryRun {
		store.SetSetting(bg, s.DB, settingRelocated, "1")
	}
	l.Progress(100)
	l.Printf("Veri dizini taşındı: %s", NewDataDir)
	return nil
}

// recreateHere creates the container on whatever path the helper now
// resolves, waits until SQL Server answers, rotates sa and re-applies the
// memory setting; a stopped server is stopped again.
func (s *Service) recreateHere(ctx context.Context, l *jobs.Log, srv Server, saPW string, wasStopped bool) error {
	if err := s.createContainer(ctx, l, srv, saPW); err != nil {
		return err
	}
	if err := s.waitReady(ctx, l); err != nil {
		return err
	}
	if err := s.rotateSA(ctx, l, srv); err != nil {
		l.Printf("UYARI: sa şifresi yenilenemedi: %v", err)
	}
	if err := s.configure(ctx, l, srv); err != nil {
		l.Printf("UYARI: %v", err)
	}
	status := StatusRunning
	if wasStopped {
		s.helper(ctx, l, nil, nil, 2*time.Minute, "stop")
		status = StatusStopped
	}
	s.Store.SetServerStatus(ctx, srv.ID, status, "")
	return nil
}

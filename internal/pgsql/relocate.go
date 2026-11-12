package pgsql

import (
	"context"
	"errors"
	"fmt"
	"os"
	"time"

	"github.com/zahit5834/hostpanel/internal/databases"
	"github.com/zahit5834/hostpanel/internal/jobs"
	"github.com/zahit5834/hostpanel/internal/store"
)

// --- T2 (Faz 13): data directories under a root-owned parent ---

const (
	// NewDataDir is the PostgreSQL data directory after the move
	// (postgres-backup moves along).
	NewDataDir = databases.NewDBRoot + "postgres"

	settingRelocated = "db_relocated_pg" // dry-run only: simulated location
)

// AtOldLocation reports an installed server still under the panel-owned parent.
func (s *Service) AtOldLocation(ctx context.Context) bool {
	if _, err := s.Store.Server(ctx); err != nil {
		return false
	}
	if s.DryRun {
		return store.GetSetting(ctx, s.DB, settingRelocated, "") != "1"
	}
	_, oldErr := os.Lstat(DataDir)
	_, newErr := os.Lstat(NewDataDir)
	return oldErr == nil && newErr != nil
}

// StartRelocate queues the move of the PostgreSQL data directories.
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
	return s.Jobs.Submit(ctx, jobs.Spec{Kind: "pg.server.relocate", TargetType: "pg_server", TargetID: "postgres",
		Summary: "PostgreSQL veri dizini " + NewDataDir + " konumuna taşınıyor", Params: map[string]any{"server_id": srv.ID}})
}

// jobRelocate mirrors the MSSQL job: remove the container, move, create on
// the new path (create waits until PostgreSQL answers); on failure move back.
func (s *Service) jobRelocate(ctx context.Context, l *jobs.Log, p map[string]any) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	srv, err := s.Store.Server(ctx)
	if err != nil || srv.ID != paramID(p, "server_id") {
		return errors.New("sunucu kaydı bulunamadı")
	}
	wasStopped := srv.Status == StatusStopped
	l.Printf("Container kaldırılıyor (veri korunur); PostgreSQL birkaç dakika erişilemez…")
	if _, err := s.helper(ctx, l, nil, nil, 3*time.Minute, "remove-container"); err != nil {
		return fmt.Errorf("container kaldırılamadı, hiçbir şey taşınmadı: %w", err)
	}
	bg := context.WithoutCancel(ctx)
	l.Progress(20)
	if _, err := s.helper(bg, l, nil, nil, 5*time.Minute, "relocate", "to-new"); err != nil {
		l.Printf("Taşınamadı (%v); container eski konumla yeniden oluşturuluyor…", err)
		if rerr := s.recreateHere(bg, l, srv, wasStopped); rerr != nil {
			return s.failServer(bg, srv.ID, fmt.Errorf("taşınamadı (%v) ve eski konumla da açılamadı: %w", err, rerr))
		}
		return fmt.Errorf("veri dizini taşınamadı, eski konumda çalışmaya devam ediyor: %w", err)
	}
	l.Progress(50)
	if err := s.recreateHere(bg, l, srv, wasStopped); err != nil {
		l.Printf("Yeni konumda açılmadı (%v); eski konuma geri dönülüyor…", err)
		s.helper(bg, l, nil, nil, 3*time.Minute, "remove-container")
		if _, merr := s.helper(bg, l, nil, nil, 5*time.Minute, "relocate", "to-old"); merr != nil {
			return s.failServer(bg, srv.ID, fmt.Errorf("yeni konumda açılmadı (%v) ve geri taşınamadı: %w", err, merr))
		}
		if rerr := s.recreateHere(bg, l, srv, wasStopped); rerr != nil {
			return s.failServer(bg, srv.ID, fmt.Errorf("yeni konumda açılmadı (%v), eski konumda da açılamadı: %w", err, rerr))
		}
		return fmt.Errorf("yeni konumda açılmadı, eski konuma dönüldü: %w", err)
	}
	if s.DryRun {
		store.SetSetting(bg, s.DB, settingRelocated, "1")
	}
	l.Progress(100)
	l.Printf("Veri dizinleri taşındı: %s (+ %spostgres-backup)", NewDataDir, databases.NewDBRoot)
	return nil
}

func (s *Service) recreateHere(ctx context.Context, l *jobs.Log, srv Server, wasStopped bool) error {
	if err := s.createContainer(ctx, l, srv); err != nil {
		return err
	}
	s.recordVersion(ctx, srv)
	status := StatusRunning
	if wasStopped {
		s.helper(ctx, l, nil, nil, 2*time.Minute, "stop")
		status = StatusStopped
	}
	s.Store.SetServerStatus(ctx, srv.ID, status, "")
	return nil
}

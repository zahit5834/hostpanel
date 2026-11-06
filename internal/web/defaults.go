package web

import (
	"context"
	"database/sql"
	"errors"
	"strconv"

	"github.com/zahit5834/hostpanel/internal/store"
)

// panelDefaults are the Ayarlar → Genel defaults: log retention (read by the
// daily maintenance in main) and the site wizard's resource limits.
type panelDefaults struct {
	ActivityDays int
	JobDays      int
	MemoryMB     int
	CPUPct       int
}

// Settings keys (retention_* are also read by cmd/hostpanel maintenance).
const (
	setRetentionActivity = "retention_activity_days"
	setRetentionJobs     = "retention_job_days"
	setDefaultMemory     = "default_memory_mb"
	setDefaultCPU        = "default_cpu_pct"
)

func settingInt(ctx context.Context, db *sql.DB, key string, def int) int {
	n, err := strconv.Atoi(store.GetSetting(ctx, db, key, ""))
	if err != nil || n <= 0 {
		return def
	}
	return n
}

func (s *Server) panelDefaults(ctx context.Context) panelDefaults {
	return panelDefaults{
		ActivityDays: settingInt(ctx, s.DB, setRetentionActivity, 180),
		JobDays:      settingInt(ctx, s.DB, setRetentionJobs, 30),
		MemoryMB:     settingInt(ctx, s.DB, setDefaultMemory, 512),
		CPUPct:       settingInt(ctx, s.DB, setDefaultCPU, 100),
	}
}

func (d panelDefaults) validate() error {
	switch {
	case d.ActivityDays < 7 || d.ActivityDays > 3650:
		return errors.New("işlem geçmişi saklama süresi 7–3650 gün olmalı")
	case d.JobDays < 1 || d.JobDays > 365:
		return errors.New("iş logu saklama süresi 1–365 gün olmalı")
	case d.MemoryMB < 64 || d.MemoryMB > 65536:
		return errors.New("varsayılan bellek sınırı 64–65536 MB olmalı")
	case d.CPUPct < 5 || d.CPUPct > 1600:
		return errors.New("varsayılan CPU kotası %5–1600 olmalı")
	}
	return nil
}

func (d panelDefaults) save(ctx context.Context, db *sql.DB) {
	store.SetSetting(ctx, db, setRetentionActivity, strconv.Itoa(d.ActivityDays))
	store.SetSetting(ctx, db, setRetentionJobs, strconv.Itoa(d.JobDays))
	store.SetSetting(ctx, db, setDefaultMemory, strconv.Itoa(d.MemoryMB))
	store.SetSetting(ctx, db, setDefaultCPU, strconv.Itoa(d.CPUPct))
}

package web

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/zahit5834/hostpanel/internal/logs"
	"github.com/zahit5834/hostpanel/internal/store"
)

// An OOM alert closes once the victim stayed up for oomQuiet: activity
// system.oom.resolved, dashboard alert gone, Server page marks it.
func TestOOMResolves(t *testing.T) {
	ts, s := newTestServer(t)
	c := client()
	w := webClient{t: t, ts: ts, c: c, csrf: login(t, ts, c)}
	ctx := context.Background()
	sys := logs.WithActor(ctx, logs.Actor{Source: logs.SourceSystem})
	now := time.Now()
	rec := func(unit, who string, at time.Time) {
		s.Activity.Record(sys, logs.Entry{TS: at, Action: "system.oom", TargetType: "server", TargetID: unit, Status: logs.StatusFailed,
			Summary: "Bellek yetersiz: " + who + " sonlandırıldı (kendi bellek sınırına ulaştı, pid 1)"}, nil)
	}
	rec("hp-build-old.service", "dotnet", now.Add(-45*time.Minute)) // quiet long enough
	rec("nginx.service", "nginx", now.Add(-5*time.Minute))          // too recent

	if _, body := w.get("/", false); !strings.Contains(body, "dotnet sonlandırıldı") || !strings.Contains(body, "nginx sonlandırıldı") {
		t.Fatal("alerts missing before check")
	}
	store.SetSetting(ctx, s.DB, setOOMChecked, "1")
	s.OOMCheck(ctx)
	fixed, _ := s.Activity.Query(ctx, logs.Filter{Action: "system.oom.resolved"})
	if len(fixed) != 1 || fixed[0].TargetID != "hp-build-old.service" || fixed[0].Summary != "Bellek sorunu giderildi: dotnet" {
		t.Fatalf("resolved: %+v", fixed)
	}
	_, body := w.get("/", false)
	if strings.Contains(body, "dotnet sonlandırıldı") || !strings.Contains(body, "nginx sonlandırıldı") {
		t.Fatal("dashboard should keep only the open alert")
	}
	if _, body := w.get("/server?tab=general", false); !strings.Contains(body, "giderildi") {
		t.Fatal("server page should mark the resolved kill")
	}
	// A second check does not resolve it again.
	s.OOMCheck(ctx)
	if fixed, _ := s.Activity.Query(ctx, logs.Filter{Action: "system.oom.resolved"}); len(fixed) != 1 {
		t.Fatalf("resolved twice: %d", len(fixed))
	}
	// A new kill of the same unit reopens the alert.
	rec("hp-build-old.service", "dotnet", now.Add(time.Second))
	if _, body := w.get("/", false); !strings.Contains(body, "dotnet sonlandırıldı") {
		t.Fatal("repeat kill should reopen the alert")
	}
}

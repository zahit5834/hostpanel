package sysmaint

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestParseUpgradable(t *testing.T) {
	p := ParseUpgradable(dryApt)
	if len(p) != 4 || p[0].Name != "openssl" || !p[0].Security || p[0].Old != "3.0.13-0ubuntu3.6" || p[0].New != "3.0.13-0ubuntu3.7" ||
		p[2].Security || p[2].Suite != "noble-updates" || p[3].Arch != "amd64" {
		t.Fatalf("%+v", p)
	}
	s := &Service{DryRun: true}
	a := s.Upgradable(context.Background(), false)
	if a.Security != 2 || len(a.Held) != 1 || a.Held[0] != "docker.io" || !a.Pkgs[0].Security || a.Pkgs[3].Security {
		t.Fatalf("%+v", a)
	}
}

func TestParseNeedrestart(t *testing.T) {
	r := ParseNeedrestart("NEEDRESTART-VER: 3.6\nNEEDRESTART-KCUR: 6.8.0-147-generic\nNEEDRESTART-KEXP: 6.8.0-149-generic\nNEEDRESTART-KSTA: 3\nNEEDRESTART-SVC: nginx.service\nNEEDRESTART-SVC: nginx.service\nNEEDRESTART-PID: dbus-daemon=1\n")
	if !r.KernelPending() || len(r.Services) != 1 || r.KExp != "6.8.0-149-generic" || r.Missing {
		t.Fatalf("%+v", r)
	}
	if !ParseNeedrestart("NEEDRESTART-MISSING: 1\n").Missing {
		t.Fatal("missing")
	}
}

func TestParseScheduled(t *testing.T) {
	k, at := ParseScheduled(`(st) "reboot" 1794460055000000`)
	if k != "reboot" || at.Unix() != 1794460055 {
		t.Fatal(k, at)
	}
	for _, none := range []string{`(st) "" 18446744073709551615`, `(st) "reboot" 0`, "", "garbage"} {
		if k, at := ParseScheduled(none); k != "" || !at.IsZero() {
			t.Errorf("%q → %s %s", none, k, at)
		}
	}
}

func TestParseOOM(t *testing.T) {
	out := "2026-11-12T05:00:00+00:00 srv kernel: oom-kill:constraint=CONSTRAINT_MEMCG,nodemask=(null),cpuset=hp-site-ornek.service,mems_allowed=0,oom_memcg=/system.slice/hp-site-ornek.service,task_memcg=/system.slice/hp-site-ornek.service,task=dotnet,pid=4321,uid=1001\n" +
		"2026-11-12T05:00:00+00:00 srv kernel: Memory cgroup out of memory: Killed process 4321 (dotnet)\n" +
		"2026-11-12T06:00:00+00:00 srv kernel: oom-kill:constraint=CONSTRAINT_NONE,nodemask=(null),cpuset=/,mems_allowed=0,global_oom,task_memcg=/system.slice/docker-abc.scope,task=sqlservr,pid=99,uid=10001\n"
	o := ParseOOM(out)
	if len(o) != 2 || o[0].Process != "dotnet" || o[0].PID != 4321 || !o[0].Limit || o[0].Unit() != "hp-site-ornek.service" ||
		o[1].Limit || o[1].Unit() != "docker-abc.scope" || o[1].Time.Hour() != 6 {
		t.Fatalf("%+v", o)
	}
}

func TestReadSystemFiles(t *testing.T) {
	root := t.TempDir()
	write := func(p, c string) {
		os.MkdirAll(filepath.Dir(root+p), 0o755)
		os.WriteFile(root+p, []byte(c), 0o644)
	}
	write("/proc/meminfo", "MemTotal:        8000000 kB\nMemFree: 1 kB\nMemAvailable:    4000000 kB\nSwapTotal:       0 kB\nSwapFree: 0 kB\n")
	write("/proc/sys/kernel/random/boot_id", "abc-123\n")
	write("/proc/uptime", "3600.50 100.0\n")
	write("/var/run/reboot-required", "")
	write("/var/run/reboot-required.pkgs", "dbus\ndbus\nlinux-base\n")
	write("/etc/apt/apt.conf.d/20auto-upgrades", "APT::Periodic::Update-Package-Lists \"1\";\nAPT::Periodic::Unattended-Upgrade \"0\";\n")
	s := &Service{Root: root, Probe: nil}
	m := s.ReadMem()
	if m.Total != 8000000*1024 || m.Available != 4000000*1024 || m.SwapTotal != 0 {
		t.Fatalf("%+v", m)
	}
	if a := s.AutoStatus(); !a.Known || a.On {
		t.Fatalf("%+v", a)
	}
	s.DryRun = true // skip busctl
	ri := s.Reboot(context.Background())
	if !ri.Required || strings.Join(ri.Pkgs, ",") != "dbus,linux-base" || ri.BootID != "abc-123" || time.Since(ri.BootedAt) < 59*time.Minute {
		t.Fatalf("%+v", ri)
	}
	if err := s.CreateSwap(context.Background(), 100); err == nil {
		t.Fatal("size")
	}
	if err := s.CreateSwap(context.Background(), 2048); err != nil || s.ReadMem().SwapTotal != 2048<<20 {
		t.Fatal(err)
	}
	if err := s.CreateSwap(context.Background(), 2048); err == nil {
		t.Fatal("second swap")
	}
	p := MakePlan(m, []Reservation{{"MSSQL", 2304, ""}, {"Siteler", 6000, ""}, {"yok", 0, ""}})
	if !p.Over() || len(p.Items) != 2 || p.Pct != 8304*100/7812 {
		t.Fatalf("%+v", p)
	}
}

func TestScheduleReboot(t *testing.T) {
	s := &Service{DryRun: true}
	ctx := context.Background()
	for _, bad := range []string{"+0", "+1441", "25:00", "now", "+x", "12:5"} {
		if _, err := s.ScheduleReboot(ctx, bad); err == nil {
			t.Errorf("accepted %q", bad)
		}
	}
	at, err := s.ScheduleReboot(ctx, "+5")
	if err != nil || time.Until(at) < 4*time.Minute {
		t.Fatal(at, err)
	}
	if ri := s.Reboot(ctx); ri.Scheduled.IsZero() {
		t.Fatal("not scheduled")
	}
	s.CancelReboot(ctx)
	if ri := s.Reboot(ctx); !ri.Scheduled.IsZero() {
		t.Fatal("not cancelled")
	}
	if at, _ := s.ScheduleReboot(ctx, "03:30"); at.Hour() != 3 || at.Minute() != 30 || !at.After(time.Now()) {
		t.Fatal(at)
	}
	if _, err := s.ServiceAction(ctx, "restart", "ssh"); err == nil {
		t.Fatal("ssh is not managed")
	}
	if _, err := s.ServiceAction(ctx, "stop", "nginx"); err == nil {
		t.Fatal("stop is not offered")
	}
}

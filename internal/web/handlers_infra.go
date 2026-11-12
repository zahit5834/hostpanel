package web

import (
	"context"
	"encoding/json"
	"slices"
	"strings"
	"time"

	"github.com/zahit5834/hostpanel/internal/databases"
	"github.com/zahit5834/hostpanel/internal/exec"
	"github.com/zahit5834/hostpanel/internal/logs"
	"github.com/zahit5834/hostpanel/internal/mail"
	"github.com/zahit5834/hostpanel/internal/notify"
	"github.com/zahit5834/hostpanel/internal/pgsql"
	"github.com/zahit5834/hostpanel/internal/store"
)

// --- I1: infrastructure monitoring (monitor hook, every 10 minutes) ---

const (
	setInfraState = "infra_state" // JSON map[name]infraState
	infraDownAt   = 2             // consecutive failed checks before "down" (≥ 10 min)
)

type infraState struct {
	Fails int    `json:"f"`
	Down  bool   `json:"d"`           // notified as down
	Since int64  `json:"s,omitempty"` // first failed check (unix)
	Why   string `json:"w,omitempty"`
}

// infraUnits are watched when installed (LoadState=loaded).
var infraUnits = []struct{ Unit, Label string }{
	{"nginx.service", "nginx"},
	{"docker.service", "Docker"},
	{"named.service", "DNS sunucusu (BIND)"},
	{"fail2ban.service", "fail2ban"},
	{"certbot.timer", "certbot yenileme zamanlayıcısı"},
}

// infraObservation is one component's state in this round: ok=false with a
// reason, or skip (not installed / not expected to run / unknown).
type infraObservation struct {
	Name, Label, Why string
	OK, Skip         bool
}

// ParseUnitShow reads `systemctl show -p LoadState -p ActiveState u1 u2 …`
// (one block per unit, in argument order, separated by blank lines).
func ParseUnitShow(out string, n int) []map[string]string {
	res := make([]map[string]string, n)
	i := 0
	res[0] = map[string]string{}
	for _, line := range strings.Split(strings.TrimRight(out, "\n"), "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			if len(res[i]) > 0 && i+1 < n {
				i++
				res[i] = map[string]string{}
			}
			continue
		}
		if k, v, ok := strings.Cut(line, "="); ok {
			res[i][k] = v
		}
	}
	for j := range res {
		if res[j] == nil {
			res[j] = map[string]string{}
		}
	}
	return res
}

func (s *Server) infraObserve(ctx context.Context) []infraObservation {
	var obs []infraObservation
	args := []string{"show", "-p", "LoadState", "-p", "ActiveState"}
	for _, u := range infraUnits {
		args = append(args, u.Unit)
	}
	res, err := s.Sites.Probe.Run(ctx, exec.Cmd{Name: "systemctl", Args: args, Timeout: 10 * time.Second})
	blocks := ParseUnitShow(res.Stdout, len(infraUnits))
	for i, u := range infraUnits {
		o := infraObservation{Name: "unit:" + u.Unit, Label: u.Label}
		b := blocks[i]
		switch {
		case err != nil && res.Stdout == "", b["LoadState"] != "loaded":
			o.Skip = true
		case u.Unit == "named.service" && !s.DNS.Installed(ctx):
			o.Skip = true // a BIND the panel did not install is not ours to watch
		case b["ActiveState"] == "active":
			o.OK = true
		default:
			o.Why = "servis durumu: " + b["ActiveState"]
		}
		obs = append(obs, o)
	}
	// Containers that should be running (the panel's own record says so).
	type cont struct {
		name, label string
		want        bool
		live        func() (databases.Status, string)
	}
	var conts []cont
	if srv, err := s.DBs.Store.Server(ctx); err == nil && srv.ID != 0 {
		conts = append(conts, cont{"container:mssql", "MSSQL", srv.Status == databases.StatusRunning,
			func() (databases.Status, string) { return s.DBs.LiveStatus(ctx), "" }})
	}
	if srv, err := s.PG.Store.Server(ctx); err == nil && srv.ID != 0 {
		conts = append(conts, cont{"container:postgres", "PostgreSQL", srv.Status == pgsql.StatusRunning,
			func() (databases.Status, string) { return s.PG.LiveStatus(ctx), "" }})
	}
	if srv, err := s.Mail.Store.Server(ctx); err == nil && srv.ID != 0 {
		conts = append(conts, cont{"container:mail", "Posta sunucusu", srv.Status == mail.StatusRunning,
			func() (databases.Status, string) { st := s.Mail.LiveStatus(ctx); return st.Status, st.Health }})
	}
	for _, c := range conts {
		o := infraObservation{Name: c.name, Label: c.label}
		if !c.want {
			o.Skip = true
			obs = append(obs, o)
			continue
		}
		st, health := c.live()
		switch {
		case st.Err != "":
			o.Skip = true // the helper failed: unknown, not down
		case st.Docker != "active":
			o.Why = "Docker çalışmıyor"
		case !st.Running():
			o.Why = "container durumu: " + st.Container
		case health == "unhealthy":
			o.Why = "container sağlıksız (healthcheck)"
		default:
			o.OK = true
		}
		obs = append(obs, o)
	}
	return obs
}

func (s *Server) infraLoad(ctx context.Context) map[string]infraState {
	m := map[string]infraState{}
	json.Unmarshal([]byte(store.GetSetting(ctx, s.DB, setInfraState, "{}")), &m)
	return m
}

// InfraCheck notifies components that went down (two checks in a row) and
// came back. Components that are not installed or meant to be stopped are
// not watched.
func (s *Server) InfraCheck(ctx context.Context) {
	obs := s.infraObserve(ctx)
	prev := s.infraLoad(ctx)
	next := map[string]infraState{}
	now := time.Now()
	sys := logs.WithActor(ctx, logs.Actor{Source: logs.SourceSystem})
	for _, o := range obs {
		st := prev[o.Name]
		switch {
		case o.Skip: // stopped on purpose, not installed or unknown: forget it quietly
			continue
		case o.OK:
			if st.Down {
				s.Activity.Record(sys, logs.Entry{Action: "infra.up", TargetType: "infra", TargetID: o.Name,
					Summary: o.Label + " tekrar çalışıyor"}, nil)
				s.notifyInfra(ctx, o.Label+" tekrar çalışıyor", "Kesinti süresi: "+time.Since(time.Unix(st.Since, 0)).Round(time.Minute).String())
			}
			continue // healthy components are not stored
		}
		if st.Fails == 0 {
			st.Since = now.Unix()
		}
		st.Fails++
		st.Why = o.Why
		if st.Fails >= infraDownAt && !st.Down {
			st.Down = true
			s.Activity.Record(sys, logs.Entry{Action: "infra.down", TargetType: "infra", TargetID: o.Name, Status: logs.StatusFailed,
				Summary: o.Label + " çalışmıyor", Error: o.Why}, nil)
			s.notifyInfra(ctx, o.Label+" çalışmıyor", o.Why+"\nİlk tespit: "+time.Unix(st.Since, 0).Format("02.01 15:04"))
		}
		next[o.Name] = st
	}
	b, _ := json.Marshal(next)
	store.SetSetting(ctx, s.DB, setInfraState, string(b))
}

func (s *Server) notifyInfra(ctx context.Context, title, text string) {
	if s.Notify != nil {
		s.Notify.Send(ctx, notify.Event{Kind: notify.KindInfra, Key: "infra:" + title, NoDedupe: true, Title: title, Text: text})
	}
}

// infraDown lists the components currently notified as down (dashboard).
func (s *Server) infraDown(ctx context.Context) []struct{ Name, Why string } {
	var out []struct{ Name, Why string }
	m := s.infraLoad(ctx)
	names := make([]string, 0, len(m))
	for n := range m {
		names = append(names, n)
	}
	slices.Sort(names)
	for _, n := range names {
		if st := m[n]; st.Down {
			out = append(out, struct{ Name, Why string }{infraLabel(n), st.Why})
		}
	}
	return out
}

func infraLabel(name string) string {
	for _, u := range infraUnits {
		if "unit:"+u.Unit == name {
			return u.Label
		}
	}
	switch name {
	case "container:mssql":
		return "MSSQL"
	case "container:postgres":
		return "PostgreSQL"
	case "container:mail":
		return "Posta sunucusu"
	}
	return name
}

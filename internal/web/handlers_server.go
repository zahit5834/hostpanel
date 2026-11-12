package web

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"slices"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/zahit5834/hostpanel/internal/exec"
	"github.com/zahit5834/hostpanel/internal/logs"
	"github.com/zahit5834/hostpanel/internal/system"
)

// serverCache keeps slow, rarely changing server facts (du can take minutes
// on a full disk).
type serverCache struct {
	mu     sync.Mutex
	disk   diskInfo
	diskMu sync.Mutex // one du at a time
}

type diskInfo struct {
	At    time.Time
	Parts []diskPart
	Err   string
}

type diskPart struct {
	Key, Label string
	Bytes      uint64
	Pct        int // of the root filesystem
}

const (
	diskCacheTTL = 10 * time.Minute
)

// ServiceUnits shown on the server page.
var serverUnits = []struct{ Unit, Label string }{
	{"nginx.service", "nginx"},
	{"docker.service", "Docker"},
	{"named.service", "BIND (DNS)"},
	{"fail2ban.service", "fail2ban"},
	{"hostpanel.service", "HostPanel"},
	{"certbot.timer", "certbot (yenileme zamanlayıcısı)"},
	{"ufw.service", "UFW"},
}

type unitState struct{ Unit, Label, State string }

func (s *Server) unitStates(ctx context.Context) []unitState {
	names := make([]string, len(serverUnits))
	for i, u := range serverUnits {
		names[i] = u.Unit
	}
	// One call; is-active prints one line per unit and exits non-zero if any is down.
	res, _ := s.Sites.Probe.Run(ctx, exec.Cmd{Name: "systemctl", Args: append([]string{"is-active"}, names...), Timeout: 5 * time.Second})
	lines := strings.Split(strings.TrimSpace(res.Stdout), "\n")
	out := make([]unitState, len(serverUnits))
	for i, u := range serverUnits {
		st := "unknown"
		if i < len(lines) && lines[i] != "" {
			st = strings.TrimSpace(lines[i])
		}
		out[i] = unitState{u.Unit, u.Label, st}
	}
	return out
}

var diskLabels = []struct{ Key, Label string }{
	{"sites", "Siteler (/var/www/sites)"},
	{"backups", "Yerel yedekler (/var/backups/hostpanel)"},
	{"mssql", "MSSQL verisi"},
	{"postgres", "PostgreSQL verisi (+ silme öncesi dökümler)"},
	{"mail", "Posta sunucusu (postalar, hesaplar, DKIM)"},
	{"docker", "Docker (imajlar)"},
	{"panel", "Panel verisi"},
	{"logs", "Loglar (/var/log)"},
}

func (s *Server) diskUsage(ctx context.Context, refresh bool) diskInfo {
	c := &s.srvInfo
	c.diskMu.Lock() // a second request waits for the running du instead of starting another
	defer c.diskMu.Unlock()
	c.mu.Lock()
	cur := c.disk
	c.mu.Unlock()
	if !refresh && !cur.At.IsZero() && time.Since(cur.At) < diskCacheTTL {
		return cur
	}
	info := diskInfo{At: time.Now()}
	cmd := exec.Helper(s.Cfg.ScriptsDir, "hp-server.sh", "disk-usage")
	cmd.Timeout = 10 * time.Minute
	res, err := s.Runner.Run(context.WithoutCancel(ctx), cmd)
	if err != nil {
		info.Err = err.Error()
	}
	vals := map[string]uint64{}
	for _, l := range strings.Split(res.Stdout, "\n") {
		if k, v, ok := strings.Cut(strings.TrimSpace(l), "="); ok {
			vals[k], _ = strconv.ParseUint(v, 10, 64)
		}
	}
	total := system.Read().DiskTotal
	for _, d := range diskLabels {
		p := diskPart{Key: d.Key, Label: d.Label, Bytes: vals[d.Key]}
		if total > 0 {
			p.Pct = int(p.Bytes * 100 / total)
		}
		info.Parts = append(info.Parts, p)
	}
	sort.SliceStable(info.Parts, func(i, j int) bool { return info.Parts[i].Bytes > info.Parts[j].Bytes })
	c.mu.Lock()
	c.disk = info
	c.mu.Unlock()
	return info
}

// ufwStatus reads the rules through the root helper (ufw needs root).
func (s *Server) ufwStatus(ctx context.Context) (system.UFWStatus, error) {
	if s.Cfg.DryRun {
		return system.ParseUFW(dryRunUFW(s.panelPort())), nil
	}
	res, err := s.Runner.Run(ctx, exec.Helper(s.Cfg.ScriptsDir, "hp-server.sh", "ufw-status"))
	if err != nil {
		return system.UFWStatus{}, err
	}
	return system.ParseUFW(res.Stdout), nil
}

func (s *Server) panelPort() string {
	_, p, _ := net.SplitHostPort(s.Cfg.Listen)
	return p
}

// dryRunUFW is sample output so the page can be developed without root.
func dryRunUFW(panelPort string) string {
	return "installed=yes\nactive=yes\nprotected=22,80,443," + panelPort + "\n---\n" +
		"[ 1] OpenSSH                    ALLOW IN    Anywhere\n" +
		"[ 2] 80,443/tcp                 ALLOW IN    Anywhere\n" +
		"[ 3] 1433/tcp                   ALLOW IN    203.0.113.7                # hostpanel-mssql\n" +
		"[ 4] 8080/tcp                   ALLOW IN    198.51.100.0/24            # hostpanel\n" +
		"[ 5] OpenSSH (v6)               ALLOW IN    Anywhere (v6)\n"
}

func ufwText(st system.UFWStatus) string {
	var b strings.Builder
	for _, r := range st.Rules {
		b.WriteString(r.Line + "\n")
	}
	return b.String()
}

// renderServer re-renders the UFW tab (its forms swap #ufw).
func (s *Server) renderServer(w http.ResponseWriter, r *http.Request, status int, errMsg, notice string) {
	s.renderServerTab(w, r, status, "ufw", "ufw", errMsg, notice, nil)
}

func (s *Server) serverPage(w http.ResponseWriter, r *http.Request) {
	tab := r.URL.Query().Get("tab")
	if !slices.Contains(serverTabs, tab) {
		tab = "general"
	}
	s.renderServerTab(w, r, http.StatusOK, tab, "", "", "", nil)
}

// serverPart renders the lazily loaded cards (hx-trigger="load").
func (s *Server) serverPart(w http.ResponseWriter, r *http.Request) {
	refresh := r.URL.Query().Get("refresh") == "1"
	var d serverData
	block := ""
	switch part := r.PathValue("part"); part {
	case "disk":
		d.Disk, block = s.diskUsage(r.Context(), refresh), "server-disk"
	case "upd", "restart":
		s.serverUpdatesPart(w, r, part)
		return
	case "ssh":
		s.renderSSH(w, r, http.StatusOK, "", "")
		return
	default:
		http.NotFound(w, r)
		return
	}
	d.DryRun = s.Cfg.DryRun
	s.render(w, r, http.StatusOK, "server", block, Page{Data: d})
}

func (s *Server) ufwChange(ctx context.Context, action, summary string, params map[string]any, args ...string) error {
	before, _ := s.ufwStatus(ctx)
	start := time.Now()
	_, err := s.Runner.Run(ctx, exec.Helper(s.Cfg.ScriptsDir, "hp-server.sh", args...))
	after, _ := s.ufwStatus(ctx)
	s.Activity.Record(ctx, logs.Entry{Action: action, TargetType: "server", TargetID: "ufw", Summary: summary,
		Status: statusOf(err), Error: errText(err), DurationMS: time.Since(start).Milliseconds(),
		Diff: logs.LineDiff(ufwText(before), ufwText(after))}, params)
	return err
}

func (s *Server) ufwAdd(w http.ResponseWriter, r *http.Request) {
	st, err := s.ufwStatus(r.Context())
	if err != nil {
		s.renderServer(w, r, http.StatusBadGateway, err.Error(), "")
		return
	}
	if !st.Active {
		s.renderServer(w, r, http.StatusConflict, "UFW etkin değil; panel UFW'yi açmaz.", "")
		return
	}
	in := system.UFWRuleInput{Action: r.PostFormValue("action"), Port: r.PostFormValue("port"),
		Proto: r.PostFormValue("proto"), From: r.PostFormValue("from")}
	if err := in.Validate(st.Protected); err != nil {
		s.renderServer(w, r, http.StatusBadRequest, err.Error(), "")
		return
	}
	summary := fmt.Sprintf("UFW kuralı eklendi: %s %s/%s ← %s", in.Action, in.Port, in.Proto, in.From)
	err = s.ufwChange(r.Context(), "server.ufw.add", summary,
		map[string]any{"action": in.Action, "port": in.Port, "proto": in.Proto, "from": in.From},
		"ufw-add", in.Action, in.Port, in.Proto, in.From)
	if err != nil {
		s.renderServer(w, r, http.StatusBadGateway, "Kural eklenemedi: "+helperErr(err), "")
		return
	}
	s.securityAlert(r, "UFW kuralı eklendi", summary)
	s.renderServer(w, r, http.StatusOK, "", "Kural eklendi.")
}

func (s *Server) ufwDelete(w http.ResponseWriter, r *http.Request) {
	no, err := strconv.Atoi(r.PathValue("no"))
	hash := r.PostFormValue("hash")
	st, serr := s.ufwStatus(r.Context())
	if err != nil || serr != nil {
		s.renderServer(w, r, http.StatusBadRequest, "Kural okunamadı.", "")
		return
	}
	var rule *system.UFWRule
	for i := range st.Rules {
		if st.Rules[i].No == no {
			rule = &st.Rules[i]
		}
	}
	switch {
	case !st.Active:
		s.renderServer(w, r, http.StatusConflict, "UFW etkin değil.", "")
		return
	case rule == nil || system.RuleHash(rule.Line) != hash:
		s.renderServer(w, r, http.StatusConflict, "Kural listesi değişti; sayfayı yenileyip tekrar deneyin.", "")
		return
	case rule.Locked != "":
		s.renderServer(w, r, http.StatusForbidden, "Bu kural panelden silinemez: "+rule.Locked, "")
		return
	}
	err = s.ufwChange(r.Context(), "server.ufw.delete", "UFW kuralı silindi: "+rule.To+" "+rule.Action+" "+rule.From,
		map[string]any{"rule": rule.Line}, "ufw-delete", strconv.Itoa(no), hash)
	if err != nil {
		s.renderServer(w, r, http.StatusBadGateway, "Kural silinemedi: "+helperErr(err), "")
		return
	}
	s.securityAlert(r, "UFW kuralı silindi", rule.Line)
	s.renderServer(w, r, http.StatusOK, "", "Kural silindi.")
}

// helperErr shows a helper's own (Turkish) die message when there is one.
func helperErr(err error) string {
	var ee *exec.ExitError
	if errors.As(err, &ee) {
		if msg := strings.TrimSpace(ee.Stderr); msg != "" {
			if i := strings.LastIndexByte(msg, '\n'); i >= 0 {
				msg = msg[i+1:]
			}
			return msg
		}
	}
	return err.Error()
}

func init() {
	funcs["ruleHash"] = system.RuleHash
	funcs["unitClass"] = func(st string) string {
		switch st {
		case "active":
			return "success"
		case "failed":
			return "failed"
		}
		return ""
	}
}

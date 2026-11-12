// Package web serves the panel UI: handlers, middleware, templates and static files.
package web

import (
	"context"
	"database/sql"
	"embed"
	"github.com/zahit5834/hostpanel/internal/hostsec"
	"github.com/zahit5834/hostpanel/internal/images"
	"github.com/zahit5834/hostpanel/internal/sysmaint"
	"github.com/zahit5834/hostpanel/internal/system"
	"github.com/zahit5834/hostpanel/internal/traffic"
	"io"
	"io/fs"
	"log/slog"
	"net/http"
	"net/netip"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/zahit5834/hostpanel/internal/auth"
	"github.com/zahit5834/hostpanel/internal/backups"
	"github.com/zahit5834/hostpanel/internal/config"
	"github.com/zahit5834/hostpanel/internal/crons"
	"github.com/zahit5834/hostpanel/internal/customers"
	"github.com/zahit5834/hostpanel/internal/databases"
	"github.com/zahit5834/hostpanel/internal/dns"
	"github.com/zahit5834/hostpanel/internal/exec"
	"github.com/zahit5834/hostpanel/internal/jobs"
	"github.com/zahit5834/hostpanel/internal/logs"
	"github.com/zahit5834/hostpanel/internal/mail"
	"github.com/zahit5834/hostpanel/internal/monitor"
	"github.com/zahit5834/hostpanel/internal/notify"
	"github.com/zahit5834/hostpanel/internal/panelcfg"
	"github.com/zahit5834/hostpanel/internal/pgsql"
	"github.com/zahit5834/hostpanel/internal/runtimes"
	"github.com/zahit5834/hostpanel/internal/sites"
	"github.com/zahit5834/hostpanel/internal/ssl"
	"github.com/zahit5834/hostpanel/internal/store"
	"github.com/zahit5834/hostpanel/internal/update"
)

//go:embed templates static
var assets embed.FS

// Server holds every dependency the handlers need.
type Server struct {
	Cfg      config.Config
	DB       *sql.DB
	Auth     *auth.Service
	Activity *logs.Activity
	Jobs     *jobs.Manager
	Runner   exec.Runner
	Log      *slog.Logger
	Version  string

	Customers *customers.Store
	Sites     *sites.Service
	Runtimes  *runtimes.Registry
	SSL       *ssl.Service
	DBs       *databases.Service
	PG        *pgsql.Service
	Backups   *backups.Service
	Monitor   *monitor.Service
	Notify    *notify.Service
	Crons     *crons.Service
	Update    *update.Service
	DNS       *dns.Service
	Mail      *mail.Service
	Traffic   *traffic.Service
	Idle      *system.IdleGC // returns memory to the OS after the last request
	Images    *images.Service
	SSH       *hostsec.SSH      // Faz 11: SSH login settings + admin keys
	F2B       *hostsec.Fail2ban // host fail2ban jails
	Sys       *sysmaint.Service // OS updates, reboot, memory, services
	// ExportConfig writes the encrypted panel configuration (main wires it:
	// it needs the master key, which the web layer never holds otherwise).
	ExportConfig func(ctx context.Context, passphrase string, w io.Writer) (panelcfg.Manifest, error)

	// BaseCtx outlives requests (cancelled on shutdown); background work
	// started from a handler (cron "run now") uses it.
	BaseCtx context.Context

	metrics metricsState
	srvInfo serverCache

	tpl       *renderer
	allowlist atomic.Pointer[[]netip.Prefix]
	authLogMu sync.Mutex
	authLog   *os.File
}

// Init loads templates and settings. Call once before Handler.
func (s *Server) Init(ctx context.Context) error {
	var tfs fs.FS
	if s.Cfg.Dev {
		// Dev mode reads templates from disk on each request for instant edits.
		tfs = os.DirFS("internal/web")
	} else {
		tfs = assets
	}
	r, err := newRenderer(tfs, s.Cfg.Dev)
	if err != nil {
		return err
	}
	s.tpl = r
	if err := s.loadAllowlist(store.GetSetting(ctx, s.DB, "ip_allowlist", "")); err != nil {
		s.Log.Warn("invalid ip_allowlist setting ignored", "err", err)
	}
	f, err := os.OpenFile(s.Cfg.AuthLogPath(), os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o640)
	if err != nil {
		return err
	}
	s.authLog = f
	return nil
}

// Close releases files.
func (s *Server) Close() {
	if s.authLog != nil {
		s.authLog.Close()
	}
}

// Handler builds the full middleware chain and routes.
func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	s.routes(mux)
	var h http.Handler = mux
	h = s.withSession(h)
	h = s.withAllowlist(h)
	h = s.withClientIP(h)
	h = securityHeaders(h, s.Cfg.SecureCookies)
	h = s.recoverer(h)
	if s.Idle != nil {
		inner := h
		h = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			defer s.Idle.Touch()
			inner.ServeHTTP(w, r)
		})
	}
	return h
}

// HTTPServer returns a server with conservative timeouts. WriteTimeout is left
// at zero because SSE streams are long-lived; handlers bound their own work.
func (s *Server) HTTPServer() *http.Server {
	return &http.Server{
		Addr:              s.Cfg.Listen,
		Handler:           s.Handler(),
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       60 * time.Second,
		IdleTimeout:       90 * time.Second,
		MaxHeaderBytes:    64 << 10,
		ErrorLog:          slog.NewLogLogger(s.Log.Handler(), slog.LevelWarn),
	}
}

// writeAuthLog appends one fail2ban-parsable line, e.g.
// "2026-11-05T12:00:00Z hostpanel: login failed ip=1.2.3.4 reason=password".
func (s *Server) writeAuthLog(event, ip, reason string) {
	s.authLogMu.Lock()
	defer s.authLogMu.Unlock()
	reason = strings.Map(func(r rune) rune {
		if r == '\n' || r == '\r' || r == ' ' {
			return '_'
		}
		return r
	}, reason)
	s.authLog.WriteString(time.Now().UTC().Format(time.RFC3339) + " hostpanel: " + event + " ip=" + ip + " reason=" + reason + "\n")
}

func (s *Server) loadAllowlist(raw string) error {
	prefixes, err := parseAllowlist(raw)
	if err != nil {
		return err
	}
	s.allowlist.Store(&prefixes)
	return nil
}

// parseAllowlist accepts comma/newline separated IPs or CIDRs.
func parseAllowlist(raw string) ([]netip.Prefix, error) {
	var out []netip.Prefix
	for _, f := range strings.FieldsFunc(raw, func(r rune) bool { return r == ',' || r == '\n' || r == ' ' || r == '\r' }) {
		if strings.Contains(f, "/") {
			p, err := netip.ParsePrefix(f)
			if err != nil {
				return nil, err
			}
			out = append(out, p.Masked())
			continue
		}
		a, err := netip.ParseAddr(f)
		if err != nil {
			return nil, err
		}
		out = append(out, netip.PrefixFrom(a, a.BitLen()))
	}
	return out, nil
}

func allowed(prefixes []netip.Prefix, ip string) bool {
	if len(prefixes) == 0 {
		return true
	}
	a, err := netip.ParseAddr(ip)
	if err != nil {
		return false
	}
	a = a.Unmap()
	if a.IsLoopback() { // SSH tunnel access must always work
		return true
	}
	for _, p := range prefixes {
		if p.Contains(a) {
			return true
		}
	}
	return false
}

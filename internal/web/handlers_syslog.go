package web

import (
	"bytes"
	"context"
	"fmt"
	"html"
	"io"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/zahit5834/hostpanel/internal/exec"
	"github.com/zahit5834/hostpanel/internal/logs"
	"github.com/zahit5834/hostpanel/internal/sites"
)

// Log Center → Sistem Logları. Every source is read without root: panel files,
// files in /var/log readable by the adm group (nginx, auth.log, fail2ban),
// root-helper logs in RootLogDir (group hostpanel), the systemd journal
// (systemd-journal group). Only the container logs (MSSQL, PostgreSQL) go
// through a helper.

type sysSource struct {
	ID, Label string
	Site      bool   // needs a site picker
	Unit      string // journal unit ("" = file)
}

var systemSources = []sysSource{
	{ID: "panel", Label: "Panel logu"},
	{ID: "auth", Label: "Panel giriş denemeleri"},
	{ID: "site", Label: "Site servisi (journal)", Site: true},
	{ID: "nginx-access", Label: "nginx erişim logu", Site: true},
	{ID: "nginx-error", Label: "nginx hata logu", Site: true},
	{ID: "certbot", Label: "certbot (SSL yenileme)", Unit: "certbot.service"},
	{ID: "ssl-renewals", Label: "SSL yenileme kayıtları"},
	{ID: "rclone", Label: "rclone (Drive aktarımları)"},
	{ID: "update", Label: "Panel güncelleme"},
	{ID: "apt", Label: "Sistem güncellemeleri (apt)"},
	{ID: "docker", Label: "Docker servisi", Unit: "docker.service"},
	{ID: "mssql", Label: "MSSQL container"},
	{ID: "postgres", Label: "PostgreSQL container"},
	{ID: "dns", Label: "DNS (BIND)", Unit: "named.service"},
	{ID: "mail", Label: "Posta sunucusu (Postfix, Dovecot, Rspamd)"},
	{ID: "fail2ban", Label: "fail2ban"},
	{ID: "sshauth", Label: "SSH / sistem girişleri (auth.log)"},
}

// sysQuery is the parsed filter form.
type sysQuery struct {
	Src          sysSource
	SiteID       int64
	Site         *sites.Site
	N            int
	Text, Level  string
	Since, Until time.Time
	SinceS       string
	UntilS       string
	Path         string // file sources
	Unit         string // journal sources
}

const dtLocal = "2006-01-02T15:04" // <input type="datetime-local">

func (s *Server) parseSysQuery(ctx context.Context, q url.Values) sysQuery {
	sq := sysQuery{Src: systemSources[0], Text: strings.TrimSpace(q.Get("q")), Level: q.Get("level"),
		SinceS: q.Get("since"), UntilS: q.Get("until"), SiteID: parseInt64(q.Get("site"))}
	for _, src := range systemSources {
		if src.ID == q.Get("source") {
			sq.Src = src
		}
	}
	switch sq.Level {
	case "info", "warn", "error":
	default:
		sq.Level = ""
	}
	sq.N, _ = strconv.Atoi(q.Get("n"))
	if sq.N != 500 && sq.N != 1000 {
		sq.N = 100
	}
	if t, err := time.ParseInLocation(dtLocal, sq.SinceS, time.Local); err == nil {
		sq.Since = t
	} else {
		sq.SinceS = ""
	}
	if t, err := time.ParseInLocation(dtLocal, sq.UntilS, time.Local); err == nil {
		sq.Until = t.Add(time.Minute - time.Nanosecond) // inclusive minute
	} else {
		sq.UntilS = ""
	}
	if sq.Src.Site && sq.SiteID > 0 {
		if site, err := s.Sites.Store.Get(ctx, sq.SiteID); err == nil {
			sq.Site = &site
		} else {
			sq.SiteID = 0
		}
	}
	sq.Unit = sq.Src.Unit
	switch sq.Src.ID {
	case "panel":
		sq.Path = s.Cfg.PanelLogPath()
	case "auth":
		sq.Path = s.Cfg.AuthLogPath()
	case "ssl-renewals":
		sq.Path = s.Cfg.RenewLogPath()
	case "rclone":
		sq.Path = s.Cfg.RcloneLogPath()
	case "update":
		sq.Path = s.Cfg.UpdateLogPath()
	case "apt":
		sq.Path = s.Cfg.AptLogPath()
	case "fail2ban":
		sq.Path = "/var/log/fail2ban.log"
	case "sshauth":
		sq.Path = "/var/log/auth.log"
	case "nginx-access", "nginx-error":
		kind := strings.TrimPrefix(sq.Src.ID, "nginx-")
		if sq.Site != nil {
			sq.Path = sites.NginxLogPath(*sq.Site, kind)
		} else {
			sq.Path = "/var/log/nginx/" + kind + ".log" // global log (requests that match no site)
		}
	case "site":
		if sq.Site != nil {
			sq.Unit = sq.Site.Unit() + ".service"
		}
	}
	return sq
}

// Filtered reports whether a text/level/date filter is active.
func (sq sysQuery) Filtered() bool {
	return sq.Text != "" || sq.Level != "" || !sq.Since.IsZero() || !sq.Until.IsZero()
}

// Live reports whether the source supports live tailing.
func (sq sysQuery) Live() bool { return sq.Path != "" || sq.Unit != "" }

// match applies text and level filters (date is handled by the reader).
func (sq sysQuery) match(l string) bool {
	if sq.Text != "" && !strings.Contains(strings.ToLower(l), strings.ToLower(sq.Text)) {
		return false
	}
	if sq.Level != "" {
		if strings.Contains(l, `"level":"`) {
			return strings.Contains(l, `"level":"`+strings.ToUpper(sq.Level)+`"`)
		}
		low := strings.ToLower(l)
		switch sq.Level {
		case "error":
			return strings.Contains(low, "error") || strings.Contains(low, "[crit]") || strings.Contains(low, "[alert]") ||
				strings.Contains(low, "[emerg]") || strings.Contains(low, "fail")
		case "warn":
			return strings.Contains(low, "warn") || strings.Contains(low, "notice")
		default:
			return strings.Contains(low, "info")
		}
	}
	return true
}

// QueryString rebuilds the filter for links (download, live stream).
func (sq sysQuery) QueryString() string {
	v := url.Values{"source": {sq.Src.ID}, "n": {strconv.Itoa(sq.N)}}
	for k, x := range map[string]string{"q": sq.Text, "level": sq.Level, "since": sq.SinceS, "until": sq.UntilS} {
		if x != "" {
			v.Set(k, x)
		}
	}
	if sq.SiteID > 0 {
		v.Set("site", strconv.FormatInt(sq.SiteID, 10))
	}
	return v.Encode()
}

func (s *Server) readSysLines(ctx context.Context, sq sysQuery) []string {
	switch {
	case sq.Src.ID == "mssql":
		// docker logs needs the docker socket (root): read through hp-mssql.sh.
		return s.filterLines(sq, s.DBs.ContainerLogs(ctx, sq.N))
	case sq.Src.ID == "postgres":
		return s.filterLines(sq, s.PG.ContainerLogs(ctx, sq.N))
	case sq.Src.ID == "mail":
		if s.Mail == nil {
			return nil
		}
		return s.filterLines(sq, s.Mail.ContainerLogs(ctx, sq.N))
	case sq.Src.Site && sq.Site == nil && sq.Src.ID == "site":
		return []string{"(bir site seçin)"}
	case sq.Unit != "":
		return s.filterLines(sq, s.journal(ctx, sq))
	}
	var lines []string
	var err error
	if sq.Filtered() {
		now, prev := time.Now(), true
		lines, err = logs.ScanLines(sq.Path, sq.N, func(l string) bool {
			if !sq.Since.IsZero() || !sq.Until.IsZero() {
				if !logs.InRange(l, sq.Since, sq.Until, now, &prev) {
					return false
				}
			}
			return sq.match(l)
		})
	} else {
		lines, err = logs.TailLines(sq.Path, sq.N)
	}
	if err != nil {
		lines = append(lines, "(log okunamadı: "+err.Error()+")")
		if os.IsPermission(err) {
			lines = append(lines, "(panel kullanıcısı adm grubunda olmalı — Faz 6 kurulum betiği ekler)")
		}
	}
	return lines
}

func (s *Server) filterLines(sq sysQuery, lines []string) []string {
	if sq.Text == "" && sq.Level == "" {
		return lines
	}
	out := lines[:0]
	for _, l := range lines {
		if sq.match(l) {
			out = append(out, l)
		}
	}
	return out
}

func journalArgs(sq sysQuery) []string {
	args := []string{"-u", sq.Unit, "--no-pager", "-o", "short-iso"}
	if !sq.Since.IsZero() {
		args = append(args, "--since", sq.Since.Format("2006-01-02 15:04:05"))
	}
	if !sq.Until.IsZero() {
		args = append(args, "--until", sq.Until.Format("2006-01-02 15:04:05"))
	}
	return args
}

func (s *Server) journal(ctx context.Context, sq sysQuery) []string {
	args := append(journalArgs(sq), "-n", strconv.Itoa(sq.N))
	res, err := s.Sites.Probe.Run(ctx, exec.Cmd{Name: "journalctl", Args: args, Timeout: 20 * time.Second})
	out := strings.TrimRight(res.Stdout, "\n")
	if err != nil && out == "" {
		return []string{"(journal okunamadı: " + err.Error() + ")"}
	}
	if out == "" || out == "-- No entries --" {
		return nil
	}
	return strings.Split(out, "\n")
}

func (s *Server) systemLogs(w http.ResponseWriter, r *http.Request) {
	sq := s.parseSysQuery(r.Context(), r.URL.Query())
	lines := s.readSysLines(r.Context(), sq)
	if r.URL.Query().Get("download") == "1" {
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		w.Header().Set("Content-Disposition", fmt.Sprintf(`attachment; filename="%s-%s.log"`, sq.Src.ID, time.Now().Format("20060102-150405")))
		for _, l := range lines {
			fmt.Fprintln(w, l)
		}
		return
	}
	block := "layout"
	if isHX(r) {
		block = "syslog-page"
		if r.Header.Get("HX-Target") == "syslog-box" {
			block = "syslog-lines"
		}
	}
	siteList, _ := s.Sites.Store.List(r.Context(), 0)
	s.render(w, r, http.StatusOK, "logs_system", block, Page{Title: "Sistem Logları", Nav: "logs", Data: map[string]any{
		"Sources": systemSources, "Q": sq, "Lines": lines, "SiteList": siteList, "LiveOn": r.URL.Query().Get("live") == "1",
	}})
}

// --- live tail (SSE) ---

// systemLogStream follows a file or journal source. Everything is bound to
// the request: the 1 s file ticker and the journalctl process end when the
// browser disconnects (or "Durdur" removes the SSE element).
func (s *Server) systemLogStream(w http.ResponseWriter, r *http.Request) {
	sq := s.parseSysQuery(r.Context(), r.URL.Query())
	flusher, ok := w.(http.Flusher)
	if !ok || !sq.Live() {
		http.Error(w, "canlı takip desteklenmiyor", http.StatusBadRequest)
		return
	}
	h := w.Header()
	h.Set("Content-Type", "text/event-stream")
	h.Set("Cache-Control", "no-cache")
	h.Set("X-Accel-Buffering", "no")
	ctx := r.Context()
	lines := make(chan string, 256)
	if sq.Unit != "" {
		go s.followJournal(ctx, sq, lines)
	} else {
		// Wait until the start offset is taken, so nothing written after
		// ": connected" is skipped.
		ready := make(chan struct{})
		go followFile(ctx, sq.Path, lines, ready)
		<-ready
	}
	fmt.Fprint(w, ": connected\n\n")
	flusher.Flush()
	heartbeat := time.NewTicker(25 * time.Second)
	defer heartbeat.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-heartbeat.C:
			if _, err := fmt.Fprint(w, ": ping\n\n"); err != nil {
				return
			}
			flusher.Flush()
		case l, open := <-lines:
			if !open {
				fmt.Fprint(w, "event: line\ndata: <div class=\"muted\">(takip sona erdi)</div>\n\n")
				flusher.Flush()
				return
			}
			if !sq.match(l) {
				continue
			}
			if _, err := fmt.Fprintf(w, "event: line\ndata: <div>%s</div>\n\n", html.EscapeString(l)); err != nil {
				return
			}
			// Drain what is already queued before flushing (bursts → one write).
			for n := len(lines); n > 0; n-- {
				if l, ok := <-lines; ok && sq.match(l) {
					fmt.Fprintf(w, "event: line\ndata: <div>%s</div>\n\n", html.EscapeString(l))
				}
			}
			flusher.Flush()
		}
	}
}

// lineWriter splits a byte stream into lines and queues them (dropping when
// the browser is too slow; the console is best-effort).
type lineWriter struct {
	ch      chan<- string
	partial []byte
}

func (lw *lineWriter) Write(p []byte) (int, error) {
	data := append(lw.partial, p...)
	for {
		i := bytes.IndexByte(data, '\n')
		if i < 0 {
			break
		}
		select {
		case lw.ch <- string(bytes.TrimRight(data[:i], "\r")):
		default:
		}
		data = data[i+1:]
	}
	if len(data) > 64<<10 { // absurdly long line: emit as is
		select {
		case lw.ch <- string(data):
		default:
		}
		data = nil
	}
	lw.partial = append(lw.partial[:0], data...)
	return len(p), nil
}

func (s *Server) followJournal(ctx context.Context, sq sysQuery, out chan<- string) {
	defer close(out)
	args := []string{"-u", sq.Unit, "--no-pager", "-o", "short-iso", "-f", "-n", "0"}
	s.Sites.Probe.Run(ctx, exec.Cmd{Name: "journalctl", Args: args, Timeout: 12 * time.Hour, Output: &lineWriter{ch: out}})
}

// followFile polls the file once a second for appended bytes; a smaller size
// (copytruncate) or another inode (rotation) restarts from the beginning.
// ready is closed once the starting offset (end of file) is recorded.
func followFile(ctx context.Context, path string, out chan<- string, ready chan<- struct{}) {
	defer close(out)
	lw := &lineWriter{ch: out}
	var f *os.File
	var ino uint64
	var off int64
	open := func(fromEnd bool) {
		if f != nil {
			f.Close()
			f = nil
		}
		nf, err := os.Open(path)
		if err != nil {
			return
		}
		st, _ := nf.Stat()
		f, off = nf, 0
		if sys, ok := st.Sys().(*syscall.Stat_t); ok {
			ino = sys.Ino
		}
		if fromEnd {
			off = st.Size()
		}
	}
	open(true)
	close(ready)
	defer func() {
		if f != nil {
			f.Close()
		}
	}()
	t := time.NewTicker(time.Second)
	defer t.Stop()
	buf := make([]byte, 32<<10)
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
		st, err := os.Stat(path)
		if err != nil {
			continue // rotated away; wait for the new file
		}
		if sys, ok := st.Sys().(*syscall.Stat_t); f == nil || (ok && sys.Ino != ino) || st.Size() < off {
			open(false)
			if f == nil {
				continue
			}
		}
		for off < st.Size() {
			n, err := f.ReadAt(buf, off)
			if n > 0 {
				lw.Write(buf[:n])
				off += int64(n)
			}
			if err != nil {
				if err != io.EOF {
					return
				}
				break
			}
		}
	}
}

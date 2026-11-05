package web

import (
	"context"
	"fmt"
	"html"
	"net/http"
	"strconv"
	"strings"
	"time"

	"hostpanel/internal/exec"
	"hostpanel/internal/jobs"
	"hostpanel/internal/logs"
)

func pathID(r *http.Request) (int64, bool) {
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	return id, err == nil && id > 0
}

// --- Activity log ---

type activityData struct {
	Entries []logs.Entry
	Filter  logs.Filter
	From    string
	To      string
	NextID  int64
	Query   string // current filter as query string, for "load more"
	OpenID  int64
}

func parseActivityFilter(r *http.Request) (logs.Filter, string, string) {
	q := r.URL.Query()
	f := logs.Filter{
		Action:   strings.TrimSpace(q.Get("action")),
		Status:   q.Get("status"),
		Source:   q.Get("source"),
		Text:     strings.TrimSpace(q.Get("q")),
		TargetID: strings.TrimSpace(q.Get("target")),
		Limit:    50,
	}
	f.BeforeID, _ = strconv.ParseInt(q.Get("before"), 10, 64)
	from, to := q.Get("from"), q.Get("to")
	if t, err := time.ParseInLocation("2006-01-02", from, time.Local); err == nil {
		f.From = t
	}
	if t, err := time.ParseInLocation("2006-01-02", to, time.Local); err == nil {
		f.To = t.AddDate(0, 0, 1)
	}
	return f, from, to
}

func (s *Server) activityList(w http.ResponseWriter, r *http.Request) {
	f, from, to := parseActivityFilter(r)
	entries, err := s.Activity.Query(r.Context(), f)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	d := activityData{Entries: entries, Filter: f, From: from, To: to}
	d.OpenID, _ = strconv.ParseInt(r.URL.Query().Get("open"), 10, 64)
	if len(entries) == f.Limit {
		d.NextID = entries[len(entries)-1].ID
	}
	q := r.URL.Query()
	q.Del("before")
	q.Del("open")
	d.Query = q.Encode()
	block := "layout"
	if isHX(r) {
		block = "activity-rows"
		if f.BeforeID == 0 {
			block = "activity-table"
		}
	}
	s.render(w, r, http.StatusOK, "logs_activity", block, Page{Title: "Log Merkezi", Nav: "logs", Data: d})
}

func (s *Server) activityDetail(w http.ResponseWriter, r *http.Request) {
	id, ok := pathID(r)
	if !ok {
		http.NotFound(w, r)
		return
	}
	e, err := s.Activity.Get(r.Context(), id)
	if err != nil {
		http.NotFound(w, r)
		return
	}
	var job *jobs.Job
	if e.JobID > 0 {
		if j, err := s.Jobs.Get(r.Context(), e.JobID); err == nil {
			job = &j
		}
	}
	s.render(w, r, http.StatusOK, "logs_activity", "activity-detail", Page{Data: map[string]any{"E": e, "Job": job}})
}

// --- Jobs ---

func (s *Server) jobList(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	before, _ := strconv.ParseInt(q.Get("before"), 10, 64)
	list, err := s.Jobs.List(r.Context(), q.Get("status"), q.Get("kind"), "", before, 50)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	var next int64
	if len(list) == 50 {
		next = list[len(list)-1].ID
	}
	block := "layout"
	if isHX(r) {
		block = "job-table"
	}
	s.render(w, r, http.StatusOK, "logs_jobs", block, Page{Title: "İş Logları", Nav: "logs",
		Data: map[string]any{"Jobs": list, "Status": q.Get("status"), "Kind": q.Get("kind"), "NextID": next}})
}

func (s *Server) jobDetail(w http.ResponseWriter, r *http.Request) {
	id, ok := pathID(r)
	if !ok {
		http.NotFound(w, r)
		return
	}
	j, err := s.Jobs.Get(r.Context(), id)
	if err != nil {
		http.NotFound(w, r)
		return
	}
	s.render(w, r, http.StatusOK, "logs_job", "layout", Page{Title: "İş #" + strconv.FormatInt(id, 10), Nav: "logs",
		Data: map[string]any{"Job": j, "Active": s.Jobs.IsActive(id)}})
}

func (s *Server) jobCancel(w http.ResponseWriter, r *http.Request) {
	id, _ := pathID(r)
	s.Jobs.Cancel(id)
	w.Header().Set("HX-Refresh", "true")
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) jobRetry(w http.ResponseWriter, r *http.Request) {
	id, _ := pathID(r)
	nid, err := s.Jobs.Retry(r.Context(), id)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	w.Header().Set("HX-Redirect", fmt.Sprintf("/logs/jobs/%d", nid))
	w.WriteHeader(http.StatusNoContent)
}

// jobStream sends a job's output over SSE: first the lines already in the log
// file, then live lines. Event ids are line numbers, so a reconnecting
// EventSource (Last-Event-ID) resumes without duplicates.
func (s *Server) jobStream(w http.ResponseWriter, r *http.Request) {
	id, ok := pathID(r)
	if !ok {
		http.NotFound(w, r)
		return
	}
	flusher, ok := w.(http.Flusher)
	if !ok {
		http.Error(w, "streaming unsupported", http.StatusInternalServerError)
		return
	}
	h := w.Header()
	h.Set("Content-Type", "text/event-stream")
	h.Set("Cache-Control", "no-cache")
	h.Set("X-Accel-Buffering", "no") // disable nginx buffering
	lastID, _ := strconv.ParseInt(r.Header.Get("Last-Event-ID"), 10, 64)

	// Subscribe before reading the file so no line can fall between the two.
	var events <-chan jobs.Event
	if s.Jobs.IsActive(id) {
		ch, unsub := s.Jobs.Broker().Subscribe(id)
		defer unsub()
		events = ch
	}
	send := func(event, id, data string) error {
		if id != "" {
			fmt.Fprintf(w, "id: %s\n", id)
		}
		_, err := fmt.Fprintf(w, "event: %s\ndata: %s\n\n", event, data)
		return err
	}
	lineHTML := func(s string) string {
		cls := ""
		if strings.Contains(s, "HATA") || strings.Contains(s, "ERROR") {
			cls = ` class="err"`
		} else if strings.Contains(s, "[DRY-RUN]") {
			cls = ` class="dry"`
		}
		return "<div" + cls + ">" + html.EscapeString(s) + "</div>"
	}
	var seq int64
	n, err := jobs.ReplayFile(s.Jobs.LogPath(id), func(line string) error {
		seq++
		if seq <= lastID {
			return nil
		}
		return send("line", strconv.FormatInt(seq, 10), lineHTML(line))
	})
	if err != nil {
		return
	}
	flusher.Flush()

	if events == nil { // job already finished
		j, _ := s.Jobs.Get(r.Context(), id)
		send("done", "", statusBadge(j.Status))
		flusher.Flush()
		return
	}
	heartbeat := time.NewTicker(25 * time.Second)
	defer heartbeat.Stop()
	for {
		select {
		case <-r.Context().Done():
			return
		case <-heartbeat.C:
			if _, err := fmt.Fprint(w, ": ping\n\n"); err != nil {
				return
			}
			flusher.Flush()
		case ev, open := <-events:
			if !open {
				// Job finished (or we were too slow). Report the final state if known.
				j, err := s.Jobs.Get(context.WithoutCancel(r.Context()), id)
				if err == nil && j.Done() {
					send("progress", "", progressHTML(j.Progress))
					send("done", "", statusBadge(j.Status))
				}
				flusher.Flush()
				return
			}
			switch ev.Type {
			case jobs.EventLine:
				if ev.Seq <= n || ev.Seq <= lastID {
					continue // already sent from the file
				}
				send("line", strconv.FormatInt(ev.Seq, 10), lineHTML(ev.Data))
			case jobs.EventProgress:
				p, _ := strconv.Atoi(ev.Data)
				send("progress", "", progressHTML(p))
			case jobs.EventStatus:
				send("status", "", statusBadge(ev.Data))
			}
			flusher.Flush()
		}
	}
}

func progressHTML(p int) string {
	return fmt.Sprintf(`<progress max="100" value="%d"></progress> <span>%%%d</span>`, p, p)
}

func statusBadge(status string) string {
	label, _ := funcs["statusLabel"].(func(string) string)
	return `<span class="badge ` + html.EscapeString(status) + `">` + html.EscapeString(label(status)) + `</span>`
}

// --- self test job (exercises runner, helper scripts, job log and SSE end-to-end) ---

func (s *Server) selftestHandler(ctx context.Context, l *jobs.Log, _ map[string]any) error {
	c := exec.Helper(s.Cfg.ScriptsDir, "hp-selftest.sh", "ping")
	c.Output = l
	if _, err := s.Runner.Run(ctx, c); err != nil {
		return err
	}
	for i := 1; i <= 5; i++ {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(time.Second):
		}
		l.Printf("Adım %d/5 tamamlandı", i)
		l.Progress(i * 20)
	}
	return nil
}

// RegisterJobs binds job kinds owned by the web layer.
func (s *Server) RegisterJobs() {
	s.Jobs.Register("system.selftest", s.selftestHandler)
}

func (s *Server) selftestStart(w http.ResponseWriter, r *http.Request) {
	id, err := s.Jobs.Submit(r.Context(), jobs.Spec{Kind: "system.selftest", Summary: "Sistem öz testi", Retryable: true})
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	w.Header().Set("HX-Redirect", fmt.Sprintf("/logs/jobs/%d", id))
	w.WriteHeader(http.StatusNoContent)
}

// --- System logs (Faz 0: panel's own logs; more sources in Faz 5) ---

var systemSources = []struct{ ID, Label string }{
	{"panel", "Panel logu"},
	{"auth", "Panel giriş denemeleri"},
	{"certbot", "certbot (SSL yenileme)"},
}

func (s *Server) journalLines(ctx context.Context, unit string, n int) []string {
	res, err := s.Sites.Probe.Run(ctx, exec.Cmd{Name: "journalctl", Args: []string{"-u", unit, "-n", strconv.Itoa(n), "--no-pager", "-o", "short-iso"},
		Timeout: 10 * time.Second})
	out := strings.TrimRight(res.Stdout, "\n")
	if err != nil && out == "" {
		return []string{"(journal okunamadı: " + err.Error() + ")"}
	}
	if out == "" {
		return nil
	}
	return strings.Split(out, "\n")
}

func (s *Server) systemLogs(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	src := q.Get("source")
	path := s.Cfg.PanelLogPath()
	switch src {
	case "auth":
		path = s.Cfg.AuthLogPath()
	case "certbot":
		path = ""
	default:
		src = "panel"
	}
	n, _ := strconv.Atoi(q.Get("n"))
	if n != 500 && n != 1000 {
		n = 100
	}
	text := strings.TrimSpace(q.Get("q"))
	level := q.Get("level")
	var lines []string
	var err error
	if path == "" {
		// /var/log/letsencrypt is root-only; the systemd journal is readable
		// by the systemd-journal group without sudo.
		lines = s.journalLines(r.Context(), "certbot.service", n)
	} else if lines, err = logs.TailLines(path, n); err != nil {
		lines = []string{"(log okunamadı: " + err.Error() + ")"}
	}
	if text != "" || level != "" {
		filtered := lines[:0]
		for _, l := range lines {
			if text != "" && !strings.Contains(strings.ToLower(l), strings.ToLower(text)) {
				continue
			}
			if level != "" && !strings.Contains(l, `"level":"`+strings.ToUpper(level)+`"`) {
				continue
			}
			filtered = append(filtered, l)
		}
		lines = filtered
	}
	if q.Get("download") == "1" {
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		w.Header().Set("Content-Disposition", fmt.Sprintf(`attachment; filename="%s-%s.log"`, src, time.Now().Format("20060102-150405")))
		for _, l := range lines {
			fmt.Fprintln(w, l)
		}
		return
	}
	block := "layout"
	if isHX(r) {
		block = "syslog-lines"
	}
	s.render(w, r, http.StatusOK, "logs_system", block, Page{Title: "Sistem Logları", Nav: "logs", Data: map[string]any{
		"Sources": systemSources, "Source": src, "N": n, "Q": text, "Level": level, "Lines": lines,
	}})
}

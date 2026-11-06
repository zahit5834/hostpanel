// Package update checks GitHub Releases for a newer panel version and starts
// the self-update. The update itself (download, verification, restart, health
// check, rollback) is done by root in deploy/scripts/hp-update.sh, outside the
// panel's own service; the panel only picks the version and later records the
// outcome that hp-update.sh leaves in status.json.
package update

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/zahit5834/hostpanel/internal/exec"
	"github.com/zahit5834/hostpanel/internal/logs"
	"github.com/zahit5834/hostpanel/internal/notify"
	"github.com/zahit5834/hostpanel/internal/store"
)

// Default locations written by hp-update.sh.
const (
	DefaultStatusPath = "/var/lib/hostpanel-update/status.json"
	DefaultAPI        = "https://api.github.com"
	// CheckEvery is how old the cached release info may get before a page view refreshes it.
	CheckEvery = time.Hour
)

// Settings keys.
const (
	setLatest   = "update_latest"      // JSON Release
	setChecked  = "update_checked_at"  // RFC3339
	setCheckErr = "update_check_error" // last error text
	setNotified = "update_notified"    // tag we already sent a notification for
	setRecorded = "update_recorded_id" // status.json id already written to the activity log
)

// Status states (status.json).
const (
	StateRunning    = "running"
	StateSuccess    = "success"
	StateRolledBack = "rolled_back"
	StateFailed     = "failed"
)

var tagRe = regexp.MustCompile(`^v(\d{1,4})\.(\d{1,4})\.(\d{1,4})$`)

// ValidTag reports whether t is a release tag hp-update.sh accepts.
func ValidTag(t string) bool { return tagRe.MatchString(t) }

// parse returns the numeric parts of a vX.Y.Z tag.
func parse(t string) ([3]int, bool) {
	m := tagRe.FindStringSubmatch(t)
	if m == nil {
		return [3]int{}, false
	}
	var v [3]int
	for i := range v {
		v[i], _ = strconv.Atoi(m[i+1])
	}
	return v, true
}

// Newer reports whether tag a is a higher version than b (both vX.Y.Z).
func Newer(a, b string) bool {
	va, ok1 := parse(a)
	vb, ok2 := parse(b)
	if !ok1 || !ok2 {
		return false
	}
	for i := range va {
		if va[i] != vb[i] {
			return va[i] > vb[i]
		}
	}
	return false
}

// Release is the part of the GitHub release we show.
type Release struct {
	Tag       string    `json:"tag"`
	Name      string    `json:"name"`
	Notes     string    `json:"notes"`
	URL       string    `json:"url"`
	Published time.Time `json:"published"`
}

// Status mirrors hp-update.sh's status.json.
type Status struct {
	ID         string `json:"id"`
	From       string `json:"from"`
	To         string `json:"to"`
	State      string `json:"state"`
	Step       string `json:"step"`
	Reason     string `json:"reason"`
	StartedAt  string `json:"started_at"`
	FinishedAt string `json:"finished_at"`
}

// Done reports whether the update has finished (whatever the outcome).
func (s Status) Done() bool { return s.State != "" && s.State != StateRunning }

// Info is what the settings page shows.
type Info struct {
	Current   string
	Latest    Release
	CheckedAt time.Time
	CheckErr  string
	Available bool   // Latest is newer than Current
	CanUpdate bool   // Available and the current build is a release
	Reason    string // why CanUpdate is false
	Status    Status // last/ongoing update
	Repo      string
}

// Service checks for releases and hands updates to the root helper.
type Service struct {
	DB         *sql.DB
	Runner     exec.Runner
	ScriptsDir string
	Activity   *logs.Activity
	Log        *slog.Logger
	Notify     func(context.Context, notify.Event)
	Version    string // running version (main.version)
	Repo       string // owner/name
	API        string // GitHub API base; DefaultAPI when empty
	StatusPath string // DefaultStatusPath when empty
	LogPath    string // root's update.log (readable by the panel group)
	Dev        bool
	Client     *http.Client
}

func (s *Service) api() string {
	if s.API != "" {
		return strings.TrimRight(s.API, "/")
	}
	return DefaultAPI
}

func (s *Service) statusPath() string {
	if s.StatusPath != "" {
		return s.StatusPath
	}
	return DefaultStatusPath
}

func (s *Service) client() *http.Client {
	if s.Client != nil {
		return s.Client
	}
	return &http.Client{Timeout: 15 * time.Second}
}

// Check asks GitHub for the latest release and caches the answer in settings.
// It notifies once per new tag.
func (s *Service) Check(ctx context.Context) (Release, error) {
	rel, err := s.fetch(ctx)
	now := time.Now().UTC().Format(time.RFC3339)
	store.SetSetting(ctx, s.DB, setChecked, now)
	if err != nil {
		store.SetSetting(ctx, s.DB, setCheckErr, err.Error())
		return Release{}, err
	}
	store.SetSetting(ctx, s.DB, setCheckErr, "")
	b, _ := json.Marshal(rel)
	store.SetSetting(ctx, s.DB, setLatest, string(b))
	if Newer(rel.Tag, s.Version) && store.GetSetting(ctx, s.DB, setNotified, "") != rel.Tag {
		store.SetSetting(ctx, s.DB, setNotified, rel.Tag)
		if s.Notify != nil {
			s.Notify(ctx, notify.Event{Kind: notify.KindUpdate, Key: "update:" + rel.Tag,
				Title: "Panel güncellemesi mevcut: " + rel.Tag,
				Text:  fmt.Sprintf("Çalışan sürüm %s. Ayarlar → Güncelleme sayfasından kurabilirsiniz.", s.Version)})
		}
	}
	return rel, nil
}

func (s *Service) fetch(ctx context.Context) (Release, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, s.api()+"/repos/"+s.Repo+"/releases/latest", nil)
	if err != nil {
		return Release{}, err
	}
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("User-Agent", "hostpanel/"+s.Version)
	resp, err := s.client().Do(req)
	if err != nil {
		return Release{}, fmt.Errorf("GitHub'a ulaşılamadı: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusNotFound {
		return Release{}, fmt.Errorf("%s deposunda yayınlanmış sürüm yok", s.Repo)
	}
	if resp.StatusCode != http.StatusOK {
		return Release{}, fmt.Errorf("GitHub yanıtı: %s", resp.Status)
	}
	var raw struct {
		Tag       string    `json:"tag_name"`
		Name      string    `json:"name"`
		Body      string    `json:"body"`
		URL       string    `json:"html_url"`
		Published time.Time `json:"published_at"`
		Draft     bool      `json:"draft"`
		Pre       bool      `json:"prerelease"`
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(&raw); err != nil {
		return Release{}, fmt.Errorf("GitHub yanıtı okunamadı: %w", err)
	}
	if !ValidTag(raw.Tag) {
		return Release{}, fmt.Errorf("son sürümün etiketi beklenen biçimde değil: %q", raw.Tag)
	}
	if len(raw.Body) > 8000 {
		raw.Body = raw.Body[:8000] + "…"
	}
	return Release{Tag: raw.Tag, Name: raw.Name, Notes: raw.Body, URL: raw.URL, Published: raw.Published}, nil
}

// Info returns the cached state; it refreshes from GitHub when the cache is
// older than CheckEvery and refresh is set.
func (s *Service) Info(ctx context.Context, refresh bool) Info {
	in := Info{Current: s.Version, Repo: s.Repo}
	in.CheckedAt, _ = time.Parse(time.RFC3339, store.GetSetting(ctx, s.DB, setChecked, ""))
	if refresh && time.Since(in.CheckedAt) > CheckEvery {
		s.Check(ctx)
		in.CheckedAt, _ = time.Parse(time.RFC3339, store.GetSetting(ctx, s.DB, setChecked, ""))
	}
	json.Unmarshal([]byte(store.GetSetting(ctx, s.DB, setLatest, "{}")), &in.Latest)
	in.CheckErr = store.GetSetting(ctx, s.DB, setCheckErr, "")
	in.Status, _ = s.ReadStatus()
	in.Available = Newer(in.Latest.Tag, s.Version)
	switch {
	case !ValidTag(s.Version):
		in.Reason = "Bu bir geliştirme derlemesi (" + s.Version + "); panelden güncelleme yalnızca release sürümlerinde çalışır."
	case !in.Available:
		in.Reason = "Güncel sürüm kullanılıyor."
	case in.Status.State == StateRunning:
		in.Reason = "Bir güncelleme sürüyor."
	default:
		in.CanUpdate = true
	}
	return in
}

// ReadStatus reads status.json (missing file = zero Status).
func (s *Service) ReadStatus() (Status, error) {
	var st Status
	b, err := os.ReadFile(s.statusPath())
	if errors.Is(err, os.ErrNotExist) {
		return st, nil
	}
	if err != nil {
		return st, err
	}
	if len(b) > 64<<10 {
		return st, errors.New("status.json çok büyük")
	}
	err = json.Unmarshal(b, &st)
	return st, err
}

// Start hands the update to hp-update.sh, which runs it in its own unit and
// restarts the panel. Only the latest known release, and only when newer.
func (s *Service) Start(ctx context.Context, tag string) error {
	in := s.Info(ctx, false)
	if !ValidTag(tag) || tag != in.Latest.Tag {
		return errors.New("yalnızca en son yayınlanan sürüme güncellenebilir; önce 'Şimdi kontrol et'")
	}
	if !in.CanUpdate {
		return errors.New(in.Reason)
	}
	_, err := s.Runner.Run(ctx, exec.Helper(s.ScriptsDir, "hp-update.sh", "start", tag))
	status := "success"
	if err != nil {
		status = "failed"
	}
	s.Activity.Record(ctx, logs.Entry{Action: "panel.update.start", TargetType: "panel", Status: status,
		Summary: fmt.Sprintf("Panel güncellemesi başlatıldı: %s → %s", s.Version, tag), Error: errString(err)},
		map[string]any{"from": s.Version, "to": tag})
	if err != nil {
		return fmt.Errorf("güncelleme başlatılamadı: %w", err)
	}
	return nil
}

// RecordFinished writes a finished update from status.json to the activity log
// once (called at startup: the new — or rolled back — panel reports the result).
func (s *Service) RecordFinished(ctx context.Context) {
	st, err := s.ReadStatus()
	if err != nil || !st.Done() || st.ID == "" || store.GetSetting(ctx, s.DB, setRecorded, "") == st.ID {
		return
	}
	store.SetSetting(ctx, s.DB, setRecorded, st.ID)
	e := logs.Entry{Action: "panel.update", TargetType: "panel", Source: logs.SourceSystem}
	var title string
	switch st.State {
	case StateSuccess:
		e.Status, e.Summary = "success", fmt.Sprintf("Panel güncellendi: %s → %s", st.From, st.To)
		title = "Panel güncellendi: " + st.To
	case StateRolledBack:
		e.Status, e.Summary = "failed", fmt.Sprintf("Panel güncellemesi geri alındı (%s → %s): %s", st.From, st.To, st.Reason)
		e.Error = st.Reason
		title = "Panel güncellemesi geri alındı"
	default:
		e.Status, e.Summary = "failed", fmt.Sprintf("Panel güncellemesi başarısız (%s → %s): %s", st.From, st.To, st.Reason)
		e.Error = st.Reason
		title = "Panel güncellemesi başarısız"
	}
	params := map[string]any{"from": st.From, "to": st.To, "state": st.State, "step": st.Step,
		"started_at": st.StartedAt, "finished_at": st.FinishedAt}
	if s.LogPath != "" {
		if lines, err := logs.TailLines(s.LogPath, 40); err == nil {
			params["log"] = strings.Join(lines, "\n")
		}
	}
	s.Activity.Record(ctx, e, params)
	if s.Notify != nil {
		s.Notify(ctx, notify.Event{Kind: notify.KindUpdate, Key: "update-result:" + st.ID, Title: title, Text: e.Summary})
	}
	if s.Log != nil {
		s.Log.Info("panel update recorded", "state", st.State, "from", st.From, "to", st.To)
	}
}

func errString(err error) string {
	if err == nil {
		return ""
	}
	return err.Error()
}

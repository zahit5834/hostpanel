// Package images checks the registries for newer container images of the
// services the panel runs (SQL Server, docker-mailserver) and notifies once
// per new tag. Only updates within the running major line are offered for
// one-click install (SQL Server: same year and OS, newer CU/GDR;
// docker-mailserver: same major, newer minor/patch/revision); a new major
// line is shown as information only (it can change data formats or
// configuration). The update itself is a job of the owning service.
package images

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/zahit5834/hostpanel/internal/notify"
	"github.com/zahit5834/hostpanel/internal/store"
)

// Engine ids.
const (
	MSSQL = "mssql"
	Mail  = "mail"
)

// Repositories (image names without tag).
const (
	MSSQLRepo = "mcr.microsoft.com/mssql/server"
	MailRepo  = "mailserver/docker-mailserver"
)

// Default registry endpoints (anonymous, read-only).
const (
	DefaultMCR = "https://mcr.microsoft.com"
	DefaultHub = "https://hub.docker.com"
)

// --- SQL Server tags: YYYY-CU<n>[-GDR<m>]-ubuntu-<os> ---

var mssqlTagRe = regexp.MustCompile(`^(20[0-9][0-9])-CU([0-9]+)(?:-GDR([0-9]+))?-(ubuntu-[0-9]+\.[0-9]+)$`)

type mssqlVer struct {
	year, cu, gdr int
	os            string
}

func parseMSSQL(tag string) (mssqlVer, bool) {
	m := mssqlTagRe.FindStringSubmatch(tag)
	if m == nil {
		return mssqlVer{}, false
	}
	var v mssqlVer
	v.year, _ = strconv.Atoi(m[1])
	v.cu, _ = strconv.Atoi(m[2])
	if m[3] != "" {
		v.gdr, _ = strconv.Atoi(m[3])
	}
	v.os = m[4]
	return v, v.cu < 1000 && v.gdr < 1000
}

func (a mssqlVer) newer(b mssqlVer) bool {
	if a.cu != b.cu {
		return a.cu > b.cu
	}
	return a.gdr > b.gdr
}

// PickMSSQL returns the newest tag in the running line (same year and OS)
// and, separately, the newest tag of a newer year (information only).
func PickMSSQL(current string, tags []string) (latest, major string) {
	cur, ok := parseMSSQL(current)
	if !ok {
		return "", ""
	}
	best, bestMajor := cur, mssqlVer{}
	for _, t := range tags {
		v, ok := parseMSSQL(t)
		if !ok || v.os != cur.os {
			continue
		}
		switch {
		case v.year == cur.year && v.newer(best):
			best, latest = v, t
		case v.year > cur.year && (bestMajor.year < v.year || (bestMajor.year == v.year && v.newer(bestMajor))):
			bestMajor, major = v, t
		}
	}
	return latest, major
}

// --- docker-mailserver tags: X.Y.Z-rN (immutable revisions) ---

var mailTagRe = regexp.MustCompile(`^([0-9]+)\.([0-9]+)\.([0-9]+)(?:-r([0-9]+))?$`)

func parseMail(tag string) ([4]int, bool) {
	m := mailTagRe.FindStringSubmatch(tag)
	if m == nil {
		return [4]int{}, false
	}
	var v [4]int
	for i := 0; i < 4; i++ {
		if m[i+1] != "" {
			v[i], _ = strconv.Atoi(m[i+1])
		}
		if v[i] > 9999 {
			return v, false
		}
	}
	return v, true
}

func mailNewer(a, b [4]int) bool {
	for i := range a {
		if a[i] != b[i] {
			return a[i] > b[i]
		}
	}
	return false
}

// PickMail returns the newest revision tag (X.Y.Z-rN; the plain X.Y.Z tags
// move) of the running major and the newest tag of a newer major.
func PickMail(current string, tags []string) (latest, major string) {
	cur, ok := parseMail(current)
	if !ok {
		return "", ""
	}
	best, bestMajor := cur, [4]int{}
	for _, t := range tags {
		if !strings.Contains(t, "-r") {
			continue
		}
		v, ok := parseMail(t)
		if !ok {
			continue
		}
		switch {
		case v[0] == cur[0] && mailNewer(v, best):
			best, latest = v, t
		case v[0] > cur[0] && mailNewer(v, bestMajor):
			bestMajor, major = v, t
		}
	}
	return latest, major
}

// Tag returns the part after the last ':' of an image reference.
func Tag(image string) string {
	if i := strings.LastIndexByte(image, ':'); i >= 0 {
		return image[i+1:]
	}
	return ""
}

// Repo returns the part before the last ':'.
func Repo(image string) string {
	if i := strings.LastIndexByte(image, ':'); i >= 0 {
		return image[:i]
	}
	return image
}

// IsUpdate reports whether target is an offered update for current: same
// repository, and the newest-in-line pick among {target}.
func IsUpdate(engine, current, target string) bool {
	if Repo(current) != Repo(target) {
		return false
	}
	var latest string
	switch engine {
	case MSSQL:
		latest, _ = PickMSSQL(Tag(current), []string{Tag(target)})
	case Mail:
		latest, _ = PickMail(Tag(current), []string{Tag(target)})
	}
	return latest != "" && latest == Tag(target)
}

// --- check service ---

// Info is the cached result of one engine's check.
type Info struct {
	Engine    string    `json:"engine"`
	Label     string    `json:"label"`
	Current   string    `json:"current"`    // running image
	Latest    string    `json:"latest"`     // full image of the offered update ("" = up to date)
	NewMajor  string    `json:"new_major"`  // full image of a newer major line (information)
	CheckedAt time.Time `json:"checked_at"` //
	Err       string    `json:"err"`
	Installed bool      `json:"-"`
}

// Available reports whether an update can be installed.
func (i Info) Available() bool { return i.Latest != "" && i.Latest != i.Current }

// Engine describes one checked service.
type Engine struct {
	ID, Label string
	Current   func(ctx context.Context) string // running image, "" when not installed
}

// Service runs the checks.
type Service struct {
	DB      *sql.DB
	Engines []Engine
	Notify  func(context.Context, notify.Event)
	Log     *slog.Logger
	Client  *http.Client
	MCR     string // DefaultMCR when empty
	Hub     string // DefaultHub when empty
	Version string // User-Agent
}

func (s *Service) client() *http.Client {
	if s.Client != nil {
		return s.Client
	}
	return &http.Client{Timeout: 20 * time.Second}
}

func setKey(id string) string      { return "image_info_" + id }
func notifiedKey(id string) string { return "image_notified_" + id }

// Infos returns the cached check results of the installed engines.
func (s *Service) Infos(ctx context.Context) []Info {
	var out []Info
	for _, e := range s.Engines {
		if i, ok := s.Info(ctx, e.ID); ok {
			out = append(out, i)
		}
	}
	return out
}

// Info returns engine id's cached result, refreshed with the running image
// (ok is false when the engine is not installed).
func (s *Service) Info(ctx context.Context, id string) (Info, bool) {
	for _, e := range s.Engines {
		if e.ID != id {
			continue
		}
		cur := e.Current(ctx)
		if cur == "" {
			return Info{}, false
		}
		var i Info
		json.Unmarshal([]byte(store.GetSetting(ctx, s.DB, setKey(id), "{}")), &i)
		i.Engine, i.Label, i.Installed = e.ID, e.Label, true
		if i.Current != cur { // updated (or reinstalled) since the check
			i.Latest, i.NewMajor = "", ""
			if i.Current != "" {
				i.CheckedAt = time.Time{}
			}
			i.Current = cur
		}
		return i, true
	}
	return Info{}, false
}

// Check asks the registries about every installed engine, caches the
// answers and sends one notification per new tag.
func (s *Service) Check(ctx context.Context) []Info {
	var out []Info
	for _, e := range s.Engines {
		cur := e.Current(ctx)
		if cur == "" {
			continue
		}
		i := Info{Engine: e.ID, Label: e.Label, Current: cur, CheckedAt: time.Now().UTC(), Installed: true}
		latest, major, err := s.fetch(ctx, e.ID, cur)
		if err != nil {
			i.Err = err.Error()
			if s.Log != nil {
				s.Log.Warn("image check failed", "engine", e.ID, "err", err)
			}
		} else {
			i.Latest, i.NewMajor = latest, major
		}
		b, _ := json.Marshal(i)
		store.SetSetting(ctx, s.DB, setKey(e.ID), string(b))
		if i.Available() && store.GetSetting(ctx, s.DB, notifiedKey(e.ID), "") != i.Latest {
			store.SetSetting(ctx, s.DB, notifiedKey(e.ID), i.Latest)
			if s.Notify != nil {
				page := "Veritabanları → MSSQL"
				if e.ID == Mail {
					page = "E-posta"
				}
				s.Notify(ctx, notify.Event{Kind: notify.KindUpdate, Key: "image:" + i.Latest,
					Title: e.Label + " güncellemesi mevcut: " + Tag(i.Latest),
					Text:  fmt.Sprintf("Çalışan imaj %s. %s sayfasından kurabilirsiniz.", Tag(cur), page)})
			}
		}
		out = append(out, i)
	}
	return out
}

func (s *Service) fetch(ctx context.Context, id, current string) (latest, major string, err error) {
	switch id {
	case MSSQL:
		tags, err := s.mcrTags(ctx)
		if err != nil {
			return "", "", err
		}
		l, m := PickMSSQL(Tag(current), tags)
		return withRepo(MSSQLRepo, l), withRepo(MSSQLRepo, m), nil
	case Mail:
		tags, err := s.hubTags(ctx)
		if err != nil {
			return "", "", err
		}
		l, m := PickMail(Tag(current), tags)
		return withRepo(MailRepo, l), withRepo(MailRepo, m), nil
	}
	return "", "", errors.New("bilinmeyen servis")
}

func withRepo(repo, tag string) string {
	if tag == "" {
		return ""
	}
	return repo + ":" + tag
}

func (s *Service) get(ctx context.Context, url string, v any) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return err
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", "hostpanel/"+s.Version)
	resp, err := s.client().Do(req)
	if err != nil {
		return fmt.Errorf("kayıt deposuna ulaşılamadı: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("kayıt deposu yanıtı: %s", resp.Status)
	}
	return json.NewDecoder(io.LimitReader(resp.Body, 2<<20)).Decode(v)
}

// mcrTags lists mcr.microsoft.com/mssql/server tags (Docker registry v2,
// anonymous).
func (s *Service) mcrTags(ctx context.Context) ([]string, error) {
	base := s.MCR
	if base == "" {
		base = DefaultMCR
	}
	var r struct {
		Tags []string `json:"tags"`
	}
	if err := s.get(ctx, strings.TrimRight(base, "/")+"/v2/mssql/server/tags/list", &r); err != nil {
		return nil, err
	}
	return r.Tags, nil
}

// hubTags lists the 100 most recently pushed docker-mailserver tags.
func (s *Service) hubTags(ctx context.Context) ([]string, error) {
	base := s.Hub
	if base == "" {
		base = DefaultHub
	}
	var r struct {
		Results []struct {
			Name string `json:"name"`
		} `json:"results"`
	}
	if err := s.get(ctx, strings.TrimRight(base, "/")+"/v2/namespaces/mailserver/repositories/docker-mailserver/tags?page_size=100&ordering=last_updated", &r); err != nil {
		return nil, err
	}
	out := make([]string, 0, len(r.Results))
	for _, t := range r.Results {
		out = append(out, t.Name)
	}
	return out, nil
}

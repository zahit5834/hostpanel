// Package domains tracks the registration expiry of the domains the panel
// serves (Faz 12, I4). Dates come from RDAP (the registries' official JSON
// service, located through IANA's bootstrap file) once a day; TLDs without
// RDAP (e.g. .tr) take a manually entered date. Notifications go out at
// 30/15/7 days, once per threshold and expiry date.
package domains

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"slices"
	"strings"
	"time"
)

const (
	BootstrapURL = "https://data.iana.org/rdap/dns.json"
	SourceRDAP   = "rdap"
	SourceManual = "manual"
	recheck      = 20 * time.Hour
	maxBody      = 512 << 10
)

// Thresholds are the notification points in days before expiry (descending).
var Thresholds = []int{30, 15, 7}

// secondLevel lists public suffixes with two labels that matter here; any
// other name is registrable at its last two labels.
var secondLevel = map[string]bool{
	"com.tr": true, "net.tr": true, "org.tr": true, "gen.tr": true, "web.tr": true, "biz.tr": true, "info.tr": true,
	"av.tr": true, "dr.tr": true, "bel.tr": true, "pol.tr": true, "edu.tr": true, "gov.tr": true, "k12.tr": true,
	"tv.tr": true, "name.tr": true, "tel.tr": true, "bbs.tr": true, "kep.tr": true, "tsk.tr": true,
	"co.uk": true, "org.uk": true, "me.uk": true, "ltd.uk": true, "plc.uk": true, "ac.uk": true, "gov.uk": true,
	"com.au": true, "net.au": true, "org.au": true, "co.nz": true, "co.jp": true, "com.br": true, "com.cn": true,
	"co.za": true, "com.mx": true, "com.ar": true, "co.in": true, "com.sg": true, "com.cy": true, "com.az": true,
}

// Registrable reduces a host name to the name that is registered
// ("www.shop.ornek.com.tr" → "ornek.com.tr"). "" for single labels.
func Registrable(host string) string {
	host = strings.TrimSuffix(strings.ToLower(strings.TrimSpace(host)), ".")
	labels := strings.Split(host, ".")
	if len(labels) < 2 || slices.Contains(labels, "") {
		return ""
	}
	n := 2
	if secondLevel[strings.Join(labels[len(labels)-2:], ".")] {
		n = 3
	}
	if len(labels) < n {
		return "" // the name is a public suffix itself
	}
	return strings.Join(labels[len(labels)-n:], ".")
}

// TLD of a registrable name.
func TLD(name string) string { return name[strings.LastIndexByte(name, '.')+1:] }

// Entry is one tracked domain.
type Entry struct {
	Name      string
	ExpiresAt time.Time // zero = unknown
	Source    string
	Registrar string
	CheckedAt time.Time
	Error     string
	Notified  int
}

// DaysLeft until expiry (whole days, negative after it).
func (e Entry) DaysLeft(now time.Time) int {
	return int(e.ExpiresAt.Sub(now).Hours() / 24)
}

// Service is the store + lookups.
type Service struct {
	DB     *sql.DB
	Log    *slog.Logger
	Client *http.Client
	// Bootstrap overrides BootstrapURL in tests.
	Bootstrap string
	// Notify receives threshold notifications (title, text, key).
	Notify func(ctx context.Context, title, text, key string)
}

const cols = `name, expires_at, source, registrar, checked_at, error, notified`

func scan(r interface{ Scan(...any) error }) (Entry, error) {
	var e Entry
	var exp, chk int64
	err := r.Scan(&e.Name, &exp, &e.Source, &e.Registrar, &chk, &e.Error, &e.Notified)
	if exp > 0 {
		e.ExpiresAt = time.Unix(exp, 0)
	}
	if chk > 0 {
		e.CheckedAt = time.Unix(chk, 0)
	}
	return e, err
}

// List returns all tracked domains, soonest expiry first (unknown last).
func (s *Service) List(ctx context.Context) ([]Entry, error) {
	rows, err := s.DB.QueryContext(ctx, `SELECT `+cols+` FROM domain_expiry ORDER BY expires_at = 0, expires_at, name`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Entry
	for rows.Next() {
		e, err := scan(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, e)
	}
	return out, rows.Err()
}

// Get returns one entry.
func (s *Service) Get(ctx context.Context, name string) (Entry, error) {
	return scan(s.DB.QueryRowContext(ctx, `SELECT `+cols+` FROM domain_expiry WHERE name=?`, name))
}

// Map indexes entries by name.
func (s *Service) Map(ctx context.Context) map[string]Entry {
	list, _ := s.List(ctx)
	m := make(map[string]Entry, len(list))
	for _, e := range list {
		m[e.Name] = e
	}
	return m
}

// Sync makes the table hold exactly the registrable names of hosts.
func (s *Service) Sync(ctx context.Context, hosts []string) error {
	want := map[string]bool{}
	for _, h := range hosts {
		if n := Registrable(h); n != "" {
			want[n] = true
		}
	}
	have := s.Map(ctx)
	for n := range want {
		if _, ok := have[n]; !ok {
			if _, err := s.DB.ExecContext(ctx, `INSERT OR IGNORE INTO domain_expiry(name) VALUES(?)`, n); err != nil {
				return err
			}
		}
	}
	for n := range have {
		if !want[n] {
			s.DB.ExecContext(ctx, `DELETE FROM domain_expiry WHERE name=?`, n)
		}
	}
	return nil
}

// SetManual stores a manually entered expiry date (zero date = back to RDAP).
func (s *Service) SetManual(ctx context.Context, name string, date time.Time) error {
	e, err := s.Get(ctx, name)
	if err != nil {
		return errors.New("alan adı bulunamadı")
	}
	if date.IsZero() {
		_, err = s.DB.ExecContext(ctx, `UPDATE domain_expiry SET source=?, expires_at=0, checked_at=0, notified=0, error='' WHERE name=?`,
			SourceRDAP, name)
		return err
	}
	now := time.Now()
	if date.Before(now.AddDate(-1, 0, 0)) || date.After(now.AddDate(15, 0, 0)) {
		return errors.New("tarih makul aralıkta değil")
	}
	notified := e.Notified
	if !date.Equal(e.ExpiresAt) {
		notified = 0
	}
	_, err = s.DB.ExecContext(ctx, `UPDATE domain_expiry SET source=?, expires_at=?, checked_at=?, error='', notified=? WHERE name=?`,
		SourceManual, date.Unix(), now.Unix(), notified, name)
	return err
}

func (s *Service) client() *http.Client {
	if s.Client != nil {
		return s.Client
	}
	return &http.Client{Timeout: 15 * time.Second}
}

func (s *Service) getJSON(ctx context.Context, url string, v any) (int, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return 0, err
	}
	req.Header.Set("Accept", "application/rdap+json, application/json")
	req.Header.Set("User-Agent", "HostPanel")
	res, err := s.client().Do(req)
	if err != nil {
		return 0, err
	}
	defer res.Body.Close()
	if res.StatusCode != http.StatusOK {
		io.Copy(io.Discard, io.LimitReader(res.Body, maxBody))
		return res.StatusCode, fmt.Errorf("HTTP %d", res.StatusCode)
	}
	return res.StatusCode, json.NewDecoder(io.LimitReader(res.Body, maxBody)).Decode(v)
}

// ParseBootstrap maps each TLD to its first RDAP base URL (https only).
func ParseBootstrap(r io.Reader) (map[string]string, error) {
	var b struct {
		Services [][][]string `json:"services"`
	}
	if err := json.NewDecoder(r).Decode(&b); err != nil {
		return nil, err
	}
	out := map[string]string{}
	for _, svc := range b.Services {
		if len(svc) < 2 {
			continue
		}
		base := ""
		for _, u := range svc[1] {
			if strings.HasPrefix(u, "https://") {
				base = u
				break
			}
		}
		if base == "" {
			continue
		}
		if !strings.HasSuffix(base, "/") {
			base += "/"
		}
		for _, tld := range svc[0] {
			out[strings.ToLower(tld)] = base
		}
	}
	return out, nil
}

// rdapDomain is the part of an RDAP domain object we read.
type rdapDomain struct {
	Events []struct {
		Action string `json:"eventAction"`
		Date   string `json:"eventDate"`
	} `json:"events"`
	Entities []struct {
		Roles []string          `json:"roles"`
		VCard []json.RawMessage `json:"vcardArray"`
	} `json:"entities"`
}

// ParseRDAP returns the expiration date and registrar name of an RDAP domain object.
func ParseRDAP(r io.Reader) (time.Time, string, error) {
	var d rdapDomain
	if err := json.NewDecoder(r).Decode(&d); err != nil {
		return time.Time{}, "", err
	}
	return d.expiry()
}

func (d rdapDomain) expiry() (time.Time, string, error) {
	var exp time.Time
	for _, e := range d.Events {
		if e.Action == "expiration" {
			t, err := time.Parse(time.RFC3339, e.Date)
			if err == nil {
				exp = t
			}
		}
	}
	reg := ""
	for _, ent := range d.Entities {
		if !slices.Contains(ent.Roles, "registrar") || len(ent.VCard) < 2 {
			continue
		}
		var props [][]any
		if json.Unmarshal(ent.VCard[1], &props) != nil {
			continue
		}
		for _, p := range props {
			if len(p) >= 4 && p[0] == "fn" {
				if v, ok := p[3].(string); ok {
					reg = v
				}
			}
		}
	}
	if len(reg) > 120 {
		reg = reg[:120]
	}
	if exp.IsZero() {
		return exp, reg, errors.New("kayıtta bitiş tarihi yok")
	}
	return exp, reg, nil
}

// Refresh looks up the RDAP entries not checked in the last 20 h (force:
// all of them) and sends the threshold notifications.
func (s *Service) Refresh(ctx context.Context, force bool) error {
	list, err := s.List(ctx)
	if err != nil {
		return err
	}
	now := time.Now()
	var due []Entry
	for _, e := range list {
		if e.Source == SourceRDAP && (force || now.Sub(e.CheckedAt) > recheck) {
			due = append(due, e)
		}
	}
	var lookupErr error
	if len(due) > 0 {
		lookupErr = s.lookupAll(ctx, due, now)
	}
	s.notify(ctx, now)
	return lookupErr
}

func (s *Service) lookupAll(ctx context.Context, due []Entry, now time.Time) error {
	burl := s.Bootstrap
	if burl == "" {
		burl = BootstrapURL
	}
	var boot map[string]string
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, burl, nil)
	if err == nil {
		var res *http.Response
		if res, err = s.client().Do(req); err == nil {
			if res.StatusCode == http.StatusOK {
				boot, err = ParseBootstrap(io.LimitReader(res.Body, 1<<20))
			} else {
				err = fmt.Errorf("HTTP %d", res.StatusCode)
			}
			res.Body.Close()
		}
	}
	if err != nil {
		return fmt.Errorf("RDAP listesi alınamadı: %w", err)
	}
	for i, e := range due {
		if i > 0 {
			select { // be gentle with the registries
			case <-ctx.Done():
				return ctx.Err()
			case <-time.After(time.Second):
			}
		}
		base, ok := boot[TLD(e.Name)]
		var exp time.Time
		reg, msg := "", ""
		if !ok {
			msg = "." + TLD(e.Name) + " için RDAP servisi yok; bitiş tarihini elle girin"
		} else {
			var d rdapDomain
			code, err := s.getJSON(ctx, base+"domain/"+e.Name, &d)
			switch {
			case code == http.StatusNotFound:
				msg = "kayıt bulunamadı (alan adı kayıtlı değil ya da süresi dolmuş olabilir)"
			case err != nil:
				msg = "sorgu başarısız: " + err.Error()
			default:
				exp, reg, err = d.expiry()
				if err != nil {
					msg = err.Error()
				}
			}
		}
		if msg != "" {
			// keep the last known date: a failed lookup is not a lost domain
			s.DB.ExecContext(ctx, `UPDATE domain_expiry SET checked_at=?, error=? WHERE name=? AND source=?`,
				now.Unix(), msg, e.Name, SourceRDAP)
			continue
		}
		notified := e.Notified
		if !exp.Equal(e.ExpiresAt) {
			notified = 0 // renewed (or first lookup): thresholds start over
		}
		s.DB.ExecContext(ctx, `UPDATE domain_expiry SET expires_at=?, registrar=?, checked_at=?, error='', notified=? WHERE name=? AND source=?`,
			exp.Unix(), reg, now.Unix(), notified, e.Name, SourceRDAP)
	}
	return nil
}

// notify sends one notification per crossed threshold and expiry date.
func (s *Service) notify(ctx context.Context, now time.Time) {
	list, _ := s.List(ctx)
	for _, e := range list {
		if e.ExpiresAt.IsZero() {
			continue
		}
		days := e.DaysLeft(now)
		th := 0
		for _, t := range Thresholds {
			if days <= t {
				th = t
			}
		}
		if th == 0 || (e.Notified != 0 && e.Notified <= th) {
			continue
		}
		s.DB.ExecContext(ctx, `UPDATE domain_expiry SET notified=? WHERE name=?`, th, e.Name)
		if s.Notify != nil {
			title := fmt.Sprintf("Alan adının süresi doluyor: %s (%d gün)", e.Name, days)
			if days < 0 {
				title = "Alan adının süresi doldu: " + e.Name
			}
			text := "Bitiş: " + e.ExpiresAt.Format("02.01.2006")
			if e.Registrar != "" {
				text += "\nKayıt firması: " + e.Registrar
			}
			s.Notify(ctx, title, text, fmt.Sprintf("domain:%s:%d:%d", e.Name, e.ExpiresAt.Unix(), th))
		}
	}
}

// Expiring returns entries expiring within days (already expired included).
func (s *Service) Expiring(ctx context.Context, days int) []Entry {
	list, _ := s.List(ctx)
	now := time.Now()
	var out []Entry
	for _, e := range list {
		if !e.ExpiresAt.IsZero() && e.DaysLeft(now) <= days {
			out = append(out, e)
		}
	}
	return out
}

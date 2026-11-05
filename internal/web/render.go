package web

import (
	"bytes"
	"encoding/json"
	"fmt"
	"html/template"
	"io/fs"
	"net/http"
	"strings"
	"sync"
	"time"

	"hostpanel/internal/auth"
)

// renderer parses layout + one page per template set. In dev mode it reparses
// on every call so template edits show up without a rebuild.
type renderer struct {
	fs    fs.FS
	dev   bool
	mu    sync.Mutex
	cache map[string]*template.Template
}

func newRenderer(fsys fs.FS, dev bool) (*renderer, error) {
	r := &renderer{fs: fsys, dev: dev, cache: map[string]*template.Template{}}
	if !dev { // fail fast in production if any template is broken
		pages, err := fs.Glob(fsys, "templates/pages/*.html")
		if err != nil {
			return nil, err
		}
		for _, p := range pages {
			name := strings.TrimSuffix(strings.TrimPrefix(p, "templates/pages/"), ".html")
			if _, err := r.get(name); err != nil {
				return nil, err
			}
		}
	}
	return r, nil
}

func (r *renderer) get(page string) (*template.Template, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if t, ok := r.cache[page]; ok && !r.dev {
		return t, nil
	}
	t, err := template.New("").Funcs(funcs).ParseFS(r.fs, "templates/layout.html", "templates/partials/*.html", "templates/pages/"+page+".html")
	if err != nil {
		return nil, fmt.Errorf("template %s: %w", page, err)
	}
	r.cache[page] = t
	return t, nil
}

// Page is the data every page template receives.
type Page struct {
	Title    string
	Nav      string
	CSRF     string
	LoggedIn bool
	Dev      bool
	DryRun   bool
	Version  string
	Error    string
	Notice   string
	Data     any
}

// render executes block ("layout" for full pages, or a named partial for HTMX swaps).
func (s *Server) render(w http.ResponseWriter, r *http.Request, status int, page, block string, p Page) {
	t, err := s.tpl.get(page)
	if err != nil {
		s.Log.Error("template load", "err", err)
		http.Error(w, "Şablon hatası", http.StatusInternalServerError)
		return
	}
	if se := sessionFrom(r); se != nil {
		p.CSRF = se.CSRF
		p.LoggedIn = se.Stage == auth.StageFull
	}
	p.Dev, p.DryRun, p.Version = s.Cfg.Dev, s.Cfg.DryRun, s.Version
	var buf bytes.Buffer // render fully first so a template error never sends half a page
	if err := t.ExecuteTemplate(&buf, block, p); err != nil {
		s.Log.Error("template exec", "page", page, "block", block, "err", err)
		http.Error(w, "Şablon hatası", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	w.Write(buf.Bytes())
}

// isHX reports an HTMX request that wants only a fragment.
func isHX(r *http.Request) bool {
	return r.Header.Get("HX-Request") == "true" && r.Header.Get("HX-Boosted") != "true"
}

var trMonths = [...]string{"Oca", "Şub", "Mar", "Nis", "May", "Haz", "Tem", "Ağu", "Eyl", "Eki", "Kas", "Ara"}

var funcs = template.FuncMap{
	"list": func(v ...any) []any { return v },
	// pngDataURL marks a server-generated PNG data URI (the 2FA QR) as safe;
	// html/template would otherwise replace data: URLs with #ZgotmplZ.
	"pngDataURL": func(s string) template.URL {
		if strings.HasPrefix(s, "data:image/png;base64,") {
			return template.URL(s)
		}
		return ""
	},
	"datetime": func(t time.Time) string {
		if t.IsZero() {
			return "—"
		}
		return fmt.Sprintf("%02d %s %s", t.Day(), trMonths[t.Month()-1], t.Format("15:04:05"))
	},
	"iso": func(t time.Time) string { return t.Format(time.RFC3339) },
	"ago": func(t time.Time) string {
		d := time.Since(t)
		switch {
		case d < time.Minute:
			return "az önce"
		case d < time.Hour:
			return fmt.Sprintf("%d dk önce", int(d.Minutes()))
		case d < 24*time.Hour:
			return fmt.Sprintf("%d sa önce", int(d.Hours()))
		default:
			return fmt.Sprintf("%d gün önce", int(d.Hours()/24))
		}
	},
	"ms": func(ms int64) string {
		if ms < 1000 {
			return fmt.Sprintf("%d ms", ms)
		}
		return (time.Duration(ms) * time.Millisecond).Round(100 * time.Millisecond).String()
	},
	"statusLabel": func(s string) string {
		switch s {
		case "success":
			return "Başarılı"
		case "failed":
			return "Başarısız"
		case "running":
			return "Devam ediyor"
		case "queued":
			return "Sırada"
		case "canceled":
			return "İptal edildi"
		}
		return s
	},
	"siteStatus": func(s string) string {
		return map[string]string{
			"provisioning": "Hazırlanıyor", "awaiting_deploy": "Deploy bekliyor", "running": "Çalışıyor",
			"stopped": "Durduruldu", "maintenance": "Bakımda", "disabled": "Devre dışı", "error": "Hata",
			"deleting": "Siliniyor", "active": "Aktif", "previous": "Önceki", "failed": "Başarısız", "pruned": "Silindi",
			"pending": "Bekliyor", "replaced": "Değiştirildi", "removed": "Kaldırıldı",
			"installing": "Kuruluyor", "creating": "Oluşturuluyor", "ready": "Hazır", "dropping": "Siliniyor",
		}[s]
	},
	"kb": func(n int64) string {
		if n < 1<<20 {
			return fmt.Sprintf("%d KB", n>>10)
		}
		return fmt.Sprintf("%.1f MB", float64(n)/(1<<20))
	},
	"size": func(n int64) string {
		switch {
		case n >= 1<<30:
			return fmt.Sprintf("%.2f GB", float64(n)/(1<<30))
		case n >= 1<<20:
			return fmt.Sprintf("%.1f MB", float64(n)/(1<<20))
		default:
			return fmt.Sprintf("%d KB", n>>10)
		}
	},
	"prettyJSON": func(s string) string {
		if s == "" {
			return ""
		}
		var v any
		if json.Unmarshal([]byte(s), &v) != nil {
			return s
		}
		b, _ := json.MarshalIndent(v, "", "  ")
		return string(b)
	},
	"diffLines": func(s string) []diffLine {
		var out []diffLine
		for _, l := range strings.Split(s, "\n") {
			k := ""
			switch {
			case strings.HasPrefix(l, "+"):
				k = "add"
			case strings.HasPrefix(l, "-"):
				k = "del"
			}
			out = append(out, diffLine{Kind: k, Text: l})
		}
		return out
	},
}

type diffLine struct{ Kind, Text string }

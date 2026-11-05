package sites

import (
	"bytes"
	"fmt"
	"path/filepath"
	"strings"
	"text/template"

	"hostpanel/internal/runtimes"
)

// nginx modes derived from site status.
const (
	ModeApp         = "app"
	ModePlaceholder = "placeholder"
	ModeStopped     = "stopped"
	ModeMaintenance = "maintenance"
	ModeDisabled    = "disabled"
)

// ModeFor maps a site status to how nginx should serve it.
func ModeFor(status string) string {
	switch status {
	case StatusRunning, StatusError:
		return ModeApp
	case StatusStopped:
		return ModeStopped
	case StatusMaintenance:
		return ModeMaintenance
	case StatusDisabled:
		return ModeDisabled
	default:
		return ModePlaceholder
	}
}

// NginxData is passed to the nginx templates.
type NginxData struct {
	Domain       string
	ServerNames  []string // names served by the main server block
	RedirectFrom []string // names that 301 to RedirectTo
	RedirectTo   string
	Mode         string
	Type         string
	Port         int
	Root         string
	Index        string
	SPA          bool
	MaxUploadMB  int
	Gzip         bool
	Snippet      string
	AccessLog    string
	ErrorLog     string
	PagesDir     string
	ErrorPage    string // page served for 503 in non-app modes
	ACMERoot     string
}

// NginxDataFor builds template data for s in the given mode.
func NginxDataFor(s Site, def *runtimes.Definition, mode, templatesDir string) NginxData {
	d := NginxData{
		Domain:      s.Domain,
		Mode:        mode,
		Type:        def.Type,
		Port:        s.Port,
		Root:        s.Dir() + "/current",
		Index:       "index.html",
		MaxUploadMB: s.MaxUploadMB,
		Gzip:        s.Gzip,
		Snippet:     strings.TrimSpace(s.CustomSnippet),
		AccessLog:   "/var/log/nginx/hp-" + s.Domain + ".access.log",
		ErrorLog:    "/var/log/nginx/hp-" + s.Domain + ".error.log",
		PagesDir:    filepath.Join(templatesDir, "pages") + "/",
		ErrorPage:   "503.html",
		ACMERoot:    "/var/www/letsencrypt",
	}
	if mode == ModeDisabled {
		d.ErrorPage = "disabled.html"
	}
	if v := s.Fields["index"]; v != "" {
		d.Index = v
	}
	d.SPA = s.Fields["spa"] == "evet"
	switch s.WWWMode {
	case WWWToWWW:
		d.ServerNames = append([]string{s.WWWName()}, s.Aliases...)
		d.RedirectFrom, d.RedirectTo = []string{s.Domain}, s.WWWName()
	case WWWToApex:
		d.ServerNames = append([]string{s.Domain}, s.Aliases...)
		d.RedirectFrom, d.RedirectTo = []string{s.WWWName()}, s.Domain
	default:
		d.ServerNames = append([]string{s.Domain, s.WWWName()}, s.Aliases...)
	}
	return d
}

// RenderNginx renders the runtime's nginx template from templatesDir/nginx/.
// common.conf.tpl (shared blocks) is always loaded alongside it.
func RenderNginx(templatesDir, name string, d NginxData) (string, error) {
	dir := filepath.Join(templatesDir, "nginx")
	t, err := template.New(name).Funcs(template.FuncMap{"join": strings.Join}).
		ParseFiles(filepath.Join(dir, "common.conf.tpl"), filepath.Join(dir, name))
	if err != nil {
		return "", fmt.Errorf("nginx şablonu: %w", err)
	}
	var b bytes.Buffer
	if err := t.ExecuteTemplate(&b, name, d); err != nil {
		return "", fmt.Errorf("nginx şablonu: %w", err)
	}
	out := b.String()
	if err := ValidateConf(out, d.Domain); err != nil {
		return "", err
	}
	return out, nil
}

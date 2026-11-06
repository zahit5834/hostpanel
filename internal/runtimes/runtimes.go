// Package runtimes loads site runtime definitions (.NET, Node.js, static, ...)
// from YAML files, so new runtimes can be added without code changes.
package runtimes

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"sort"
	"strings"
	"sync"

	"github.com/goccy/go-yaml"

	"github.com/zahit5834/hostpanel/internal/exec"
)

// Runtime types.
const (
	TypeProxy   = "proxy"   // app listens on 127.0.0.1:<port>, nginx proxies
	TypeStatic  = "static"  // nginx serves files directly
	TypeFastCGI = "fastcgi" // php-fpm master per site, nginx speaks FastCGI to its socket
)

// Field is a runtime-specific site setting shown in the wizard.
type Field struct {
	Key         string `yaml:"key"`
	Label       string `yaml:"label"`
	Required    bool   `yaml:"required"`
	Pattern     string `yaml:"pattern"`
	Placeholder string `yaml:"placeholder"`
	Default     string `yaml:"default"`
	Help        string `yaml:"help"`

	re *regexp.Regexp
}

// Versions describes how versions are discovered and installed.
type Versions struct {
	ListCommand   []string `yaml:"list-command"`   // argv, run unprivileged
	ListDir       string   `yaml:"list-dir"`       // or: one sub-directory per version
	ListRegex     string   `yaml:"list-regex"`     // first capture group = version
	Available     string   `yaml:"available"`      // remote source id: dotnet-releases | node-dist
	InstallScript string   `yaml:"install-script"` // scripts/runtimes/<file>, via hp-runtime.sh

	re *regexp.Regexp
}

// Definition is one runtime YAML file.
type Definition struct {
	ID              string            `yaml:"id"`
	DisplayName     string            `yaml:"displayName"`
	Type            string            `yaml:"type"`
	Versions        Versions          `yaml:"versions"`
	StartCommand    string            `yaml:"startCommand"`
	Environment     map[string]string `yaml:"environment"`
	SystemdTemplate string            `yaml:"systemdTemplate"`
	NginxTemplate   string            `yaml:"nginxTemplate"`
	SiteFields      []Field           `yaml:"siteFields"`
	Info            string            `yaml:"info"` // shown on the site page
	SDK             *SDK              `yaml:"sdk"`  // build toolchain for git deploy (optional)
}

// SDK describes how to list installed SDKs (e.g. .NET SDKs for dotnet publish).
type SDK struct {
	ListCommand []string `yaml:"list-command"`
	ListRegex   string   `yaml:"list-regex"`

	re *regexp.Regexp
}

// HasUnit reports whether sites of this runtime run as their own systemd
// unit (proxy apps and PHP's per-site php-fpm master).
func (d *Definition) HasUnit() bool { return d.Type == TypeProxy || d.Type == TypeFastCGI }

// Provider is what the rest of the panel uses. The YAML-backed implementation
// covers every runtime for now; a code-backed one can implement it later.
type Provider interface {
	Def() *Definition
	InstalledVersions(ctx context.Context) ([]string, error)
	InstalledSDKs(ctx context.Context) []string
	AvailableVersions(ctx context.Context) ([]Available, error)
	ValidateFields(values map[string]string) (map[string]string, error)
	StartArgs(v Vars) ([]string, error)
	Env(v Vars) map[string]string
}

// Vars are the placeholders available in startCommand and environment.
type Vars struct {
	Domain  string
	Port    int
	Version string
	SiteDir string
	Fields  map[string]string
}

var (
	idRe       = regexp.MustCompile(`^[a-z][a-z0-9-]{1,20}$`)
	envKeyRe   = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*$`)
	argTokenRe = regexp.MustCompile(`^[A-Za-z0-9._/@:=,+-]+$`)
	scriptRe   = regexp.MustCompile(`^[a-z0-9-]+\.sh$`)
	tplRe      = regexp.MustCompile(`^[a-z0-9-]+\.(service|conf)\.tpl$`)
	placeRe    = regexp.MustCompile(`\{\{\s*([A-Za-z][A-Za-z0-9_]*)\s*\}\}`)
)

// Parse decodes and validates one definition.
func Parse(b []byte) (*Definition, error) {
	var d Definition
	if err := yaml.Unmarshal(b, &d); err != nil {
		return nil, err
	}
	if !idRe.MatchString(d.ID) {
		return nil, fmt.Errorf("geçersiz id %q", d.ID)
	}
	if d.DisplayName == "" {
		d.DisplayName = d.ID
	}
	switch d.Type {
	case TypeProxy, TypeFastCGI:
		if strings.TrimSpace(d.StartCommand) == "" || d.SystemdTemplate == "" {
			return nil, fmt.Errorf("%s: %s tipi startCommand ve systemdTemplate ister", d.ID, d.Type)
		}
	case TypeStatic:
	default:
		return nil, fmt.Errorf("%s: bilinmeyen tip %q", d.ID, d.Type)
	}
	if d.NginxTemplate == "" {
		d.NginxTemplate = d.Type + ".conf.tpl"
	}
	for _, t := range []string{d.SystemdTemplate, d.NginxTemplate} {
		if t != "" && !tplRe.MatchString(t) {
			return nil, fmt.Errorf("%s: geçersiz şablon adı %q", d.ID, t)
		}
	}
	if s := d.Versions.InstallScript; s != "" && !scriptRe.MatchString(s) {
		return nil, fmt.Errorf("%s: geçersiz install-script %q", d.ID, s)
	}
	if d.Versions.ListRegex != "" {
		re, err := regexp.Compile(d.Versions.ListRegex)
		if err != nil || re.NumSubexp() < 1 {
			return nil, fmt.Errorf("%s: list-regex bir yakalama grubu içermeli", d.ID)
		}
		d.Versions.re = re
	}
	if d.SDK != nil {
		re, err := regexp.Compile(d.SDK.ListRegex)
		if err != nil || re.NumSubexp() < 1 || len(d.SDK.ListCommand) == 0 {
			return nil, fmt.Errorf("%s: sdk list-command ve yakalama gruplu list-regex ister", d.ID)
		}
		d.SDK.re = re
	}
	for k := range d.Environment {
		if !envKeyRe.MatchString(k) {
			return nil, fmt.Errorf("%s: geçersiz ortam değişkeni adı %q", d.ID, k)
		}
	}
	for i := range d.SiteFields {
		f := &d.SiteFields[i]
		if !regexp.MustCompile(`^[A-Za-z][A-Za-z0-9_]*$`).MatchString(f.Key) {
			return nil, fmt.Errorf("%s: geçersiz alan anahtarı %q", d.ID, f.Key)
		}
		if f.Pattern != "" {
			re, err := regexp.Compile(f.Pattern)
			if err != nil {
				return nil, fmt.Errorf("%s.%s: geçersiz pattern: %w", d.ID, f.Key, err)
			}
			f.re = re
		}
	}
	return &d, nil
}

// yamlProvider implements Provider from a Definition.
type yamlProvider struct {
	def    *Definition
	runner exec.Runner // unprivileged, read-only probes
	remote *remoteCache
	fake   bool // dry-run: pretend the latest available versions are installed
}

func (p *yamlProvider) Def() *Definition { return p.def }

// InstalledVersions lists versions present on this server, newest first.
func (p *yamlProvider) InstalledVersions(ctx context.Context) ([]string, error) {
	v := p.def.Versions
	if p.def.Type == TypeStatic {
		return nil, nil
	}
	var lines []string
	switch {
	case v.ListDir != "":
		ents, err := os.ReadDir(v.ListDir)
		if err != nil && !errors.Is(err, os.ErrNotExist) {
			return nil, err
		}
		for _, e := range ents {
			if e.IsDir() {
				lines = append(lines, e.Name())
			}
		}
	case len(v.ListCommand) > 0:
		res, err := p.runner.Run(ctx, exec.Cmd{Name: v.ListCommand[0], Args: v.ListCommand[1:]})
		if err == nil {
			lines = strings.Split(res.Stdout, "\n")
		}
	}
	seen := map[string]bool{}
	var out []string
	for _, l := range lines {
		ver := strings.TrimSpace(l)
		if v.re != nil {
			m := v.re.FindStringSubmatch(ver)
			if m == nil {
				continue
			}
			ver = m[1]
		}
		if ver != "" && !seen[ver] {
			seen[ver] = true
			out = append(out, ver)
		}
	}
	if len(out) == 0 && p.fake {
		if av, err := p.AvailableVersions(ctx); err == nil {
			for _, a := range av {
				out = append(out, a.Version)
			}
		}
	}
	SortVersions(out)
	return out, nil
}

// InstalledSDKs lists installed SDK versions (newest first); nil when the
// runtime has no SDK definition.
func (p *yamlProvider) InstalledSDKs(ctx context.Context) []string {
	sdk := p.def.SDK
	if sdk == nil {
		return nil
	}
	var out []string
	res, err := p.runner.Run(ctx, exec.Cmd{Name: sdk.ListCommand[0], Args: sdk.ListCommand[1:]})
	if err == nil {
		for _, l := range strings.Split(res.Stdout, "\n") {
			if m := sdk.re.FindStringSubmatch(strings.TrimSpace(l)); m != nil && !slices.Contains(out, m[1]) {
				out = append(out, m[1])
			}
		}
	}
	if len(out) == 0 && p.fake {
		// Dry-run: one SDK per installed runtime channel.
		vs, _ := p.InstalledVersions(ctx)
		for _, v := range vs {
			if f := strings.Split(v, "."); len(f) == 3 && !slices.Contains(out, f[0]+"."+f[1]+".100") {
				out = append(out, f[0]+"."+f[1]+".100")
			}
		}
	}
	SortVersions(out)
	return out
}

// HasSDKFor reports whether an SDK of the same major version as runtime
// version v is installed.
func HasSDKFor(sdks []string, v string) bool {
	major, _, _ := strings.Cut(v, ".")
	for _, s := range sdks {
		if m, _, _ := strings.Cut(s, "."); m == major {
			return true
		}
	}
	return false
}

// AvailableVersions returns installable versions from the official source.
func (p *yamlProvider) AvailableVersions(ctx context.Context) ([]Available, error) {
	if p.def.Versions.Available == "" || p.remote == nil {
		return nil, nil
	}
	return p.remote.get(ctx, p.def.Versions.Available)
}

// ValidateFields checks the wizard values against the field definitions and
// returns a cleaned map containing only known keys.
func (p *yamlProvider) ValidateFields(values map[string]string) (map[string]string, error) {
	out := map[string]string{}
	for _, f := range p.def.SiteFields {
		v := strings.TrimSpace(values[f.Key])
		if v == "" {
			v = f.Default
		}
		if v == "" {
			if f.Required {
				return nil, fmt.Errorf("%s zorunlu", f.Label)
			}
			continue
		}
		if f.re != nil && !f.re.MatchString(v) {
			return nil, fmt.Errorf("%s geçersiz", f.Label)
		}
		out[f.Key] = v
	}
	return out, nil
}

func (v Vars) lookup(name string) (string, bool) {
	switch name {
	case "domain":
		return v.Domain, true
	case "port":
		return fmt.Sprint(v.Port), true
	case "version":
		return v.Version, true
	case "siteDir":
		return v.SiteDir, true
	}
	s, ok := v.Fields[name]
	return s, ok
}

func expand(s string, v Vars) string {
	return placeRe.ReplaceAllStringFunc(s, func(m string) string {
		val, _ := v.lookup(placeRe.FindStringSubmatch(m)[1])
		return val
	})
}

// StartArgs renders startCommand into argv. Every token must be a plain
// path/word; the root helper re-checks this before writing the unit.
func (p *yamlProvider) StartArgs(v Vars) ([]string, error) {
	if !p.def.HasUnit() {
		return nil, nil
	}
	var argv []string
	for _, tok := range strings.Fields(p.def.StartCommand) {
		// A placeholder may expand to several words (e.g. optional {{args}}).
		for _, part := range strings.Fields(expand(tok, v)) {
			if !argTokenRe.MatchString(part) || strings.Contains(part, "..") {
				return nil, fmt.Errorf("başlangıç komutunda geçersiz değer: %q", part)
			}
			argv = append(argv, part)
		}
	}
	if len(argv) == 0 || !filepath.IsAbs(argv[0]) {
		return nil, errors.New("başlangıç komutu mutlak yol ile başlamalı")
	}
	return argv, nil
}

// Env renders the runtime's environment.
func (p *yamlProvider) Env(v Vars) map[string]string {
	out := make(map[string]string, len(p.def.Environment))
	for k, val := range p.def.Environment {
		out[k] = expand(val, v)
	}
	return out
}

// Registry holds all loaded runtimes.
type Registry struct {
	mu        sync.RWMutex
	providers map[string]Provider
	order     []string
	errs      []error
}

// Load reads every *.yaml in dir. Invalid files are reported via Errors and skipped.
func Load(dir string, runner exec.Runner, fake bool) (*Registry, error) {
	files, err := filepath.Glob(filepath.Join(dir, "*.yaml"))
	if err != nil {
		return nil, err
	}
	r := &Registry{providers: map[string]Provider{}}
	rc := newRemoteCache()
	for _, f := range files {
		b, err := os.ReadFile(f)
		if err != nil {
			r.errs = append(r.errs, err)
			continue
		}
		d, err := Parse(b)
		if err != nil {
			r.errs = append(r.errs, fmt.Errorf("%s: %w", filepath.Base(f), err))
			continue
		}
		if _, dup := r.providers[d.ID]; dup {
			r.errs = append(r.errs, fmt.Errorf("%s: tekrarlanan id %q", filepath.Base(f), d.ID))
			continue
		}
		r.providers[d.ID] = &yamlProvider{def: d, runner: runner, remote: rc, fake: fake}
		r.order = append(r.order, d.ID)
	}
	sort.Strings(r.order)
	return r, nil
}

// Get returns the provider for id.
func (r *Registry) Get(id string) (Provider, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	p, ok := r.providers[id]
	return p, ok
}

// All returns providers sorted by id.
func (r *Registry) All() []Provider {
	r.mu.RLock()
	defer r.mu.RUnlock()
	out := make([]Provider, 0, len(r.order))
	for _, id := range r.order {
		out = append(out, r.providers[id])
	}
	return out
}

// Errors returns problems found while loading definitions.
func (r *Registry) Errors() []error { return r.errs }

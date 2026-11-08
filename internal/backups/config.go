package backups

import (
	"bufio"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/zahit5834/hostpanel/internal/sites"
)

// SiteConfig is config.json inside a backup: everything the panel knows about
// the site that is not in the files. Env values stay AES-GCM sealed with the
// panel's master key (a backup sent to Drive without crypt doesn't expose
// connection strings or API keys).
type SiteConfig struct {
	Version        int               `json:"version"`
	CreatedAt      time.Time         `json:"created_at"`
	Domain         string            `json:"domain"`
	ShortName      string            `json:"short_name"`
	RuntimeID      string            `json:"runtime"`
	RuntimeVersion string            `json:"runtime_version"`
	Fields         map[string]string `json:"fields"`
	Aliases        []string          `json:"aliases"`
	WWWMode        string            `json:"www_mode"`
	MemoryMaxMB    int               `json:"memory_max_mb"`
	CPUQuotaPct    int               `json:"cpu_quota_pct"`
	PersistentDirs []string          `json:"persistent_dirs"`
	HealthPath     string            `json:"health_path"`
	MaxUploadMB    int               `json:"max_upload_mb"`
	Gzip           bool              `json:"gzip"`
	HSTS           bool              `json:"hsts"`
	ForceHTTPS     bool              `json:"force_https"`
	CustomSnippet  string            `json:"custom_snippet"`
	ActiveRelease  string            `json:"active_release"`
	EnvSealed      map[string]string `json:"env_sealed"`
	Databases      []ConfigDB        `json:"databases"`
	Crons          []ConfigCron      `json:"crons,omitempty"`
	Git            *ConfigGit        `json:"git,omitempty"` // the deploy key is not included
}

// ConfigCron is a site cron in config.json.
type ConfigCron struct {
	Name       string `json:"name"`
	Schedule   string `json:"schedule"`
	Command    string `json:"command"`
	Enabled    bool   `json:"enabled"`
	TimeoutSec int    `json:"timeout_sec"`
}

// ConfigGit is the git deploy configuration in config.json.
type ConfigGit struct {
	RepoURL      string `json:"repo_url"`
	Branch       string `json:"branch"`
	BuildCommand string `json:"build_command"`
	OutputDir    string `json:"output_dir"`
	BuildTimeout int    `json:"build_timeout"`
}

// ConfigDB is a database included in (or referenced by) the backup.
type ConfigDB struct {
	Name   string `json:"name"`
	EnvKey string `json:"env_key,omitempty"`
	Engine string `json:"engine,omitempty"` // "" = MSSQL (db-<name>.bak), "postgres" (db-pg-<name>.dump)
}

// EnginePostgres marks a PostgreSQL database in config.json.
const EnginePostgres = "postgres"

// IsPG reports a PostgreSQL database.
func (c ConfigDB) IsPG() bool { return c.Engine == EnginePostgres }

// ConfigFor builds the config of site.
func ConfigFor(site sites.Site, active string, envSealed map[string]string, dbs []ConfigDB) SiteConfig {
	return SiteConfig{Version: 1, CreatedAt: time.Now().UTC(), Domain: site.Domain, ShortName: site.ShortName,
		RuntimeID: site.RuntimeID, RuntimeVersion: site.RuntimeVersion, Fields: site.Fields, Aliases: site.Aliases,
		WWWMode: site.WWWMode, MemoryMaxMB: site.MemoryMaxMB, CPUQuotaPct: site.CPUQuotaPct, PersistentDirs: site.PersistentDirs,
		HealthPath: site.HealthPath, MaxUploadMB: site.MaxUploadMB, Gzip: site.Gzip, HSTS: site.HSTS, ForceHTTPS: site.ForceHTTPS,
		CustomSnippet: site.CustomSnippet, ActiveRelease: active, EnvSealed: envSealed, Databases: dbs}
}

// ParseConfig reads config.json.
func ParseConfig(b []byte) (SiteConfig, error) {
	var c SiteConfig
	if err := json.Unmarshal(b, &c); err != nil {
		return c, fmt.Errorf("config.json okunamadı: %w", err)
	}
	if c.Version != 1 {
		return c, fmt.Errorf("desteklenmeyen config.json sürümü: %d", c.Version)
	}
	return c, nil
}

// SettingsFor turns the backed-up config into a settings form for target.
// For a clone (target is another site) the target keeps its own domain names.
func (c SiteConfig) SettingsFor(target sites.Site) sites.SettingsInput {
	in := sites.SettingsInput{
		Aliases: strings.Join(target.Aliases, ", "), WWWMode: target.WWWMode,
		RuntimeVersion: c.RuntimeVersion, Fields: c.Fields, MemoryMaxMB: c.MemoryMaxMB, CPUQuotaPct: c.CPUQuotaPct,
		PersistentDirs: strings.Join(c.PersistentDirs, ", "), HealthPath: c.HealthPath, MaxUploadMB: c.MaxUploadMB,
		Gzip: c.Gzip, HSTS: c.HSTS, ForceHTTPS: c.ForceHTTPS, CustomSnippet: c.CustomSnippet,
	}
	if c.Domain == target.Domain {
		in.Aliases, in.WWWMode = strings.Join(c.Aliases, ", "), c.WWWMode
	}
	if in.Fields == nil {
		in.Fields = map[string]string{}
	}
	return in
}

// ParseDotenv reads KEY=VALUE lines (the import wizard's bulk paste): blank
// lines and # comments are skipped, "export " is allowed, one level of
// matching single or double quotes is removed. Values stay literal.
func ParseDotenv(text string) (map[string]string, error) {
	out := map[string]string{}
	sc := bufio.NewScanner(strings.NewReader(text))
	sc.Buffer(make([]byte, 64*1024), 64*1024)
	n := 0
	for sc.Scan() {
		n++
		line := strings.TrimSpace(strings.TrimSuffix(sc.Text(), "\r"))
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		line = strings.TrimPrefix(line, "export ")
		k, v, ok := strings.Cut(line, "=")
		if !ok {
			return nil, fmt.Errorf("satır %d: KEY=VALUE biçiminde değil", n)
		}
		k = strings.TrimSpace(k)
		v = strings.TrimSpace(v)
		if len(v) >= 2 && (v[0] == '"' && v[len(v)-1] == '"' || v[0] == '\'' && v[len(v)-1] == '\'') {
			v = v[1 : len(v)-1]
		}
		if !sites.ValidEnvKey(k) {
			return nil, fmt.Errorf("satır %d: geçersiz değişken adı %q", n, k)
		}
		if !sites.ValidEnvValue(v) {
			return nil, fmt.Errorf("satır %d: %s değeri geçersiz (tek satır, en fazla 8 KB)", n, k)
		}
		out[k] = v
	}
	if err := sc.Err(); err != nil {
		return nil, err
	}
	if len(out) == 0 {
		return nil, errors.New("değişken bulunamadı")
	}
	return out, nil
}

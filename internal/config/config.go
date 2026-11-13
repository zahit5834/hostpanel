// Package config loads the panel configuration from YAML.
package config

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"

	"github.com/goccy/go-yaml"
)

// DefaultRepo is the GitHub repository releases are published to.
const DefaultRepo = "zahit5834/hostpanel"

// DefaultPath is where the production config file lives.
const DefaultPath = "/etc/hostpanel/config.yaml"

// Config holds all runtime settings. Zero values are filled by Defaults/DevDefaults.
type Config struct {
	Listen        string `yaml:"listen"`         // e.g. 127.0.0.1:8090
	DataDir       string `yaml:"data_dir"`       // SQLite lives here
	LogDir        string `yaml:"log_dir"`        // panel.log, auth.log, jobs/
	RootLogDir    string `yaml:"root_log_dir"`   // logs written by root helpers (root:hostpanel 0750)
	MasterKeyPath string `yaml:"master_key"`     // AES-256 key file
	ScriptsDir    string `yaml:"scripts_dir"`    // root helper scripts
	TemplatesDir  string `yaml:"templates_dir"`  // nginx/systemd templates
	RuntimesDir   string `yaml:"runtimes_dir"`   // runtime YAML definitions
	SecureCookies bool   `yaml:"secure_cookies"` // false only behind plain-HTTP SSH tunnel / dev
	TrustProxy    bool   `yaml:"trust_proxy"`    // trust X-Forwarded-For from 127.0.0.1 (nginx in front)
	DryRun        bool   `yaml:"dry_run"`        // log commands instead of executing
	Workers       int    `yaml:"workers"`        // background job workers
	PanelDomain   string `yaml:"panel_domain"`   // public panel name (nginx vhost); empty = IP mode
	PanelPort     int    `yaml:"panel_port"`     // public HTTPS port nginx serves the panel on
	PanelIPPort   int    `yaml:"panel_ip_port"`  // self-signed IP entry next to panel_domain (0 = none)
	UpdateRepo    string `yaml:"update_repo"`    // GitHub owner/name for releases

	// Dev is set by the --dev flag only, never from YAML.
	Dev bool `yaml:"-"`
}

// Defaults returns production defaults matching the on-server layout.
func Defaults() Config {
	return Config{
		Listen:        "127.0.0.1:8090",
		DataDir:       "/var/lib/hostpanel",
		LogDir:        "/var/log/hostpanel",
		RootLogDir:    "/var/log/hostpanel-root",
		MasterKeyPath: "/etc/hostpanel/master.key",
		ScriptsDir:    "/opt/hostpanel/scripts",
		TemplatesDir:  "/opt/hostpanel/templates",
		RuntimesDir:   "/etc/hostpanel/runtimes",
		SecureCookies: true,
		Workers:       1,
		PanelPort:     8443,
		UpdateRepo:    DefaultRepo,
	}
}

// DevDefaults keeps everything under ./data so development never touches the system.
func DevDefaults() Config {
	return Config{
		Listen:        "127.0.0.1:8080",
		DataDir:       "data",
		LogDir:        "data/log",
		RootLogDir:    "data/log",
		MasterKeyPath: "data/master.key",
		ScriptsDir:    "deploy/scripts",
		TemplatesDir:  "deploy/templates",
		RuntimesDir:   "deploy/runtimes",
		SecureCookies: false,
		DryRun:        true,
		Workers:       1,
		PanelPort:     8443,
		UpdateRepo:    DefaultRepo,
		Dev:           true,
	}
}

// Load reads path on top of base. A missing file is not an error in dev mode.
func Load(path string, base Config) (Config, error) {
	cfg := base
	b, err := os.ReadFile(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) && base.Dev {
			return cfg, nil
		}
		return cfg, fmt.Errorf("read config: %w", err)
	}
	if err := yaml.Unmarshal(b, &cfg); err != nil {
		return cfg, fmt.Errorf("parse config %s: %w", path, err)
	}
	cfg.Dev = base.Dev
	if cfg.Workers < 1 {
		cfg.Workers = 1
	}
	if cfg.UpdateRepo == "" {
		cfg.UpdateRepo = DefaultRepo
	}
	if cfg.PanelPort == 0 {
		cfg.PanelPort = 8443
	}
	if !repoRe.MatchString(cfg.UpdateRepo) {
		return cfg, fmt.Errorf("config: geçersiz update_repo %q (owner/name)", cfg.UpdateRepo)
	}
	if cfg.PanelPort < 1 || cfg.PanelPort > 65535 {
		return cfg, fmt.Errorf("config: geçersiz panel_port %d", cfg.PanelPort)
	}
	if cfg.PanelIPPort < 0 || cfg.PanelIPPort > 65535 || (cfg.PanelIPPort != 0 && cfg.PanelIPPort == cfg.PanelPort) {
		return cfg, fmt.Errorf("config: geçersiz panel_ip_port %d", cfg.PanelIPPort)
	}
	if cfg.PanelDomain != "" && !domainRe.MatchString(cfg.PanelDomain) {
		return cfg, fmt.Errorf("config: geçersiz panel_domain %q", cfg.PanelDomain)
	}
	return cfg, nil
}

var (
	repoRe   = regexp.MustCompile(`^[A-Za-z0-9-]{1,39}/[A-Za-z0-9._-]{1,100}$`)
	domainRe = regexp.MustCompile(`^([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$`)
)

// DBPath is the SQLite file location.
func (c Config) DBPath() string { return filepath.Join(c.DataDir, "hostpanel.db") }

// JobLogDir holds per-job output files.
func (c Config) JobLogDir() string { return filepath.Join(c.LogDir, "jobs") }

// PanelLogPath is the panel's own JSON log.
func (c Config) PanelLogPath() string { return filepath.Join(c.LogDir, "panel.log") }

// AuthLogPath receives one line per failed login, in a fail2ban-friendly format.
func (c Config) AuthLogPath() string { return filepath.Join(c.LogDir, "auth.log") }

// RenewLogPath gets one line per certbot renewal (deploy hook, root).
func (c Config) RenewLogPath() string { return filepath.Join(c.RootLogDir, "ssl-renewals.log") }

// UpdateLogPath is hp-update.sh's progress log (root).
// AptLogPath is where hp-system.sh apt-run tees apt's output.
func (c Config) AptLogPath() string { return filepath.Join(c.RootLogDir, "apt.log") }

func (c Config) UpdateLogPath() string { return filepath.Join(c.RootLogDir, "update.log") }

// RcloneLogPath mirrors rclone's log from hp-backup.sh (root).
func (c Config) RcloneLogPath() string { return filepath.Join(c.RootLogDir, "rclone.log") }

// Package config loads the panel configuration from YAML.
package config

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"github.com/goccy/go-yaml"
)

// DefaultPath is where the production config file lives.
const DefaultPath = "/etc/hostpanel/config.yaml"

// Config holds all runtime settings. Zero values are filled by Defaults/DevDefaults.
type Config struct {
	Listen        string `yaml:"listen"`         // e.g. 127.0.0.1:8443
	DataDir       string `yaml:"data_dir"`       // SQLite lives here
	LogDir        string `yaml:"log_dir"`        // panel.log, auth.log, jobs/
	MasterKeyPath string `yaml:"master_key"`     // AES-256 key file
	ScriptsDir    string `yaml:"scripts_dir"`    // root helper scripts
	TemplatesDir  string `yaml:"templates_dir"`  // nginx/systemd templates
	RuntimesDir   string `yaml:"runtimes_dir"`   // runtime YAML definitions
	SecureCookies bool   `yaml:"secure_cookies"` // false only behind plain-HTTP SSH tunnel / dev
	TrustProxy    bool   `yaml:"trust_proxy"`    // trust X-Forwarded-For from 127.0.0.1 (nginx in front)
	DryRun        bool   `yaml:"dry_run"`        // log commands instead of executing
	Workers       int    `yaml:"workers"`        // background job workers

	// Dev is set by the --dev flag only, never from YAML.
	Dev bool `yaml:"-"`
}

// Defaults returns production defaults matching the on-server layout.
func Defaults() Config {
	return Config{
		Listen:        "127.0.0.1:8443",
		DataDir:       "/var/lib/hostpanel",
		LogDir:        "/var/log/hostpanel",
		MasterKeyPath: "/etc/hostpanel/master.key",
		ScriptsDir:    "/opt/hostpanel/scripts",
		TemplatesDir:  "/opt/hostpanel/templates",
		RuntimesDir:   "/etc/hostpanel/runtimes",
		SecureCookies: true,
		Workers:       1,
	}
}

// DevDefaults keeps everything under ./data so development never touches the system.
func DevDefaults() Config {
	return Config{
		Listen:        "127.0.0.1:8080",
		DataDir:       "data",
		LogDir:        "data/log",
		MasterKeyPath: "data/master.key",
		ScriptsDir:    "deploy/scripts",
		TemplatesDir:  "deploy/templates",
		RuntimesDir:   "deploy/runtimes",
		SecureCookies: false,
		DryRun:        true,
		Workers:       1,
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
	return cfg, nil
}

// DBPath is the SQLite file location.
func (c Config) DBPath() string { return filepath.Join(c.DataDir, "hostpanel.db") }

// JobLogDir holds per-job output files.
func (c Config) JobLogDir() string { return filepath.Join(c.LogDir, "jobs") }

// PanelLogPath is the panel's own JSON log.
func (c Config) PanelLogPath() string { return filepath.Join(c.LogDir, "panel.log") }

// AuthLogPath receives one line per failed login, in a fail2ban-friendly format.
func (c Config) AuthLogPath() string { return filepath.Join(c.LogDir, "auth.log") }

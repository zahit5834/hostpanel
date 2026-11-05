package sites

import (
	"context"
	"errors"
	"maps"
	"slices"
	"strings"

	"hostpanel/internal/logs"
	"hostpanel/internal/runtimes"
)

// SettingsInput is the site settings form.
type SettingsInput struct {
	Aliases        string
	WWWMode        string
	RuntimeVersion string
	Fields         map[string]string
	MemoryMaxMB    int
	CPUQuotaPct    int
	PersistentDirs string
	HealthPath     string
	MaxUploadMB    int
	Gzip           bool
	HSTS           bool
	ForceHTTPS     bool
	CustomSnippet  string
}

// SettingsResult tells the UI what happened.
type SettingsResult struct {
	NginxDiff      string
	UnitChanged    bool // takes effect after a restart
	RestartAdvised bool
}

// UpdateSettings validates and applies settings. nginx is re-rendered and
// installed (validated + nginx -t by the helper); the unit is re-rendered when
// limits, version or start fields changed.
func (s *Service) UpdateSettings(ctx context.Context, site Site, in SettingsInput) (SettingsResult, error) {
	var res SettingsResult
	prov, err := s.provider(site)
	if err != nil {
		return res, err
	}
	def := prov.Def()
	next := site
	if next.Aliases, err = ParseAliases(in.Aliases, site.Domain); err != nil {
		return res, err
	}
	switch in.WWWMode {
	case WWWNone, WWWToWWW, WWWToApex:
		next.WWWMode = in.WWWMode
	default:
		return res, errors.New("geçersiz www seçeneği")
	}
	if def.Type == runtimes.TypeProxy && in.RuntimeVersion != site.RuntimeVersion {
		installed, _ := prov.InstalledVersions(ctx)
		if !contains(installed, in.RuntimeVersion) {
			return res, errors.New("seçilen sürüm kurulu değil")
		}
		next.RuntimeVersion = in.RuntimeVersion
	}
	if next.Fields, err = prov.ValidateFields(in.Fields); err != nil {
		return res, err
	}
	if in.MemoryMaxMB < 64 || in.MemoryMaxMB > 65536 || in.CPUQuotaPct < 5 || in.CPUQuotaPct > 1600 {
		return res, errors.New("kaynak limitleri aralık dışında (bellek 64–65536 MB, CPU %5–%1600)")
	}
	next.MemoryMaxMB, next.CPUQuotaPct = in.MemoryMaxMB, in.CPUQuotaPct
	if next.PersistentDirs, err = ParsePersistentDirs(in.PersistentDirs); err != nil {
		return res, err
	}
	if in.HealthPath == "" {
		in.HealthPath = "/"
	}
	if !ValidHealthPath(in.HealthPath) {
		return res, errors.New("geçersiz health check yolu")
	}
	next.HealthPath = in.HealthPath
	if in.MaxUploadMB < 1 || in.MaxUploadMB > 10240 {
		return res, errors.New("maksimum yükleme 1–10240 MB olmalı")
	}
	next.MaxUploadMB = in.MaxUploadMB
	next.Gzip, next.HSTS, next.ForceHTTPS = in.Gzip, in.HSTS, in.ForceHTTPS
	next.CustomSnippet = strings.ReplaceAll(strings.TrimSpace(in.CustomSnippet), "\r\n", "\n")
	if err := ValidateSnippet(next.CustomSnippet, site.Domain); err != nil {
		return res, err
	}
	if def.Type == runtimes.TypeProxy {
		if _, err := prov.StartArgs(s.vars(next)); err != nil {
			return res, err
		}
	}

	defer s.lock(site.ID)()
	oldConf, _ := s.RenderNginxFor(site)
	newConf, err := s.RenderNginxFor(next)
	if err != nil {
		return res, err
	}
	if newConf != oldConf {
		if err := s.applyNginx(ctx, nil, next, ModeFor(next.Status)); err != nil {
			return res, err
		}
		res.NginxDiff = logs.LineDiff(oldConf, newConf)
	}
	if def.Type == runtimes.TypeProxy && (next.MemoryMaxMB != site.MemoryMaxMB || next.CPUQuotaPct != site.CPUQuotaPct ||
		next.RuntimeVersion != site.RuntimeVersion || !maps.Equal(next.Fields, site.Fields)) {
		if err := s.installUnit(ctx, nil, next); err != nil {
			// Roll nginx back so config and unit don't diverge.
			s.applyNginx(context.WithoutCancel(ctx), nil, site, ModeFor(site.Status))
			return res, err
		}
		res.UnitChanged = true
		res.RestartAdvised = next.Status == StatusRunning
		if next.RuntimeVersion != site.RuntimeVersion {
			// Env may reference the version (e.g. paths); rewrite it.
			user, err := s.Env(ctx, site.ID)
			if err == nil {
				s.writeEnv(ctx, nil, next, user)
			}
		}
	}
	if !slices.Equal(next.PersistentDirs, site.PersistentDirs) {
		res.RestartAdvised = res.RestartAdvised || next.Status == StatusRunning
	}
	return res, s.Store.UpdateSettings(ctx, next)
}

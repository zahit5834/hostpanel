package sites

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"strings"

	"github.com/zahit5834/hostpanel/internal/jobs"
	"github.com/zahit5834/hostpanel/internal/logs"
	"github.com/zahit5834/hostpanel/internal/runtimes"
)

// --- D1: same-line runtime patches (.NET X.Y.*, Node X.*) ---

// PatchOffer is a newer patch of an installed runtime line.
type PatchOffer struct {
	Runtime     string // runtime id
	Name        string // display name
	From, To    string
	ToInstalled bool    // the new patch is already on the server
	Sites       []int64 // sites still on From
}

// Channel is the release line a version belongs to: .NET "10.0", Node "24".
// "" when the runtime has no official version list.
func Channel(source, v string) string {
	p := strings.Split(v, ".")
	switch {
	case source == "dotnet-releases" && len(p) >= 2:
		return p[0] + "." + p[1]
	case source == "node-dist" && len(p) >= 1:
		return p[0]
	}
	return ""
}

// newer reports whether a > b (X.Y.Z).
func newer(a, b string) bool {
	if a == b {
		return false
	}
	vs := []string{a, b}
	runtimes.SortVersions(vs)
	return vs[0] == a
}

// PatchOffers lists, for every installed version of a runtime with an
// official list, the newest patch of the same line when it is newer. Major
// (or .NET minor) changes are never offered.
func (s *Service) PatchOffers(ctx context.Context) []PatchOffer {
	var out []PatchOffer
	all, _ := s.Store.List(ctx, 0)
	for _, prov := range s.Runtimes.All() {
		def := prov.Def()
		src := def.Versions.Available
		if src == "" || !def.HasUnit() || def.Versions.InstallScript == "" {
			continue
		}
		installed, err := prov.InstalledVersions(ctx)
		if err != nil || len(installed) == 0 {
			continue
		}
		avail, err := prov.AvailableVersions(ctx)
		if err != nil {
			continue
		}
		for _, v := range installed {
			ch := Channel(src, v)
			if ch == "" {
				continue
			}
			best := ""
			for _, a := range avail {
				if Channel(src, a.Version) == ch && newer(a.Version, v) && (best == "" || newer(a.Version, best)) {
					best = a.Version
				}
			}
			if best == "" {
				continue
			}
			o := PatchOffer{Runtime: def.ID, Name: def.DisplayName, From: v, To: best, ToInstalled: slices.Contains(installed, best)}
			for _, st := range all {
				if st.RuntimeID == def.ID && st.RuntimeVersion == v {
					o.Sites = append(o.Sites, st.ID)
				}
			}
			out = append(out, o)
		}
	}
	return out
}

// SubmitPatch queues "install the patch and move the sites".
func (s *Service) SubmitPatch(ctx context.Context, runtimeID, from, to string) (int64, error) {
	var offer *PatchOffer
	for _, o := range s.PatchOffers(ctx) {
		if o.Runtime == runtimeID && o.From == from && o.To == to {
			offer = &o
			break
		}
	}
	if offer == nil {
		return 0, errors.New("bu güncelleme artık geçerli değil (sayfayı yenileyin)")
	}
	return s.Jobs.Submit(ctx, jobs.Spec{Kind: "runtime.patch", TargetType: "runtime", TargetID: runtimeID + "@" + to,
		Summary: offer.Name + " " + from + " → " + to + " (kur ve siteleri taşı)", Retryable: true,
		Params: map[string]any{"runtime": runtimeID, "from": from, "to": to}})
}

func (s *Service) jobPatch(ctx context.Context, l *jobs.Log, p map[string]any) error {
	id, _ := p["runtime"].(string)
	from, _ := p["from"].(string)
	to, _ := p["to"].(string)
	prov, ok := s.Runtimes.Get(id)
	if !ok || !runtimes.IsSemver(from) || !runtimes.IsSemver(to) {
		return errors.New("geçersiz altyapı ya da sürüm")
	}
	def := prov.Def()
	src := def.Versions.Available
	if Channel(src, from) == "" || Channel(src, from) != Channel(src, to) || !newer(to, from) {
		return errors.New("yalnızca aynı sürüm hattındaki daha yeni bir yama kurulabilir")
	}
	installed, _ := prov.InstalledVersions(ctx)
	if !slices.Contains(installed, to) {
		l.Printf("%s %s kuruluyor…", def.DisplayName, to)
		if err := s.jobRuntime("install")(ctx, l, map[string]any{"runtime": id, "version": to}); err != nil {
			return fmt.Errorf("kurulum başarısız: %w", err)
		}
	} else {
		l.Printf("%s %s zaten kurulu", def.DisplayName, to)
	}
	l.Progress(30)
	all, err := s.Store.List(ctx, 0)
	if err != nil {
		return err
	}
	var todo []Site
	for _, st := range all {
		if st.RuntimeID == id && st.RuntimeVersion == from {
			todo = append(todo, st)
		}
	}
	var failed []string
	for i, site := range todo {
		if err := s.moveSite(ctx, l, site, def, to); err != nil {
			l.Printf("✗ %s: %v (eski sürümde kaldı)", site.Domain, err)
			failed = append(failed, site.Domain)
		}
		l.Progress(30 + 70*(i+1)/len(todo))
	}
	l.Progress(100)
	moved := len(todo) - len(failed)
	l.Printf("Taşınan site: %d / %d", moved, len(todo))
	if len(failed) > 0 {
		return fmt.Errorf("%d site %s sürümünde kaldı: %s", len(failed), from, strings.Join(failed, ", "))
	}
	if s.Store.CountByRuntimeVersion(ctx, id, from) == 0 {
		l.Printf("%s artık hiçbir sitede kullanılmıyor; Altyapılar sayfasından kaldırabilirsiniz.", from)
	}
	return nil
}

// moveSite switches one site to the new patch: unit + env, restart (when it
// runs), health check; on failure everything goes back to the old version.
func (s *Service) moveSite(ctx context.Context, l *jobs.Log, site Site, def *runtimes.Definition, to string) error {
	unlock := s.lock(site.ID)
	defer unlock()
	from := site.RuntimeVersion
	next := site
	next.RuntimeVersion = to
	user, envErr := s.Env(ctx, site.ID)
	apply := func(v Site) error {
		if err := s.installUnit(ctx, l, v); err != nil {
			return err
		}
		if envErr == nil {
			if err := s.writeEnv(ctx, l, v, user); err != nil {
				return err
			}
		}
		return s.Store.UpdateSettings(ctx, v)
	}
	running := site.Status == StatusRunning && s.Store.ActiveRelease(ctx, site.ID) != PlaceholderRelease
	l.Printf("→ %s: %s → %s", site.Domain, from, to)
	err := apply(next)
	if err == nil && running {
		if err = s.helper(ctx, l, nil, nil, "hp-site-service.sh", "restart", site.ShortName); err == nil {
			err = s.healthCheck(ctx, l, next, def)
		}
	}
	if err == nil {
		s.Activity.Record(ctx, logs.Entry{Action: "site.runtime.patch", TargetType: "site", TargetID: site.Domain,
			Summary: site.Domain + ": " + def.DisplayName + " " + from + " → " + to}, map[string]any{"job_id": l.ID()})
		if !running {
			l.Printf("  site çalışmıyor; yeni sürüm bir sonraki başlatmada kullanılacak")
		}
		return nil
	}
	l.Printf("  hata, %s sürümüne dönülüyor…", from)
	bg := context.WithoutCancel(ctx)
	if rerr := apply(site); rerr != nil {
		l.Printf("  GERİ DÖNÜŞ BAŞARISIZ: %v", rerr)
	} else if running {
		s.helper(bg, l, nil, nil, "hp-site-service.sh", "restart", site.ShortName)
	}
	s.Activity.Record(ctx, logs.Entry{Action: "site.runtime.patch", TargetType: "site", TargetID: site.Domain, Status: logs.StatusFailed,
		Summary: site.Domain + ": " + def.DisplayName + " " + to + " başarısız, " + from + " sürümünde kaldı", Error: err.Error()},
		map[string]any{"job_id": l.ID()})
	return err
}

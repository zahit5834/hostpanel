package sites

import (
	"bytes"
	"context"
	"database/sql"
	"errors"
	"fmt"
	"io"
	"regexp"
	"strconv"
	"strings"
	"time"

	"hostpanel/internal/exec"
	"hostpanel/internal/jobs"
	"hostpanel/internal/logs"
	"hostpanel/internal/runtimes"
)

// GitSettings is a site's git deploy configuration. The private deploy key
// never leaves /etc/hostpanel/git/<domain>/ (root 0600).
type GitSettings struct {
	SiteID       int64
	RepoURL      string
	Branch       string
	BuildCommand string
	OutputDir    string
	BuildTimeout int // seconds
	PublicKey    string
	LastCommit   string
	LastSubject  string
	UpdatedAt    time.Time
}

// Git deploy limits.
const (
	MinBuildTimeout     = 60
	MaxBuildTimeout     = 3600
	DefaultBuildTimeout = 900
	MinBuildMemoryMB    = 1024
)

// GitDefaults are the prefilled build settings per runtime.
func GitDefaults(runtimeID string) GitSettings {
	g := GitSettings{Branch: "main", OutputDir: ".", BuildTimeout: DefaultBuildTimeout}
	switch runtimeID {
	case "dotnet":
		g.BuildCommand, g.OutputDir = "dotnet publish -c Release -o hp-publish", "hp-publish"
	case "node":
		g.BuildCommand = "npm ci && npm run build --if-present"
	case "php":
		g.BuildCommand = "if [ -f composer.json ]; then composer install --no-dev --optimize-autoloader --no-interaction; fi"
	}
	return g
}

var (
	gitHost   = `[A-Za-z0-9]([A-Za-z0-9-]*[A-Za-z0-9])?(\.[A-Za-z0-9]([A-Za-z0-9-]*[A-Za-z0-9])?)*`
	gitPath   = `[A-Za-z0-9_~][A-Za-z0-9._~/-]*`
	gitURLRes = []*regexp.Regexp{
		regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]*@` + gitHost + `:` + gitPath + `$`),
		regexp.MustCompile(`^ssh://([A-Za-z0-9][A-Za-z0-9._-]*@)?` + gitHost + `(:[0-9]{1,5})?/` + gitPath + `$`),
		regexp.MustCompile(`^https://` + gitHost + `(:[0-9]{1,5})?/` + gitPath + `$`),
	}
	branchRe = regexp.MustCompile(`^[A-Za-z0-9_][A-Za-z0-9._/-]{0,99}$`)
	shaRe    = regexp.MustCompile(`^[0-9a-f]{40}([0-9a-f]{24})?$`)
)

// ValidGitURL: git@host:path, ssh://[user@]host[:port]/path or
// https://host[:port]/path without credentials. Mirrors validate_git_url.
func ValidGitURL(u string) bool {
	if len(u) > 300 || strings.Contains(u, "..") {
		return false
	}
	for _, re := range gitURLRes {
		if re.MatchString(u) {
			return true
		}
	}
	return false
}

// SSHGitURL reports whether the URL uses SSH (needs the deploy key).
func SSHGitURL(u string) bool { return !strings.HasPrefix(u, "https://") }

// ValidBranch mirrors validate_git_branch.
func ValidBranch(b string) bool {
	return branchRe.MatchString(b) && !strings.Contains(b, "..") && !strings.Contains(b, "//") &&
		!strings.HasSuffix(b, "/") && !strings.HasSuffix(b, ".") && !strings.HasSuffix(b, ".lock") && !strings.Contains(b, "/.")
}

// ValidOutputDir: "." or a relative directory (validate_outdir).
func ValidOutputDir(d string) bool { return d == "." || ValidRelDir(d) }

// Validate cleans and checks the form values.
func (g *GitSettings) Validate() error {
	g.RepoURL, g.Branch = strings.TrimSpace(g.RepoURL), strings.TrimSpace(g.Branch)
	g.BuildCommand, g.OutputDir = strings.TrimSpace(g.BuildCommand), strings.Trim(strings.TrimSpace(g.OutputDir), "/")
	if g.OutputDir == "" {
		g.OutputDir = "."
	}
	if g.BuildTimeout == 0 {
		g.BuildTimeout = DefaultBuildTimeout
	}
	switch {
	case !ValidGitURL(g.RepoURL):
		return errors.New("geçersiz repo adresi (git@host:kullanıcı/repo.git, ssh://… veya kimlik bilgisi içermeyen https://…)")
	case !ValidBranch(g.Branch):
		return errors.New("geçersiz branch adı")
	case !ValidOutputDir(g.OutputDir):
		return errors.New("geçersiz çıktı dizini (göreli yol, .. yok)")
	case g.BuildTimeout < MinBuildTimeout || g.BuildTimeout > MaxBuildTimeout:
		return fmt.Errorf("build zaman aşımı %d–%d saniye olmalı", MinBuildTimeout, MaxBuildTimeout)
	}
	if g.BuildCommand != "" {
		if err := ValidCommand(g.BuildCommand); err != nil {
			return errors.New("build komutu: " + err.Error())
		}
	}
	return nil
}

// --- store ---

// Git returns the site's git settings (sql.ErrNoRows if none).
func (st *Store) Git(ctx context.Context, siteID int64) (GitSettings, error) {
	var g GitSettings
	var upd int64
	err := st.db.QueryRowContext(ctx, `SELECT site_id, repo_url, branch, build_command, output_dir, build_timeout, public_key,
		last_commit, last_subject, updated_at FROM site_git WHERE site_id=?`, siteID).Scan(&g.SiteID, &g.RepoURL, &g.Branch,
		&g.BuildCommand, &g.OutputDir, &g.BuildTimeout, &g.PublicKey, &g.LastCommit, &g.LastSubject, &upd)
	g.UpdatedAt = time.Unix(upd, 0)
	return g, err
}

// SaveGit upserts the editable fields.
func (st *Store) SaveGit(ctx context.Context, g GitSettings) error {
	_, err := st.db.ExecContext(ctx, `INSERT INTO site_git(site_id, repo_url, branch, build_command, output_dir, build_timeout, updated_at)
		VALUES (?,?,?,?,?,?,?) ON CONFLICT(site_id) DO UPDATE SET repo_url=excluded.repo_url, branch=excluded.branch,
		build_command=excluded.build_command, output_dir=excluded.output_dir, build_timeout=excluded.build_timeout,
		updated_at=excluded.updated_at`, g.SiteID, g.RepoURL, g.Branch, g.BuildCommand, g.OutputDir, g.BuildTimeout, time.Now().Unix())
	return err
}

func (st *Store) setGitKey(ctx context.Context, siteID int64, pub string) error {
	_, err := st.db.ExecContext(ctx, `UPDATE site_git SET public_key=? WHERE site_id=?`, pub, siteID)
	return err
}

func (st *Store) setGitCommit(ctx context.Context, siteID int64, sha, subject string) error {
	_, err := st.db.ExecContext(ctx, `UPDATE site_git SET last_commit=?, last_subject=? WHERE site_id=?`, sha, subject, siteID)
	return err
}

// --- service ---

func gitDiff(old, cur GitSettings) string {
	var b strings.Builder
	f := func(name, a, c string) {
		if a != c {
			if a != "" {
				fmt.Fprintf(&b, "- %s=%s\n", name, a)
			}
			fmt.Fprintf(&b, "+ %s=%s\n", name, c)
		}
	}
	f("repo", old.RepoURL, cur.RepoURL)
	f("branch", old.Branch, cur.Branch)
	f("build", old.BuildCommand, cur.BuildCommand)
	f("çıktı", old.OutputDir, cur.OutputDir)
	if old.BuildTimeout != cur.BuildTimeout {
		f("zaman_aşımı", strconv.Itoa(old.BuildTimeout), strconv.Itoa(cur.BuildTimeout))
	}
	return strings.TrimRight(b.String(), "\n")
}

// SaveGit validates and stores the git settings; a deploy key is generated on
// first save of an SSH repo.
func (s *Service) SaveGit(ctx context.Context, site Site, g GitSettings) (GitSettings, error) {
	g.SiteID = site.ID
	if err := g.Validate(); err != nil {
		return g, err
	}
	old, err := s.Store.Git(ctx, site.ID)
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return g, err
	}
	if err := s.Store.SaveGit(ctx, g); err != nil {
		return g, err
	}
	s.Activity.Record(ctx, logs.Entry{Action: "site.git.update", TargetType: "site", TargetID: site.Domain,
		Summary: "Git deploy ayarları kaydedildi: " + site.Domain, Diff: gitDiff(old, g)}, nil)
	if SSHGitURL(g.RepoURL) && old.PublicKey == "" {
		if _, err := s.GitKeygen(ctx, site); err != nil {
			return g, fmt.Errorf("ayarlar kaydedildi ama deploy key üretilemedi: %w", err)
		}
	}
	return s.Store.Git(ctx, site.ID)
}

// GitKeygen creates a new deploy key (the old one stops working) and returns
// its public half.
func (s *Service) GitKeygen(ctx context.Context, site Site) (string, error) {
	if _, err := s.Store.Git(ctx, site.ID); err != nil {
		return "", errors.New("önce git ayarlarını kaydedin")
	}
	c := exec.Helper(s.ScriptsDir, "hp-site-git.sh", "keygen", site.Domain)
	c.Timeout = 30 * time.Second
	res, err := s.Runner.Run(ctx, c)
	if err != nil {
		return "", err
	}
	pub := strings.TrimSpace(res.Stdout)
	if res.DryRun {
		pub = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIDRYRUNEUllSVU4tZGVwbG95LWtleS1wbGFjZWhvbGRlcg hostpanel-deploy@" + site.Domain
	}
	if !strings.HasPrefix(pub, "ssh-ed25519 ") || strings.ContainsAny(pub, "\n\r") {
		return "", errors.New("deploy key üretilemedi")
	}
	if err := s.Store.setGitKey(ctx, site.ID, pub); err != nil {
		return "", err
	}
	s.Activity.Record(ctx, logs.Entry{Action: "site.git.keygen", TargetType: "site", TargetID: site.Domain,
		Summary: "Yeni git deploy key üretildi: " + site.Domain}, nil)
	return pub, nil
}

// GitInfo is what the helper reports about keys.
type GitInfo struct {
	KeyFingerprint string
	HostKeys       []string // "host SHA256:… (ED25519)"
}

// GitInfo reads the deploy key fingerprint and the accepted host keys.
func (s *Service) GitInfo(ctx context.Context, site Site) GitInfo {
	var gi GitInfo
	c := exec.Helper(s.ScriptsDir, "hp-site-git.sh", "info", site.Domain)
	c.Timeout = 15 * time.Second
	res, err := s.Runner.Run(ctx, c)
	if err != nil || res.DryRun {
		return gi
	}
	for _, l := range strings.Split(res.Stdout, "\n") {
		if v, ok := strings.CutPrefix(l, "fp="); ok {
			gi.KeyFingerprint = strings.TrimSpace(v)
		} else if v, ok := strings.CutPrefix(l, "host="); ok && len(gi.HostKeys) < 10 {
			gi.HostKeys = append(gi.HostKeys, strings.TrimSpace(v))
		}
	}
	return gi
}

// GitResetHostKey forgets the accepted host key(s).
func (s *Service) GitResetHostKey(ctx context.Context, site Site) error {
	if err := s.helper(ctx, nil, nil, nil, "hp-site-git.sh", "reset-hostkey", site.Domain); err != nil {
		return err
	}
	s.Activity.Record(ctx, logs.Entry{Action: "site.git.hostkey-reset", TargetType: "site", TargetID: site.Domain,
		Summary: "Git host anahtarı kaydı sıfırlandı: " + site.Domain}, nil)
	return nil
}

// StartGitDeploy queues a deploy from the configured branch.
func (s *Service) StartGitDeploy(ctx context.Context, site Site) (int64, error) {
	g, err := s.Store.Git(ctx, site.ID)
	if err != nil {
		return 0, errors.New("önce git ayarlarını kaydedin")
	}
	if err := s.gitPreflight(ctx, site, g); err != nil {
		return 0, err
	}
	return s.Jobs.Submit(ctx, jobs.Spec{Kind: "site.deploy", TargetType: "site", TargetID: site.Domain,
		Summary: "Git deploy: " + site.Domain + " (" + g.Branch + ")", Params: map[string]any{"site_id": site.ID, "git": true}})
}

// gitPreflight catches problems before a job is queued.
func (s *Service) gitPreflight(ctx context.Context, site Site, g GitSettings) error {
	if site.Status == StatusProvisioning {
		return errors.New("site henüz hazırlanıyor")
	}
	if SSHGitURL(g.RepoURL) && g.PublicKey == "" {
		return errors.New("deploy key yok; \"Yeni deploy key\" ile üretin ve repo'ya ekleyin")
	}
	prov, err := s.provider(site)
	if err != nil {
		return err
	}
	if g.BuildCommand != "" && prov.Def().SDK != nil && !runtimes.HasSDKFor(prov.InstalledSDKs(ctx), site.RuntimeVersion) {
		major, _, _ := strings.Cut(site.RuntimeVersion, ".")
		return fmt.Errorf("build için .NET %s SDK'sı kurulu değil (Altyapılar → .NET → SDK kur)", major)
	}
	return nil
}

// gitBuild runs fetch → build → release for a new release and returns the
// commit. On failure the build directory is removed.
func (s *Service) gitBuild(ctx context.Context, l *jobs.Log, site Site, release string) (string, error) {
	g, err := s.Store.Git(ctx, site.ID)
	if err != nil {
		return "", errors.New("git ayarları bulunamadı")
	}
	if err := s.gitPreflight(ctx, site, g); err != nil {
		return "", err
	}
	clean := func() {
		s.helper(context.WithoutCancel(ctx), l, nil, nil, "hp-site-git.sh", "clean", site.Domain, release)
	}
	l.Printf("Repo: %s (%s)", g.RepoURL, g.Branch)
	var out bytes.Buffer
	c := exec.Helper(s.ScriptsDir, "hp-site-git.sh", "fetch", site.Domain, site.User(), g.Branch, release)
	c.Stdin, c.Output, c.Timeout = strings.NewReader(g.RepoURL), io.MultiWriter(l, &out), 15*time.Minute
	res, err := s.Runner.Run(ctx, c)
	if err != nil {
		clean()
		return "", err
	}
	sha, subject := "", ""
	for _, line := range strings.Split(out.String(), "\n") {
		if v, ok := strings.CutPrefix(line, "commit="); ok {
			sha = strings.TrimSpace(v)
		} else if v, ok := strings.CutPrefix(line, "subject="); ok {
			subject = strings.TrimSpace(v)
		}
	}
	if res.DryRun {
		sha, subject = strings.Repeat("0", 40), "(dry-run)"
	}
	if !shaRe.MatchString(sha) {
		clean()
		return "", errors.New("commit bilgisi alınamadı")
	}
	l.Printf("Commit: %s %s", sha[:7], subject)
	l.Progress(20)

	if g.BuildCommand != "" {
		mem := max(site.MemoryMaxMB, MinBuildMemoryMB)
		cpu := max(site.CPUQuotaPct, 100)
		version := site.RuntimeVersion
		if version == "" {
			version = "-"
		}
		l.Printf("Build (site kullanıcısı %s, en fazla %d sn, %d MB): %s", site.User(), g.BuildTimeout, mem, g.BuildCommand)
		c := exec.Helper(s.ScriptsDir, "hp-site-git.sh", "build", site.Domain, site.User(), release, site.RuntimeID, version,
			strconv.Itoa(g.BuildTimeout), strconv.Itoa(mem), strconv.Itoa(cpu))
		c.Stdin, c.Output, c.Timeout = strings.NewReader(g.BuildCommand), l, time.Duration(g.BuildTimeout)*time.Second+time.Minute
		if _, err := s.Runner.Run(ctx, c); err != nil {
			clean()
			return "", fmt.Errorf("build başarısız: %w", err)
		}
	} else {
		l.Printf("Build komutu yok; repo içeriği olduğu gibi yayınlanacak.")
	}
	l.Progress(35)
	args := append([]string{"release", site.Domain, site.User(), release, g.OutputDir}, site.PersistentDirs...)
	if err := s.helper(ctx, l, nil, nil, "hp-site-git.sh", args...); err != nil {
		clean()
		return "", err
	}
	s.Store.setGitCommit(ctx, site.ID, sha, subject)
	return sha, nil
}

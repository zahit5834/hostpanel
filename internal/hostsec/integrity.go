package hostsec

import (
	"crypto/sha256"
	"encoding/hex"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"syscall"
)

// Manifest maps an installed path key to its SHA-256:
//
//	scripts/<rel>    → <ScriptsDir>/<rel>
//	templates/<rel>  → <TemplatesDir>/<rel>
//	sudoers          → /etc/sudoers.d/hostpanel (read by the root helper)
//	unit             → /etc/systemd/system/hostpanel.service
type Manifest map[string]string

// packaged reports whether deploy/package.sh ships a file of deploy/scripts
// (tests stay in the repository).
func packaged(rel string) bool {
	base := filepath.Base(rel)
	return !strings.HasPrefix(base, "test_") && !strings.HasPrefix(base, "testdata_")
}

// BuildManifest hashes a deploy/ tree (the repository's or a release's).
func BuildManifest(deployDir string) (Manifest, error) {
	m := Manifest{}
	for _, tree := range []string{"scripts", "templates"} {
		root := filepath.Join(deployDir, tree)
		err := filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
			if err != nil || d.IsDir() {
				return err
			}
			rel, _ := filepath.Rel(root, p)
			if tree == "scripts" && !packaged(rel) {
				return nil
			}
			sum, err := fileSum(p)
			if err != nil {
				return err
			}
			m[tree+"/"+filepath.ToSlash(rel)] = sum
			return nil
		})
		if err != nil {
			return nil, err
		}
	}
	for key, p := range map[string]string{"sudoers": "sudoers/hostpanel", "unit": "systemd/hostpanel.service"} {
		sum, err := fileSum(filepath.Join(deployDir, p))
		if err != nil {
			return nil, err
		}
		m[key] = sum
	}
	return m, nil
}

// ReleaseManifest returns the manifest compiled into this binary.
func ReleaseManifest() Manifest { return releaseManifest }

func fileSum(p string) (string, error) {
	b, err := os.ReadFile(p)
	if err != nil {
		return "", err
	}
	h := sha256.Sum256(b)
	return hex.EncodeToString(h[:]), nil
}

// IntegrityIssue is one deviation from the release.
type IntegrityIssue struct {
	Path string
	Kind string // changed, missing, extra, writable
}

// Label is the Turkish description of Kind.
func (i IntegrityIssue) Label() string {
	switch i.Kind {
	case "changed":
		return "değiştirilmiş"
	case "missing":
		return "eksik"
	case "extra":
		return "pakette olmayan dosya"
	case "writable":
		return "root dışında yazılabilir"
	case "unreadable":
		return "okunamadı"
	}
	return i.Kind
}

// IntegrityPaths says where the installed files are.
type IntegrityPaths struct {
	ScriptsDir, TemplatesDir, Unit string
	SudoersSum                     string // from hp-system.sh sudoers-sum ("" = not checked, "missing")
	CheckOwner                     bool   // prod: files must be root-owned and not group/other writable
}

// CheckIntegrity compares the installed files with m. Issues are sorted by path.
func CheckIntegrity(m Manifest, p IntegrityPaths) []IntegrityIssue {
	var out []IntegrityIssue
	seen := map[string]bool{}
	for _, tree := range []struct{ key, dir string }{{"scripts", p.ScriptsDir}, {"templates", p.TemplatesDir}} {
		filepath.WalkDir(tree.dir, func(path string, d fs.DirEntry, err error) error {
			if err != nil {
				if path == tree.dir {
					return fs.SkipDir
				}
				return nil
			}
			rel, _ := filepath.Rel(tree.dir, path)
			key := tree.key + "/" + filepath.ToSlash(rel)
			if p.CheckOwner && writableByOthers(path, d) {
				out = append(out, IntegrityIssue{key, "writable"})
			}
			if d.IsDir() {
				return nil
			}
			if tree.key == "scripts" && !packaged(rel) {
				return nil // dev tree: tests next to the scripts
			}
			seen[key] = true
			want, ok := m[key]
			if !ok {
				out = append(out, IntegrityIssue{key, "extra"})
				return nil
			}
			if d.Type()&fs.ModeSymlink != 0 {
				out = append(out, IntegrityIssue{key, "changed"})
				return nil
			}
			got, err := fileSum(path)
			switch {
			case err != nil:
				out = append(out, IntegrityIssue{key, "unreadable"})
			case got != want:
				out = append(out, IntegrityIssue{key, "changed"})
			}
			return nil
		})
	}
	for k := range m {
		if (strings.HasPrefix(k, "scripts/") || strings.HasPrefix(k, "templates/")) && !seen[k] {
			out = append(out, IntegrityIssue{k, "missing"})
		}
	}
	if p.Unit != "" {
		got, err := fileSum(p.Unit)
		switch {
		case os.IsNotExist(err):
			out = append(out, IntegrityIssue{"unit", "missing"})
		case err != nil:
			out = append(out, IntegrityIssue{"unit", "unreadable"})
		case got != m["unit"]:
			out = append(out, IntegrityIssue{"unit", "changed"})
		}
	}
	switch p.SudoersSum {
	case "":
	case "missing":
		out = append(out, IntegrityIssue{"sudoers", "missing"})
	default:
		if p.SudoersSum != m["sudoers"] {
			out = append(out, IntegrityIssue{"sudoers", "changed"})
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Path < out[j].Path })
	return out
}

func writableByOthers(path string, d fs.DirEntry) bool {
	fi, err := os.Lstat(path)
	if err != nil {
		return false
	}
	if fi.Mode()&fs.ModeSymlink != 0 {
		return false // reported as changed/extra
	}
	st, ok := fi.Sys().(*syscall.Stat_t)
	return (ok && st.Uid != 0) || fi.Mode().Perm()&0o022 != 0
}

// IssuesKey is a stable fingerprint of a result (one notification per state).
func IssuesKey(issues []IntegrityIssue) string {
	if len(issues) == 0 {
		return ""
	}
	h := sha256.New()
	for _, i := range issues {
		h.Write([]byte(i.Path + "\x00" + i.Kind + "\n"))
	}
	return hex.EncodeToString(h.Sum(nil))[:16]
}

// HumanPath maps a manifest key to the installed path.
func (p IntegrityPaths) HumanPath(key string) string {
	switch {
	case key == "sudoers":
		return "/etc/sudoers.d/hostpanel"
	case key == "unit":
		return p.Unit
	case strings.HasPrefix(key, "scripts/"):
		return filepath.Join(p.ScriptsDir, strings.TrimPrefix(key, "scripts/"))
	case strings.HasPrefix(key, "templates/"):
		return filepath.Join(p.TemplatesDir, strings.TrimPrefix(key, "templates/"))
	}
	return key
}

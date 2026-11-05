package sites

import (
	"bufio"
	"errors"
	"fmt"
	"os"
	"regexp"
	"strconv"
	"strings"
)

// domainRe mirrors validate_domain in deploy/scripts/lib.sh: keep them identical.
var domainRe = regexp.MustCompile(`^([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$`)

// ValidDomain reports whether d is an acceptable lowercase FQDN.
func ValidDomain(d string) bool { return len(d) >= 3 && len(d) <= 253 && domainRe.MatchString(d) }

// NormalizeDomain lowercases and strips scheme, path, port and a trailing dot.
func NormalizeDomain(d string) string {
	d = strings.ToLower(strings.TrimSpace(d))
	d = strings.TrimPrefix(strings.TrimPrefix(d, "https://"), "http://")
	if i := strings.IndexAny(d, "/:"); i >= 0 {
		d = d[:i]
	}
	return strings.TrimSuffix(d, ".")
}

// ParseAliases splits user input (comma/space/newline) into normalized, unique, valid aliases.
func ParseAliases(raw, domain string) ([]string, error) {
	seen := map[string]bool{domain: true, "www." + domain: true}
	var out []string
	for _, f := range strings.FieldsFunc(raw, func(r rune) bool { return r == ',' || r == ' ' || r == '\n' || r == '\r' || r == '\t' }) {
		a := NormalizeDomain(f)
		if a == "" || seen[a] {
			continue
		}
		if !ValidDomain(a) {
			return nil, fmt.Errorf("geçersiz alias: %s", f)
		}
		seen[a] = true
		out = append(out, a)
	}
	if len(out) > 20 {
		return nil, errors.New("en fazla 20 alias")
	}
	return out, nil
}

var nonAlnum = regexp.MustCompile(`[^a-z0-9]+`)

// MaxShortName keeps site_<short> within Linux's 32-char username limit.
const MaxShortName = 24

// BaseShortName derives an identifier from a domain: "www.ornek.com.tr" → "ornek_com_tr".
func BaseShortName(domain string) string {
	s := nonAlnum.ReplaceAllString(strings.TrimPrefix(domain, "www."), "_")
	s = strings.Trim(s, "_")
	if s == "" || s[0] < 'a' || s[0] > 'z' {
		s = "s" + s
	}
	if len(s) > MaxShortName {
		s = strings.TrimRight(s[:MaxShortName], "_")
	}
	return s
}

// UniqueShortName appends _2, _3… until taken returns false.
func UniqueShortName(domain string, taken func(string) bool) string {
	base := BaseShortName(domain)
	if !taken(base) {
		return base
	}
	for i := 2; ; i++ {
		suf := "_" + strconv.Itoa(i)
		b := base
		if len(b)+len(suf) > MaxShortName {
			b = b[:MaxShortName-len(suf)]
		}
		if c := b + suf; !taken(c) {
			return c
		}
	}
}

var dirRe = regexp.MustCompile(`^[A-Za-z0-9._-]+(/[A-Za-z0-9._-]+)*$`)

// ParsePersistentDirs validates relative directory names kept under shared/.
func ParsePersistentDirs(raw string) ([]string, error) {
	var out []string
	seen := map[string]bool{}
	for _, f := range strings.FieldsFunc(raw, func(r rune) bool { return r == ',' || r == '\n' || r == '\r' || r == ' ' }) {
		f = strings.Trim(f, "/")
		if f == "" || seen[f] {
			continue
		}
		if !dirRe.MatchString(f) || strings.Contains(f, "..") || strings.HasPrefix(f, ".") {
			return nil, fmt.Errorf("geçersiz kalıcı dizin: %s", f)
		}
		seen[f] = true
		out = append(out, f)
	}
	if len(out) > 20 {
		return nil, errors.New("en fazla 20 kalıcı dizin")
	}
	return out, nil
}

var envKeyRe = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*$`)

// ValidEnvKey mirrors the check in hp-site-env.sh.
func ValidEnvKey(k string) bool { return len(k) <= 128 && envKeyRe.MatchString(k) }

// ValidEnvValue rejects values that cannot live on one EnvironmentFile line.
func ValidEnvValue(v string) bool {
	return len(v) <= 8192 && !strings.ContainsAny(v, "\n\r\x00")
}

var healthRe = regexp.MustCompile(`^/[A-Za-z0-9._~/?=&%-]*$`)

// ValidHealthPath checks the health-check URL path.
func ValidHealthPath(p string) bool { return len(p) <= 200 && healthRe.MatchString(p) }

// Port range for app processes (127.0.0.1 only).
const (
	PortMin = 5000
	PortMax = 5999
)

// FreePort picks the first port in range not assigned in DB and not listening now.
func FreePort(used map[int]bool) (int, error) {
	listening := listeningPorts()
	for p := PortMin; p <= PortMax; p++ {
		if !used[p] && !listening[p] {
			return p, nil
		}
	}
	return 0, errors.New("5000-5999 aralığında boş port kalmadı")
}

// listeningPorts reads TCP LISTEN sockets from /proc (state 0A).
func listeningPorts() map[int]bool {
	out := map[int]bool{}
	for _, f := range []string{"/proc/net/tcp", "/proc/net/tcp6"} {
		fh, err := os.Open(f)
		if err != nil {
			continue
		}
		sc := bufio.NewScanner(fh)
		sc.Scan() // header
		for sc.Scan() {
			fields := strings.Fields(sc.Text())
			if len(fields) < 4 || fields[3] != "0A" {
				continue
			}
			if i := strings.LastIndexByte(fields[1], ':'); i >= 0 {
				if p, err := strconv.ParseUint(fields[1][i+1:], 16, 16); err == nil {
					out[int(p)] = true
				}
			}
		}
		fh.Close()
	}
	return out
}

// ValidateSnippet checks a custom nginx snippet before saving. Logging
// directives are not allowed in snippets at all; the full config is then
// checked again by ValidateConf and by the root helper.
func ValidateSnippet(s, domain string) error {
	if len(s) > 8192 {
		return errors.New("snippet çok uzun (en fazla 8 KB)")
	}
	if strings.Count(s, "{") != strings.Count(s, "}") {
		return errors.New("süslü parantezler dengesiz")
	}
	for _, d := range confDirectives(s) {
		if d.name == "access_log" || d.name == "error_log" || sslFileNames.MatchString(d.name) {
			return fmt.Errorf("snippet içinde %s kullanılamaz", d.name)
		}
	}
	return ValidateConf(s, domain)
}

type confDirective struct{ name, arg string }

// confDirectives splits a config into statements at ';', '{' and '}' and
// returns each statement's first two tokens with quotes and backslashes removed.
// Splitting at every such character (even inside quotes or comments) can only
// produce extra statements, never hide a real one, so the check errs on the
// strict side. Mirrors validate_nginx_conf in deploy/scripts/lib.sh.
func confDirectives(conf string) []confDirective {
	clean := strings.NewReplacer(`"`, "", `'`, "", `\`, "")
	var out []confDirective
	for _, st := range strings.FieldsFunc(conf, func(r rune) bool { return r == ';' || r == '{' || r == '}' }) {
		f := strings.Fields(st)
		if len(f) == 0 {
			continue
		}
		name := clean.Replace(f[0])
		if strings.HasPrefix(name, "#") {
			// A comment hides the rest of its line only; later lines are separate tokens.
			lines := strings.SplitN(st, "\n", 2)
			if len(lines) == 2 {
				out = append(out, confDirectives(lines[1])...)
			}
			continue
		}
		d := confDirective{name: name}
		if len(f) > 1 {
			d.arg = clean.Replace(f[1])
		}
		out = append(out, d)
	}
	return out
}

var forbiddenNames = regexp.MustCompile(`^(load_module|include|user|env|pid|daemon|master_process|lock_file|ssl_engine|ssl_conf_command|[a-z]+_ssl_conf_command|working_directory|thread_pool|worker_[a-z_]+|[a-z_]*_temp_path|[a-z_]*_cache_path|perl[a-z_]*|lua[a-z_]*|js_[a-z_]+)$`)

// sslFileNames are directives whose argument is a file the root master reads
// (also proxy_/grpc_/uwsgi_ upstream variants).
var sslFileNames = regexp.MustCompile(`^([a-z]+_)?ssl_(certificate|certificate_key|trusted_certificate|client_certificate|crl|dhparam|password_file|stapling_file|session_ticket_key)$`)

// sslPathOK: certificate files may only come from the site's own Let's
// Encrypt lineage or its custom certificate directory.
func sslPathOK(p, domain string) bool {
	if strings.Contains(p, "..") || strings.Contains(p, "$") {
		return false
	}
	return strings.HasPrefix(p, "/etc/letsencrypt/live/"+domain+"/") || strings.HasPrefix(p, "/etc/hostpanel/ssl/"+domain+"/")
}

// ValidateConf rejects directives that would let the config make the root
// nginx master open arbitrary files or load code.
func ValidateConf(conf, domain string) error {
	for _, d := range confDirectives(conf) {
		switch {
		case forbiddenNames.MatchString(d.name):
			return fmt.Errorf("bu direktife izin verilmiyor: %s", d.name)
		case sslFileNames.MatchString(d.name) && !sslPathOK(d.arg, domain):
			return fmt.Errorf("%s yalnızca sitenin kendi sertifika dosyalarını gösterebilir", d.name)
		case d.name == "access_log" && d.arg != "off" && d.arg != "/var/log/nginx/hp-"+domain+".access.log",
			d.name == "error_log" && d.arg != "/var/log/nginx/hp-"+domain+".error.log":
			return fmt.Errorf("%s yalnızca site log dosyasına yazabilir", d.name)
		}
	}
	return nil
}

package system

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"net/netip"
	"regexp"
	"strconv"
	"strings"
)

// UFWStatus is hp-server.sh ufw-status parsed.
type UFWStatus struct {
	Installed bool
	Active    bool
	Protected []int
	Rules     []UFWRule
}

// UFWRule is one line of "ufw status numbered".
type UFWRule struct {
	No      int
	To      string // "22/tcp", "8000:9000/tcp", "OpenSSH", "Anywhere" (+ " (v6)")
	Action  string // "ALLOW IN", "DENY IN", "LIMIT IN"…
	From    string
	Comment string
	Line    string // raw line (its hash guards ufw-delete against a changed list)
	// Locked is the reason the panel won't delete it ("" = deletable).
	Locked string
}

var portSpecRe = regexp.MustCompile(`^[0-9,:]+$`)

var ufwLineRe = regexp.MustCompile(`^\[\s*([0-9]+)\]\s+(.+?)\s{2,}((?:ALLOW|DENY|REJECT|LIMIT)(?: (?:IN|OUT|FWD))?)\s+(.+?)(?:\s+#\s*(.*))?$`)

// ParseUFW parses the helper's output.
func ParseUFW(out string) UFWStatus {
	var st UFWStatus
	head, rules, _ := strings.Cut(out, "---\n")
	for _, l := range strings.Split(head, "\n") {
		k, v, _ := strings.Cut(strings.TrimSpace(l), "=")
		switch k {
		case "installed":
			st.Installed = v == "yes"
		case "active":
			st.Active = v == "yes"
		case "protected":
			for _, p := range strings.Split(v, ",") {
				if n, err := strconv.Atoi(p); err == nil {
					st.Protected = append(st.Protected, n)
				}
			}
		}
	}
	for _, l := range strings.Split(rules, "\n") {
		l = strings.TrimRight(l, " \r")
		m := ufwLineRe.FindStringSubmatch(l)
		if m == nil {
			continue
		}
		no, _ := strconv.Atoi(m[1])
		r := UFWRule{No: no, To: m[2], Action: m[3], From: strings.TrimSpace(m[4]), Comment: m[5], Line: l}
		r.Locked = lockReason(r, st.Protected)
		st.Rules = append(st.Rules, r)
	}
	return st
}

// lockReason mirrors hp-server.sh ufw-delete (the script decides; this only
// hides the button).
func lockReason(r UFWRule, protected []int) string {
	if strings.Contains(r.Comment, "hostpanel-mssql") {
		return "MSSQL kuralı (Veritabanları sayfası)"
	}
	spec, _, _ := strings.Cut(strings.TrimSuffix(r.To, " (v6)"), "/")
	if !portSpecRe.MatchString(spec) {
		return "profil / tüm portlar"
	}
	for _, p := range protected {
		if PortsOverlap(spec, p) {
			return "korumalı port " + strconv.Itoa(p)
		}
	}
	return ""
}

// PortsOverlap reports whether spec ("22", "8000:9000", "80,443") covers port p.
func PortsOverlap(spec string, p int) bool {
	for _, part := range strings.Split(spec, ",") {
		if a, b, ok := strings.Cut(part, ":"); ok {
			lo, e1 := strconv.Atoi(a)
			hi, e2 := strconv.Atoi(b)
			if e1 == nil && e2 == nil && p >= lo && p <= hi {
				return true
			}
		} else if n, err := strconv.Atoi(part); err == nil && n == p {
			return true
		}
	}
	return false
}

// RuleHash is the 16-hex prefix of sha256(line); hp-server.sh recomputes it.
func RuleHash(line string) string {
	h := sha256.Sum256([]byte(line))
	return hex.EncodeToString(h[:8])
}

var ufwPortRe = regexp.MustCompile(`^([0-9]{1,5})(?::([0-9]{1,5}))?$`)

// UFWRuleInput is the "add rule" form.
type UFWRuleInput struct {
	Action, Port, Proto, From string
}

// Validate mirrors hp-server.sh ufw-add; protected ports can't get a deny rule.
func (in *UFWRuleInput) Validate(protected []int) error {
	in.Port, in.From = strings.TrimSpace(in.Port), strings.TrimSpace(in.From)
	if in.From == "" {
		in.From = "any"
	}
	if in.Action != "allow" && in.Action != "deny" {
		return errors.New("geçersiz kural türü")
	}
	if in.Proto != "tcp" && in.Proto != "udp" && in.Proto != "any" {
		return errors.New("geçersiz protokol")
	}
	m := ufwPortRe.FindStringSubmatch(in.Port)
	if m == nil {
		return errors.New("geçersiz port (ör. 8080 veya 6000:6100)")
	}
	lo, _ := strconv.Atoi(m[1])
	hi := lo
	if m[2] != "" {
		hi, _ = strconv.Atoi(m[2])
		if hi <= lo {
			return errors.New("port aralığında ilk değer küçük olmalı")
		}
		if in.Proto == "any" {
			return errors.New("port aralığında protokol (tcp/udp) seçilmeli")
		}
	}
	if lo < 1 || hi > 65535 {
		return errors.New("port 1-65535 arasında olmalı")
	}
	if in.From != "any" {
		if err := ValidIPOrCIDR(in.From); err != nil {
			return err
		}
	}
	if in.Action == "deny" {
		for _, p := range protected {
			if PortsOverlap(in.Port, p) {
				return errors.New("korumalı port (" + strconv.Itoa(p) + ") için engelleme kuralı eklenemez")
			}
		}
	}
	return nil
}

// ValidIPOrCIDR accepts an IP or a CIDR prefix other than /0.
func ValidIPOrCIDR(s string) error {
	if strings.Contains(s, "/") {
		p, err := netip.ParsePrefix(s)
		if err != nil {
			return errors.New("geçersiz IP/CIDR: " + s)
		}
		if p.Bits() == 0 {
			return errors.New("/0 kabul edilmez (tüm adresler için \"her yer\" seçin)")
		}
		return nil
	}
	if _, err := netip.ParseAddr(s); err != nil {
		return errors.New("geçersiz IP adresi: " + s)
	}
	return nil
}

// Package dns manages the authoritative zones served by the local BIND 9:
// zone/record storage, validation, zone file rendering and the jobs that hand
// the rendered files to the root helper hp-dns.sh (which validates them again).
package dns

import (
	"errors"
	"fmt"
	"net/netip"
	"regexp"
	"strconv"
	"strings"
	"time"
)

// Record types the panel manages. SOA and the apex NS records are generated.
const (
	TypeA     = "A"
	TypeAAAA  = "AAAA"
	TypeCNAME = "CNAME"
	TypeMX    = "MX"
	TypeTXT   = "TXT"
	TypeSRV   = "SRV"
	TypeCAA   = "CAA"
	TypeNS    = "NS"
)

// Types is the order offered in the UI.
var Types = []string{TypeA, TypeAAAA, TypeCNAME, TypeMX, TypeTXT, TypeSRV, TypeCAA, TypeNS}

// CAATags are the CAA property tags accepted.
var CAATags = []string{"issue", "issuewild", "iodef"}

const (
	MinTTL    = 60
	MaxTTL    = 604800
	MaxTXT    = 2048
	maxCAAVal = 255
)

var (
	labelRe    = regexp.MustCompile(`^[a-z0-9_]([a-z0-9_-]{0,61}[a-z0-9_])?$`)
	hostnameRe = regexp.MustCompile(`^([a-z0-9_]([a-z0-9_-]{0,61}[a-z0-9])?\.)+[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$`)
	zoneNameRe = regexp.MustCompile(`^([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$`) // same as lib.sh validate_domain
)

// Zone is one authoritative zone.
type Zone struct {
	ID           int64
	Name         string
	CustomerID   int64 // 0 = none
	CustomerName string
	Serial       int64
	DefaultTTL   int
	Refresh      int
	Retry        int
	Expire       int
	Minimum      int
	DNSSEC       bool
	AutoSites    bool
	CreatedAt    time.Time
	UpdatedAt    time.Time
	RecordCount  int // filled by List
}

// Record is one resource record. Name is relative to the zone ("@" = apex).
type Record struct {
	ID     int64
	ZoneID int64
	Name   string
	Type   string
	TTL    int // 0 = zone default
	Prio   int // MX/SRV priority, CAA flag
	Weight int // SRV
	Port   int // SRV
	Tag    string
	Value  string

	// Auto records are derived from sites at render time (never stored).
	Auto   bool
	Source string // site domain for auto records
}

// ValidZoneName reports whether name is an acceptable zone (lower case, ≥ 2 labels).
func ValidZoneName(name string) bool {
	return len(name) <= 253 && zoneNameRe.MatchString(name)
}

// NormalizeZoneName lower-cases and trims a user-entered zone name.
func NormalizeZoneName(name string) (string, error) {
	n := strings.TrimSuffix(strings.ToLower(strings.TrimSpace(name)), ".")
	if !ValidZoneName(n) {
		return "", fmt.Errorf("geçersiz zone adı: %q (ör. ornek.com)", name)
	}
	return n, nil
}

// ValidHostname reports whether h is a fully qualified host name (no trailing dot).
func ValidHostname(h string) bool {
	return len(h) <= 253 && hostnameRe.MatchString(h)
}

// normalizeOwner turns a user-entered owner name into the stored relative
// form: "@" for the apex, otherwise labels relative to zone. A name entered
// fully qualified ("www.ornek.com" or "www.ornek.com.") is shortened.
func normalizeOwner(name, zone string) (string, error) {
	n := strings.ToLower(strings.TrimSpace(name))
	if n == "" || n == "@" || n == zone || n == zone+"." {
		return "@", nil
	}
	if strings.HasSuffix(n, ".") {
		if !strings.HasSuffix(n, "."+zone+".") {
			return "", fmt.Errorf("ad bu zone'da değil: %s", name)
		}
		n = strings.TrimSuffix(n, "."+zone+".")
	} else {
		n = strings.TrimSuffix(n, "."+zone)
	}
	labels := strings.Split(n, ".")
	for i, l := range labels {
		if l == "*" && i == 0 {
			continue
		}
		if !labelRe.MatchString(l) {
			return "", fmt.Errorf("geçersiz ad: %q (harf, rakam, - ve _; joker yalnızca en başta *)", name)
		}
	}
	if len(n)+1+len(zone) > 253 {
		return "", errors.New("ad çok uzun")
	}
	return n, nil
}

// normalizeTarget validates a host name value (CNAME/NS/MX/SRV). "@" means
// the zone apex. Returned without trailing dot.
func normalizeTarget(v, zone string) (string, error) {
	t := strings.TrimSuffix(strings.ToLower(strings.TrimSpace(v)), ".")
	if t == "@" {
		return zone, nil
	}
	if !ValidHostname(t) {
		return "", fmt.Errorf("geçersiz hedef ad: %q (tam ad girin, ör. mail.ornek.com)", v)
	}
	return t, nil
}

func printableASCII(s string) bool {
	for i := 0; i < len(s); i++ {
		if s[i] < 0x20 || s[i] > 0x7e {
			return false
		}
	}
	return true
}

// Normalize validates r for zone and normalizes its fields in place.
func (r *Record) Normalize(zone string) error {
	r.Type = strings.ToUpper(strings.TrimSpace(r.Type))
	name, err := normalizeOwner(r.Name, zone)
	if err != nil {
		return err
	}
	r.Name = name
	if r.TTL != 0 && (r.TTL < MinTTL || r.TTL > MaxTTL) {
		return fmt.Errorf("TTL %d–%d saniye olmalı (boş = zone varsayılanı)", MinTTL, MaxTTL)
	}
	r.Value = strings.TrimSpace(r.Value)
	if r.Type != TypeSRV {
		r.Weight, r.Port = 0, 0
	}
	if r.Type != TypeMX && r.Type != TypeSRV && r.Type != TypeCAA {
		r.Prio = 0
	}
	if r.Type != TypeCAA {
		r.Tag = ""
	}
	switch r.Type {
	case TypeA:
		a, err := netip.ParseAddr(r.Value)
		if err != nil || !a.Is4() {
			return fmt.Errorf("geçersiz IPv4 adresi: %q", r.Value)
		}
		r.Value = a.String()
	case TypeAAAA:
		a, err := netip.ParseAddr(r.Value)
		if err != nil || !a.Is6() || a.Is4In6() || a.Zone() != "" {
			return fmt.Errorf("geçersiz IPv6 adresi: %q", r.Value)
		}
		r.Value = a.String()
	case TypeCNAME:
		if r.Name == "@" {
			return errors.New("zone kökünde (@) CNAME olamaz; A kaydı kullanın")
		}
		if r.Value, err = normalizeTarget(r.Value, zone); err != nil {
			return err
		}
	case TypeNS:
		if r.Name == "@" {
			return errors.New("kök NS kayıtları DNS ayarlarındaki ns1/ns2'den otomatik üretilir")
		}
		if r.Value, err = normalizeTarget(r.Value, zone); err != nil {
			return err
		}
	case TypeMX:
		if r.Prio < 0 || r.Prio > 65535 {
			return errors.New("MX önceliği 0–65535 olmalı")
		}
		if r.Value, err = normalizeTarget(r.Value, zone); err != nil {
			return err
		}
	case TypeSRV:
		if r.Prio < 0 || r.Prio > 65535 || r.Weight < 0 || r.Weight > 65535 || r.Port < 0 || r.Port > 65535 {
			return errors.New("SRV öncelik/ağırlık/port 0–65535 olmalı")
		}
		if r.Value, err = normalizeTarget(r.Value, zone); err != nil {
			return err
		}
	case TypeTXT:
		if r.Value == "" || len(r.Value) > MaxTXT {
			return fmt.Errorf("TXT değeri 1–%d karakter olmalı", MaxTXT)
		}
		if !printableASCII(r.Value) {
			return errors.New("TXT değeri yalnızca yazdırılabilir ASCII karakter içerebilir")
		}
	case TypeCAA:
		if r.Prio != 0 && r.Prio != 128 {
			return errors.New("CAA bayrağı 0 ya da 128 olmalı")
		}
		r.Tag = strings.ToLower(strings.TrimSpace(r.Tag))
		ok := false
		for _, t := range CAATags {
			ok = ok || r.Tag == t
		}
		if !ok {
			return errors.New("CAA etiketi issue, issuewild ya da iodef olmalı")
		}
		if r.Value == "" || len(r.Value) > maxCAAVal || !printableASCII(r.Value) || strings.ContainsAny(r.Value, `"\`) {
			return errors.New(`CAA değeri 1–255 yazdırılabilir karakter olmalı (" ve \ olmadan), ör. letsencrypt.org`)
		}
	default:
		return fmt.Errorf("desteklenmeyen kayıt tipi: %q", r.Type)
	}
	return nil
}

// CheckConflicts rejects r when it clashes with the zone's other records:
// a CNAME cannot share its name with any other record, and exact duplicates
// are refused. others must not contain r itself.
func CheckConflicts(r Record, others []Record) error {
	for _, o := range others {
		if o.Name != r.Name {
			continue
		}
		if r.Type == TypeCNAME || o.Type == TypeCNAME {
			return fmt.Errorf("%s adında başka kayıt var; CNAME bir adın tek kaydı olmalı", displayName(r.Name))
		}
		if o.Type == r.Type && o.Value == r.Value && o.Prio == r.Prio && o.Weight == r.Weight && o.Port == r.Port && o.Tag == r.Tag {
			return errors.New("aynı kayıt zaten var")
		}
	}
	return nil
}

func displayName(n string) string {
	if n == "@" {
		return "@ (kök)"
	}
	return n
}

// FQDN returns the record's absolute owner name (no trailing dot).
func (r Record) FQDN(zone string) string {
	if r.Name == "@" {
		return zone
	}
	return r.Name + "." + zone
}

// Display renders the value column for the UI.
func (r Record) Display() string {
	switch r.Type {
	case TypeMX:
		return strconv.Itoa(r.Prio) + " " + r.Value
	case TypeSRV:
		return fmt.Sprintf("%d %d %d %s", r.Prio, r.Weight, r.Port, r.Value)
	case TypeCAA:
		return fmt.Sprintf("%d %s %q", r.Prio, r.Tag, r.Value)
	}
	return r.Value
}

// ZoneFor returns the zone among names that best covers host: the longest
// zone equal to host or a parent of it ("" when none).
func ZoneFor(host string, zones []string) string {
	best := ""
	for _, z := range zones {
		if (host == z || strings.HasSuffix(host, "."+z)) && len(z) > len(best) {
			best = z
		}
	}
	return best
}

// NextSerial returns the next YYYYMMDDnn serial after cur for day t.
func NextSerial(cur int64, t time.Time) int64 {
	day, _ := strconv.ParseInt(t.UTC().Format("20060102"), 10, 64)
	if base := day * 100; cur < base {
		return base
	}
	return cur + 1
}

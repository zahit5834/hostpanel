package dns

import (
	"errors"
	"fmt"
	"regexp"
	"strings"
)

// MaxZoneFile is the largest zone file the helper accepts.
const MaxZoneFile = 1 << 20

// The same rules live in deploy/scripts/lib.sh (validate_zone_file); both are
// tested against deploy/scripts/testdata_zone_bad.txt.
var (
	ttlLineRe = regexp.MustCompile(`^\$TTL [0-9]{2,6}$`)
	rrLineRe  = regexp.MustCompile(`^([a-z0-9_*.-]+)\. ([0-9]{1,6}) IN (SOA|NS|A|AAAA|CNAME|MX|TXT|SRV|CAA) (.+)$`)
	ownerRe   = regexp.MustCompile(`^(\*\.)?([a-z0-9_-]+\.)*[a-z0-9_-]+$`)

	host     = `[a-z0-9_-]+(\.[a-z0-9_-]+)*\.`
	txtChars = `([ !#-\[\]-~]|\\["\\])*`
	rdataRe  = map[string]*regexp.Regexp{
		"SOA":   regexp.MustCompile(`^` + host + ` ` + host + ` [0-9]{1,10}( [0-9]{1,10}){4}$`),
		"NS":    regexp.MustCompile(`^` + host + `$`),
		"CNAME": regexp.MustCompile(`^` + host + `$`),
		"A":     regexp.MustCompile(`^((25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])\.){3}(25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])$`),
		"AAAA":  regexp.MustCompile(`^[0-9a-f:.]{2,45}$`),
		"MX":    regexp.MustCompile(`^[0-9]{1,5} ` + host + `$`),
		"SRV":   regexp.MustCompile(`^[0-9]{1,5} [0-9]{1,5} [0-9]{1,5} ` + host + `$`),
		"TXT":   regexp.MustCompile(`^"` + txtChars + `"( "` + txtChars + `")*$`),
		"CAA":   regexp.MustCompile(`^(0|128) (issue|issuewild|iodef) "[ !#-\[\]-~]{1,255}"$`),
	}
)

// ValidateZoneFile checks a rendered zone file line by line. Only "$TTL" is
// allowed as a directive ($INCLUDE would make named read other files,
// $GENERATE/$ORIGIN change how later lines are read), every record is one
// line with an absolute owner inside zone, and each type's data must match a
// strict pattern. named-checkzone runs afterwards for the semantic checks.
func ValidateZoneFile(content, zone string) error {
	if len(content) > MaxZoneFile {
		return errors.New("zone dosyası çok büyük")
	}
	if !strings.HasSuffix(content, "\n") {
		return errors.New("zone dosyası satır sonuyla bitmeli")
	}
	for i := 0; i < len(content); i++ {
		if c := content[i]; c != '\n' && (c < 0x20 || c > 0x7e) {
			return fmt.Errorf("geçersiz karakter (0x%02x)", c)
		}
	}
	lines := strings.Split(strings.TrimSuffix(content, "\n"), "\n")
	if len(lines) < 2 || !ttlLineRe.MatchString(lines[0]) {
		return errors.New("ilk satır $TTL olmalı")
	}
	soa := 0
	for n, line := range lines[1:] {
		m := rrLineRe.FindStringSubmatch(line)
		if m == nil {
			return fmt.Errorf("satır %d: geçersiz kayıt: %q", n+2, line)
		}
		owner, typ, data := m[1], m[3], m[4]
		if owner != zone && !strings.HasSuffix(owner, "."+zone) || !ownerRe.MatchString(owner) {
			return fmt.Errorf("satır %d: ad zone dışında: %q", n+2, owner)
		}
		if !rdataRe[typ].MatchString(data) {
			return fmt.Errorf("satır %d: geçersiz %s verisi: %q", n+2, typ, data)
		}
		if typ == "SOA" {
			if n != 0 || owner != zone {
				return fmt.Errorf("satır %d: SOA yalnızca ikinci satırda ve zone kökünde olabilir", n+2)
			}
			soa++
		}
	}
	if soa != 1 {
		return errors.New("zone dosyasında tam bir SOA kaydı olmalı")
	}
	return nil
}

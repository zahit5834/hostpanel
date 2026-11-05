// Package databases manages the MSSQL container, per-customer SQL logins and
// their databases.
package databases

import (
	"crypto/rand"
	"errors"
	"math/big"
	"regexp"
	"strings"
)

// Names are used inside T-SQL identifiers (always through QUOTENAME) and in
// helper script arguments, so they are restricted to a conservative set.
var nameRe = regexp.MustCompile(`^[a-z][a-z0-9_]{1,62}$`)

// reserved names can never be created or dropped through the panel.
var reserved = map[string]bool{
	"master": true, "model": true, "msdb": true, "tempdb": true, "sa": true,
	"public": true, "guest": true, "sys": true, "dbo": true,
}

// IsolationPrefix is used by the isolation test for its temporary logins/DBs.
const IsolationPrefix = "hpiso_"

// ValidName reports whether s can be used as a login or database name.
func ValidName(s string) bool {
	return nameRe.MatchString(s) && !reserved[s] && !strings.HasPrefix(s, IsolationPrefix) && !strings.HasPrefix(s, "sys")
}

// ErrName is the user-facing error for invalid names.
var ErrName = errors.New("ad küçük harfle başlamalı; yalnızca küçük harf, rakam ve _ içerebilir (2–63 karakter); sistem adları kullanılamaz")

var trASCII = strings.NewReplacer("ç", "c", "Ç", "c", "ğ", "g", "Ğ", "g", "ı", "i", "I", "i", "İ", "i",
	"ö", "o", "Ö", "o", "ş", "s", "Ş", "s", "ü", "u", "Ü", "u")

// Slug turns free text (customer name, domain) into a name fragment: Turkish
// letters to ASCII, everything else non-alphanumeric to "_".
func Slug(s string, max int) string {
	s = strings.ToLower(trASCII.Replace(s))
	var b strings.Builder
	us := false
	for _, r := range s {
		switch {
		case r >= 'a' && r <= 'z' || r >= '0' && r <= '9':
			b.WriteRune(r)
			us = false
		case !us && b.Len() > 0:
			b.WriteByte('_')
			us = true
		}
	}
	out := strings.Trim(b.String(), "_")
	if len(out) > max {
		out = strings.TrimRight(out[:max], "_")
	}
	return out
}

// LoginBase is the preferred login name for a customer: c_<slug>.
func LoginBase(customerName string) string {
	s := Slug(customerName, 40)
	if s == "" {
		s = "musteri"
	}
	return "c_" + s
}

// DBBase suggests a database name from a site's short name or a free text.
func DBBase(s string) string {
	out := Slug(s, 50)
	if out == "" || out[0] < 'a' || out[0] > 'z' {
		out = "db_" + out
	}
	out = strings.TrimRight(out, "_")
	if !ValidName(out) {
		out = "db_" + out
	}
	return out
}

const (
	pwLower  = "abcdefghijkmnopqrstuvwxyz"
	pwUpper  = "ABCDEFGHJKLMNPQRSTUVWXYZ"
	pwDigits = "23456789"
	pwLen    = 24
)

// GeneratePassword returns a 24-character password from [A-Za-z0-9] (minus
// look-alikes) with at least one of each class: it satisfies the SQL Server
// password policy and needs no escaping in connection strings or URLs.
// ~138 bits of entropy.
func GeneratePassword() string {
	all := pwLower + pwUpper + pwDigits
	for {
		b := make([]byte, pwLen)
		for i := range b {
			b[i] = all[randInt(len(all))]
		}
		s := string(b)
		if strings.ContainsAny(s, pwLower) && strings.ContainsAny(s, pwUpper) && strings.ContainsAny(s, pwDigits) {
			return s
		}
	}
}

func randInt(n int) int {
	v, err := rand.Int(rand.Reader, big.NewInt(int64(n)))
	if err != nil {
		panic(err) // crypto/rand never fails on Linux
	}
	return int(v.Int64())
}

var pwRe = regexp.MustCompile(`^[A-Za-z0-9]{16,64}$`)

// ValidPassword checks passwords produced by GeneratePassword (and accepted by hp-mssql.sh).
func ValidPassword(s string) bool { return pwRe.MatchString(s) }

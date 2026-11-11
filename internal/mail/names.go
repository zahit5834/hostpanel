// Package mail manages the e-mail server (docker-mailserver): the container,
// mail domains, mailboxes, aliases, DKIM/DNS records, queue and bans. The
// panel never talks to the mail server itself and stores no mailbox
// passwords: everything is a whitelisted hp-mail.sh subcommand, and the
// accounts live only in the container's config files (root).
package mail

import (
	"errors"
	"regexp"
	"strings"

	"github.com/zahit5834/hostpanel/internal/sites"
)

const (
	// DefaultImage is pinned: an immutable release tag of docker-mailserver.
	DefaultImage  = "mailserver/docker-mailserver:17.0.0-r1"
	ContainerName = "hostpanel-mail"
	DataDir       = "/var/lib/hostpanel-mail"
	// BackupDomain is the folder (and backups.domain value) of mail backups.
	BackupDomain = "_mail"
	DKIMSelector = "mail"

	// Memory: ~350 MiB idle without ClamAV, ~1.2 GiB with it (measured, v17).
	DefaultMemoryMB   = 1024
	MinMemoryMB       = 768
	ClamAVMinMemoryMB = 2560
	MaxMemoryMB       = 65536

	DefaultMsgLimitMB = 25
	MaxMsgLimitMB     = 200
	MaxQuotaMB        = 1024 * 1024

	MinPassword = 10
	MaxPassword = 128
)

var (
	imageRe = regexp.MustCompile(`^mailserver/docker-mailserver:1[7-9]\.[0-9]{1,2}\.[0-9]{1,2}(-r[0-9]{1,2})?$`)
	// localRe is the local part of mailboxes and aliases the panel creates
	// (at most 64 bytes, checked separately: counted repetitions stay on the
	// heap as one instruction per repeat — RAM budget).
	localRe = regexp.MustCompile(`^[a-z0-9][a-z0-9._-]*$`)
	// targetLocalRe is the local part of a forwarding target (may be external).
	targetLocalRe = regexp.MustCompile(`^[a-z0-9][a-z0-9._+-]*$`)
)

const maxLocal = 64

// ValidImage mirrors lib.sh validate_mail_image.
func ValidImage(s string) bool { return imageRe.MatchString(s) }

// ValidLocal reports whether s can be the local part of a mailbox or alias.
func ValidLocal(s string) bool {
	return len(s) <= maxLocal && localRe.MatchString(s) && !strings.Contains(s, "..") && !strings.HasSuffix(s, ".")
}

// SplitAddress splits local@domain (already lowercased).
func SplitAddress(a string) (local, domain string, ok bool) {
	local, domain, ok = strings.Cut(a, "@")
	return local, domain, ok && !strings.Contains(domain, "@")
}

// ValidAddress mirrors lib.sh validate_mail_addr: a mailbox or alias address.
func ValidAddress(a string) bool {
	local, domain, ok := SplitAddress(a)
	return ok && ValidLocal(local) && sites.ValidDomain(domain) && len(a) <= 254
}

// ValidTarget mirrors lib.sh validate_mail_target: where an alias forwards to.
func ValidTarget(a string) bool {
	local, domain, ok := SplitAddress(a)
	return ok && len(local) <= maxLocal && targetLocalRe.MatchString(local) && !strings.Contains(local, "..") && !strings.HasSuffix(local, ".") &&
		sites.ValidDomain(domain) && len(a) <= 254
}

// NormalizeAddress lowercases and trims user input.
func NormalizeAddress(a string) string { return strings.ToLower(strings.TrimSpace(a)) }

// ErrLocal is the user-facing error for an invalid local part.
var ErrLocal = errors.New("adres küçük harf ya da rakamla başlamalı; yalnızca küçük harf, rakam, nokta, tire ve alt çizgi içerebilir (en fazla 64 karakter)")

// CheckPassword validates a password typed by the admin: printable ASCII
// without spaces, so it survives every mail client and one stdin line.
func CheckPassword(pw string) error {
	if len(pw) < MinPassword || len(pw) > MaxPassword {
		return errors.New("şifre 10–128 karakter olmalı")
	}
	for i := 0; i < len(pw); i++ {
		if pw[i] < 0x21 || pw[i] > 0x7e {
			return errors.New("şifre yalnızca boşluksuz ASCII karakterler içerebilir (harf, rakam, noktalama)")
		}
	}
	return nil
}

// DomainOf returns the domain part of an address ("" if malformed).
func DomainOf(a string) string {
	_, d, ok := SplitAddress(a)
	if !ok {
		return ""
	}
	return d
}

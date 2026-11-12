package mail

import (
	"context"
	"io"
	"net/netip"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/zahit5834/hostpanel/internal/databases"
	"github.com/zahit5834/hostpanel/internal/exec"
	"github.com/zahit5834/hostpanel/internal/sites"
)

// Mailbox is one account of the mail server.
type Mailbox struct {
	Address  string
	QuotaMB  int   // 0 = unlimited
	UsedKiB  int64 // valid when HasUsage
	HasUsage bool
	// Suspended: no IMAP/SMTP login, mail still arrives. SendBlocked: its
	// submissions are refused, IMAP and incoming mail work.
	Suspended   bool
	SendBlocked bool
}

// UsedMB is the used space rounded up to whole MB.
func (m Mailbox) UsedMB() int64 { return (m.UsedKiB + 1023) / 1024 }

// UsedPct is the used share of the quota (0 when unlimited).
func (m Mailbox) UsedPct() int {
	if m.QuotaMB <= 0 || !m.HasUsage {
		return 0
	}
	return int(min(100, m.UsedKiB*100/(int64(m.QuotaMB)*1024)))
}

// Alias forwards one address to one or more targets.
type Alias struct {
	Address string
	Targets []string
}

// Listing is the content of the server's account and alias files.
type Listing struct {
	Mailboxes []Mailbox
	Aliases   []Alias
	CatchAll  map[string]string // domain → mailbox receiving unknown addresses
}

// ForDomain returns the mailboxes and aliases of one domain.
func (l Listing) ForDomain(domain string) Listing {
	var out Listing
	for _, m := range l.Mailboxes {
		if DomainOf(m.Address) == domain {
			out.Mailboxes = append(out.Mailboxes, m)
		}
	}
	for _, a := range l.Aliases {
		if DomainOf(a.Address) == domain {
			out.Aliases = append(out.Aliases, a)
		}
	}
	if t, ok := l.CatchAll[domain]; ok {
		out.CatchAll = map[string]string{domain: t}
	}
	return out
}

// Mailbox returns the mailbox with that address.
func (l Listing) Mailbox(addr string) (Mailbox, bool) {
	for _, m := range l.Mailboxes {
		if m.Address == addr {
			return m, true
		}
	}
	return Mailbox{}, false
}

// HasMailbox reports whether addr is an account.
func (l Listing) HasMailbox(addr string) bool {
	for _, m := range l.Mailboxes {
		if m.Address == addr {
			return true
		}
	}
	return false
}

// Alias returns the alias with that address.
func (l Listing) Alias(addr string) (Alias, bool) {
	for _, a := range l.Aliases {
		if a.Address == addr {
			return a, true
		}
	}
	return Alias{}, false
}

// Domains returns every domain that has a mailbox or an alias, sorted.
func (l Listing) Domains() []string {
	seen := map[string]bool{}
	for _, m := range l.Mailboxes {
		seen[DomainOf(m.Address)] = true
	}
	for _, a := range l.Aliases {
		seen[DomainOf(a.Address)] = true
	}
	delete(seen, "")
	out := make([]string, 0, len(seen))
	for d := range seen {
		out = append(out, d)
	}
	sort.Strings(out)
	return out
}

// Ban is one address blocked by the container's Fail2ban.
type Ban struct {
	Jail string
	IP   string
}

// Status is the container state plus the mail specific bits.
type Status struct {
	databases.Status
	Health    string    // healthy | starting | unhealthy | ""
	CertUntil time.Time // zero = unknown
}

// CertDays is the number of whole days until the TLS certificate expires.
func (st Status) CertDays() int { return int(time.Until(st.CertUntil).Hours() / 24) }

// ParseStatus parses `hp-mail.sh status`.
func ParseStatus(out string) Status {
	st := Status{Status: databases.ParseStatus(out)}
	for _, line := range strings.Split(out, "\n") {
		k, v, ok := strings.Cut(strings.TrimSpace(line), "=")
		if !ok {
			continue
		}
		switch k {
		case "health":
			st.Health = v
		case "cert_until":
			if n, err := strconv.ParseInt(v, 10, 64); err == nil && n > 0 {
				st.CertUntil = time.Unix(n, 0)
			}
		}
	}
	return st
}

// ParseList parses `hp-mail.sh list`: "account <addr> <quota_mb> [flags]"
// (flags: suspended,blocked or -), "alias <addr> <target,target>" and
// "catchall <domain> <mailbox>" lines. Malformed lines are skipped.
func ParseList(out string) Listing {
	var l Listing
	for _, line := range strings.Split(out, "\n") {
		f := strings.Fields(line)
		if len(f) < 3 {
			continue
		}
		switch {
		case f[0] == "account" && len(f) <= 4:
			q, err := strconv.Atoi(f[2])
			if err != nil || q < 0 || !ValidAddress(f[1]) {
				continue
			}
			m := Mailbox{Address: f[1], QuotaMB: q}
			if len(f) == 4 {
				for _, fl := range strings.Split(f[3], ",") {
					switch fl {
					case "suspended":
						m.Suspended = true
					case "blocked":
						m.SendBlocked = true
					}
				}
			}
			l.Mailboxes = append(l.Mailboxes, m)
		case f[0] == "alias" && len(f) == 3:
			if !ValidAddress(f[1]) {
				continue
			}
			a := Alias{Address: f[1]}
			for _, t := range strings.Split(f[2], ",") {
				if ValidTarget(t) {
					a.Targets = append(a.Targets, t)
				}
			}
			if len(a.Targets) > 0 {
				l.Aliases = append(l.Aliases, a)
			}
		case f[0] == "catchall" && len(f) == 3:
			if sites.ValidDomain(f[1]) && ValidAddress(f[2]) {
				if l.CatchAll == nil {
					l.CatchAll = map[string]string{}
				}
				l.CatchAll[f[1]] = f[2]
			}
		}
	}
	sort.Slice(l.Mailboxes, func(i, j int) bool { return l.Mailboxes[i].Address < l.Mailboxes[j].Address })
	sort.Slice(l.Aliases, func(i, j int) bool { return l.Aliases[i].Address < l.Aliases[j].Address })
	return l
}

// ParseUsage parses `hp-mail.sh usage`: "<addr> <used_kib> <limit_kib|->".
func ParseUsage(out string) map[string]int64 {
	m := map[string]int64{}
	for _, line := range strings.Split(out, "\n") {
		f := strings.Fields(line)
		if len(f) != 3 {
			continue
		}
		if n, err := strconv.ParseInt(f[1], 10, 64); err == nil && n >= 0 {
			m[f[0]] = n
		}
	}
	return m
}

// dkimRe: the key length (100–1002 bytes) is checked separately — a counted
// repetition would keep ~90 KB of compiled program on the heap.
var dkimRe = regexp.MustCompile(`^v=DKIM1; k=rsa; p=[A-Za-z0-9+/]+={0,2}$`)

const dkimPrefix = "v=DKIM1; k=rsa; p="

// ParseDKIM returns the record from the "txt=" line of `hp-mail.sh dkim`
// ("" unless it is a well-formed RSA key record).
func ParseDKIM(out string) string {
	txt := ""
	for _, line := range strings.Split(out, "\n") {
		if v, ok := strings.CutPrefix(strings.TrimSpace(line), "txt="); ok {
			txt = v
		}
	}
	if n := len(txt) - len(dkimPrefix); n < 100 || n > 1002 || !dkimRe.MatchString(txt) {
		return ""
	}
	return txt
}

// parseKV returns the value of the last "key=" line.
func parseKV(out, key string) string {
	val := ""
	for _, line := range strings.Split(out, "\n") {
		if v, ok := strings.CutPrefix(strings.TrimSpace(line), key+"="); ok {
			val = v
		}
	}
	return val
}

// ParseQueue parses `hp-mail.sh queue` ("count=N").
func ParseQueue(out string) int {
	n, _ := strconv.Atoi(parseKV(out, "count"))
	return max(n, 0)
}

var jailRe = regexp.MustCompile(`^[a-z][a-z0-9-]{0,30}$`)

// ParseBans parses `hp-mail.sh bans` ("<jail> <ip>" lines).
func ParseBans(out string) []Ban {
	var bans []Ban
	for _, line := range strings.Split(out, "\n") {
		f := strings.Fields(line)
		if len(f) != 2 || !jailRe.MatchString(f[0]) {
			continue
		}
		if _, err := netip.ParseAddr(f[1]); err != nil {
			continue
		}
		bans = append(bans, Ban{Jail: f[0], IP: f[1]})
	}
	return bans
}

func (s *Service) helper(ctx context.Context, w io.Writer, stdin io.Reader, secrets []string, timeout time.Duration, args ...string) (exec.Result, error) {
	c := exec.Helper(s.ScriptsDir, "hp-mail.sh", args...)
	c.Output, c.Stdin, c.Secrets, c.Timeout = w, stdin, secrets, timeout
	return s.Runner.Run(ctx, c)
}

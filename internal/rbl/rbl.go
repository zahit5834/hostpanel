// Package rbl checks the server's mail IPs and names against DNS blocklists.
//
// Queries are plain DNS A lookups through the system resolver. Spamhaus
// refuses queries that arrive through public resolvers (answering
// 127.255.255.254 instead of data); with a free Data Query Service key the
// same zones are asked under <key>.<zone>.dq.spamhaus.net.
package rbl

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"regexp"
	"slices"
	"strings"
	"sync"
	"time"
)

// Kinds of list.
const (
	KindIP     = "ip"
	KindDomain = "domain"
)

// List is one blocklist zone.
type List struct {
	ID      string
	Name    string
	Zone    string // public zone
	DQSZone string // zone under <key>. with a DQS key ("" = none)
	Kind    string
	Delist  string // where to look up / request removal
	Note    string
}

// Lists are the zones checked (names and codes verified against the
// operators' documentation, 2026-11).
var Lists = []List{
	{ID: "zen", Name: "Spamhaus ZEN", Zone: "zen.spamhaus.org", DQSZone: "zen.dq.spamhaus.net", Kind: KindIP,
		Delist: "https://check.spamhaus.org/"},
	{ID: "spamcop", Name: "SpamCop", Zone: "bl.spamcop.net", Kind: KindIP, Delist: "https://www.spamcop.net/bl.shtml"},
	{ID: "barracuda", Name: "Barracuda", Zone: "b.barracudacentral.org", Kind: KindIP, Delist: "https://www.barracudacentral.org/lookups",
		Note: "Barracuda yalnızca kayıtlı çözümleyicilere yanıt verir; kayıtsızken “temiz” sonucu güvenilir değildir."},
	{ID: "psbl", Name: "PSBL", Zone: "psbl.surriel.com", Kind: KindIP, Delist: "https://psbl.org/"},
	{ID: "mailspike", Name: "Mailspike", Zone: "bl.mailspike.net", Kind: KindIP, Delist: "https://mailspike.org/iplookup.html"},
	{ID: "dbl", Name: "Spamhaus DBL", Zone: "dbl.spamhaus.org", DQSZone: "dbl.dq.spamhaus.net", Kind: KindDomain,
		Delist: "https://check.spamhaus.org/"},
}

// Statuses of a result.
const (
	StatusListed  = "listed"
	StatusClean   = "clean"
	StatusRefused = "refused" // the operator refused the query (public resolver, rate)
	StatusError   = "error"
)

// Result is one target on one list.
type Result struct {
	List   string   `json:"list"`
	Target string   `json:"target"`
	Status string   `json:"status"`
	Codes  []string `json:"codes,omitempty"`
	Detail string   `json:"detail,omitempty"`
}

// Resolver is the subset of *net.Resolver used (fakeable).
type Resolver interface {
	LookupHost(ctx context.Context, host string) ([]string, error)
}

var dqsKeyRe = regexp.MustCompile(`^[a-z0-9]+$`)

// ValidDQSKey reports whether k looks like a Spamhaus DQS key (26
// characters, lowercase letters and digits).
func ValidDQSKey(k string) bool { return len(k) == 26 && dqsKeyRe.MatchString(k) }

// ByID returns the list with that id.
func ByID(id string) (List, bool) {
	for _, l := range Lists {
		if l.ID == id {
			return l, true
		}
	}
	return List{}, false
}

// QueryName is the DNS name asked for target on list l ("" if the target
// does not fit the list).
func QueryName(l List, target, key string) string {
	zone := l.Zone
	if key != "" && l.DQSZone != "" {
		zone = key + "." + l.DQSZone
	}
	if l.Kind == KindDomain {
		if _, err := netip.ParseAddr(target); err == nil || target == "" {
			return "" // the DBL must never be asked for addresses
		}
		return strings.TrimSuffix(target, ".") + "." + zone
	}
	a, err := netip.ParseAddr(target)
	if err != nil || !a.Is4() {
		return ""
	}
	b := a.As4()
	return fmt.Sprintf("%d.%d.%d.%d.%s", b[3], b[2], b[1], b[0], zone)
}

// Classify turns an answer into a status. Every list answers 127.0.0.0/8
// when listed; Spamhaus uses 127.255.255.x for refused queries and the DBL
// 127.0.1.255 for an address asked as a domain.
func Classify(l List, addrs []string, err error) (string, []string, string) {
	if err != nil {
		var de *net.DNSError
		if errors.As(err, &de) && de.IsNotFound {
			return StatusClean, nil, ""
		}
		return StatusError, nil, shortErr(err)
	}
	var codes []string
	refused := false
	for _, s := range addrs {
		a, perr := netip.ParseAddr(s)
		if perr != nil || !a.Is4() {
			continue
		}
		b := a.As4()
		if b[0] != 127 {
			continue
		}
		if b[1] == 255 && b[2] == 255 || l.Kind == KindDomain && b[3] == 255 {
			refused = true
			continue
		}
		codes = append(codes, a.String())
	}
	slices.Sort(codes)
	switch {
	case len(codes) > 0:
		return StatusListed, codes, ""
	case refused:
		return StatusRefused, nil, refusedText(l, addrs)
	case len(addrs) > 0:
		return StatusError, nil, "beklenmeyen yanıt: " + strings.Join(addrs, ", ")
	}
	return StatusClean, nil, ""
}

func refusedText(l List, addrs []string) string {
	if strings.HasPrefix(l.ID, "zen") || l.ID == "dbl" {
		for _, a := range addrs {
			switch a {
			case "127.255.255.254":
				return "Spamhaus genel/açık çözümleyiciden gelen sorguyu reddetti: ücretsiz DQS anahtarı girin"
			case "127.255.255.255":
				return "Spamhaus çok fazla sorgu nedeniyle reddetti: DQS anahtarı girin"
			case "127.255.255.252":
				return "liste adı hatalı"
			}
		}
	}
	return "sorgu reddedildi"
}

func shortErr(err error) string {
	var de *net.DNSError
	if errors.As(err, &de) {
		if de.IsTimeout {
			return "zaman aşımı"
		}
		return de.Err
	}
	return err.Error()
}

// Check asks every list for every fitting target (IPv4 addresses on the IP
// lists, names on the domain lists), a few lookups at a time.
func Check(ctx context.Context, r Resolver, key string, ips []netip.Addr, names []string) []Result {
	type job struct {
		l      List
		target string
		q      string
	}
	var jobs []job
	for _, l := range Lists {
		var targets []string
		if l.Kind == KindIP {
			for _, a := range ips {
				if a.Is4() {
					targets = append(targets, a.String())
				}
			}
		} else {
			targets = names
		}
		for _, t := range targets {
			if q := QueryName(l, t, key); q != "" {
				jobs = append(jobs, job{l, t, q})
			}
		}
	}
	out := make([]Result, len(jobs))
	sem := make(chan struct{}, 4)
	var wg sync.WaitGroup
	for i, j := range jobs {
		wg.Add(1)
		sem <- struct{}{}
		go func() {
			defer func() { <-sem; wg.Done() }()
			qctx, cancel := context.WithTimeout(ctx, 8*time.Second)
			defer cancel()
			addrs, err := r.LookupHost(qctx, j.q)
			st, codes, detail := Classify(j.l, addrs, err)
			out[i] = Result{List: j.l.ID, Target: j.target, Status: st, Codes: codes, Detail: detail}
		}()
	}
	wg.Wait()
	return out
}

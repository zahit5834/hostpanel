package mail

import (
	"crypto/sha256"
	"encoding/base64"
	"sort"
	"sync"
)

// Fake is the in-memory stand-in for the server's account files in dry-run
// (development): hp-mail.sh is only logged there, so listings come from here.
// The state is lost when the panel restarts.
type Fake struct {
	mu       sync.Mutex
	accounts map[string]int // address → quota MB
	aliases  map[string][]string
	bans     []Ban
	queue    int
	// Faz 13: suspended / send-blocked mailboxes, catch-all per domain and
	// submissions per mailbox (tests set sent).
	suspended map[string]bool
	blocked   map[string]bool
	catchAll  map[string]string
	sent      map[string]int
}

// NewFake returns an empty fake server.
func NewFake() *Fake {
	return &Fake{accounts: map[string]int{}, aliases: map[string][]string{},
		suspended: map[string]bool{}, blocked: map[string]bool{}, catchAll: map[string]string{}, sent: map[string]int{}}
}

func (f *Fake) setFlag(addr string, suspend, on bool) {
	f.mu.Lock()
	defer f.mu.Unlock()
	m := f.blocked
	if suspend {
		m = f.suspended
	}
	if on {
		m[addr] = true
	} else {
		delete(m, addr)
	}
}

func (f *Fake) setCatchAll(domain, target string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if target == "" {
		delete(f.catchAll, domain)
	} else {
		f.catchAll[domain] = target
	}
}

// SetSent sets the submissions reported for a mailbox (tests).
func (f *Fake) SetSent(addr string, n int) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.sent[addr] = n
}

// SetQueue sets the reported queue length (tests).
func (f *Fake) SetQueue(n int) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.queue = n
}

func (f *Fake) sentStats() []Sender {
	f.mu.Lock()
	defer f.mu.Unlock()
	var ss []Sender
	for a, n := range f.sent {
		ss = append(ss, Sender{Address: a, Count: n})
	}
	sort.Slice(ss, func(i, j int) bool {
		if ss[i].Count != ss[j].Count {
			return ss[i].Count > ss[j].Count
		}
		return ss[i].Address < ss[j].Address
	})
	return ss
}

func (f *Fake) listing() Listing {
	f.mu.Lock()
	defer f.mu.Unlock()
	var l Listing
	for a, q := range f.accounts {
		l.Mailboxes = append(l.Mailboxes, Mailbox{Address: a, QuotaMB: q, HasUsage: true, Suspended: f.suspended[a], SendBlocked: f.blocked[a]})
	}
	for d, t := range f.catchAll {
		if l.CatchAll == nil {
			l.CatchAll = map[string]string{}
		}
		l.CatchAll[d] = t
	}
	for a, t := range f.aliases {
		l.Aliases = append(l.Aliases, Alias{Address: a, Targets: append([]string(nil), t...)})
	}
	sort.Slice(l.Mailboxes, func(i, j int) bool { return l.Mailboxes[i].Address < l.Mailboxes[j].Address })
	sort.Slice(l.Aliases, func(i, j int) bool { return l.Aliases[i].Address < l.Aliases[j].Address })
	return l
}

func (f *Fake) empty() bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.accounts) == 0
}

func (f *Fake) setAccount(addr string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if _, ok := f.accounts[addr]; !ok {
		f.accounts[addr] = 0
	}
}

func (f *Fake) setQuota(addr string, mb int) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if _, ok := f.accounts[addr]; ok {
		f.accounts[addr] = mb
	}
}

// delAccount mirrors hp-mail.sh account-del: the account, its quota and
// every alias target pointing at it go away.
func (f *Fake) delAccount(addr string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	delete(f.accounts, addr)
	delete(f.suspended, addr)
	delete(f.blocked, addr)
	for d, t := range f.catchAll {
		if t == addr {
			delete(f.catchAll, d)
		}
	}
	for a, targets := range f.aliases {
		kept := targets[:0]
		for _, t := range targets {
			if t != addr {
				kept = append(kept, t)
			}
		}
		if len(kept) == 0 {
			delete(f.aliases, a)
		} else {
			f.aliases[a] = kept
		}
	}
}

func (f *Fake) addAlias(alias, target string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	for _, t := range f.aliases[alias] {
		if t == target {
			return
		}
	}
	f.aliases[alias] = append(f.aliases[alias], target)
}

func (f *Fake) delAlias(alias, target string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	kept := f.aliases[alias][:0]
	for _, t := range f.aliases[alias] {
		if t != target {
			kept = append(kept, t)
		}
	}
	if len(kept) == 0 {
		delete(f.aliases, alias)
	} else {
		f.aliases[alias] = kept
	}
}

func (f *Fake) reset() {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.accounts, f.aliases, f.bans, f.queue = map[string]int{}, map[string][]string{}, nil, 0
	f.suspended, f.blocked, f.catchAll, f.sent = map[string]bool{}, map[string]bool{}, map[string]string{}, map[string]int{}
}

// fakeDKIM is a deterministic record of realistic length (RSA 2048: 392
// base64 characters), so the DNS code is exercised with a long TXT.
func fakeDKIM(domain string) string {
	raw := make([]byte, 0, 294+sha256.Size)
	sum := sha256.Sum256([]byte("hostpanel-dry-run-dkim:" + domain))
	for len(raw) < 294 {
		raw = append(raw, sum[:]...)
		sum = sha256.Sum256(sum[:])
	}
	return "v=DKIM1; k=rsa; p=" + base64.StdEncoding.EncodeToString(raw[:294])
}

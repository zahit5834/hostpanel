package dns

import (
	"errors"
	"fmt"
	"net/netip"
	"regexp"
	"sort"
	"strconv"
	"strings"
)

// Settings are the server-wide DNS settings.
type Settings struct {
	NS1, NS2   string // FQDN of the nameservers (no trailing dot)
	Hostmaster string // SOA contact e-mail
	IPs        []netip.Addr
}

var hostmasterRe = regexp.MustCompile(`^[a-z0-9_-]{1,64}@`)

// Validate checks the settings (Turkish errors).
func (s *Settings) Validate() error {
	s.NS1 = strings.TrimSuffix(strings.ToLower(strings.TrimSpace(s.NS1)), ".")
	s.NS2 = strings.TrimSuffix(strings.ToLower(strings.TrimSpace(s.NS2)), ".")
	s.Hostmaster = strings.ToLower(strings.TrimSpace(s.Hostmaster))
	if !ValidHostname(s.NS1) || !ValidHostname(s.NS2) {
		return errors.New("ns1 ve ns2 tam ad olmalı (ör. ns1.alanadiniz.com)")
	}
	if s.NS1 == s.NS2 {
		return errors.New("ns1 ve ns2 farklı adlar olmalı")
	}
	at := strings.IndexByte(s.Hostmaster, '@')
	if at < 0 || !hostmasterRe.MatchString(s.Hostmaster) || !ValidHostname(s.Hostmaster[at+1:]) {
		return errors.New("geçersiz yönetici e-postası (yerel kısımda yalnızca harf, rakam, - ve _; nokta olamaz)")
	}
	if len(s.IPs) == 0 {
		return errors.New("en az bir sunucu IP'si gerekli")
	}
	for _, ip := range s.IPs {
		if !ip.IsGlobalUnicast() || ip.IsPrivate() {
			return fmt.Errorf("%s genel bir IP değil; zone'lara yazılacak IP'ler internetten erişilebilir olmalı", ip)
		}
	}
	return nil
}

// Ready reports whether zones can be rendered.
func (s Settings) Ready() bool {
	return s.NS1 != "" && s.NS2 != "" && s.Hostmaster != "" && len(s.IPs) > 0
}

// rname turns hostmaster@ornek.com into hostmaster.ornek.com (SOA RNAME).
func (s Settings) rname() string { return strings.Replace(s.Hostmaster, "@", ".", 1) }

// SiteNames is the set of host names one site answers to.
type SiteNames struct {
	Domain string
	Names  []string // domain, www (when used) and aliases
}

// MailDomain is a mail domain served by the panel's mail server.
type MailDomain struct {
	Name         string
	DKIMSelector string
	DKIMTXT      string // "" until the key exists
}

// RenderInput is everything a zone file is built from.
type RenderInput struct {
	Zone     Zone
	Records  []Record    // stored records
	Sites    []SiteNames // sites whose names fall into this zone
	Settings Settings
	// MailHost is the mail server's name ("" = no mail server); its A record
	// is added when it falls into this zone. MailDomains are the mail
	// domains of this zone (MX, SPF, DKIM and DMARC records).
	MailHost    string
	MailDomains []MailDomain
}

// DMARCPolicy and SPFPolicy are the records published for mail domains.
const (
	SPFPolicy   = "v=spf1 mx ~all"
	DMARCPolicy = "v=DMARC1; p=quarantine"
)

// AutoRecords derives the A/AAAA records for the nameservers living inside
// the zone (glue content) and, when the zone has AutoSites, for every site
// name in it. A name the admin already gave an A, AAAA or CNAME record is
// left alone (manual records win).
func AutoRecords(in RenderInput) []Record {
	zone := in.Zone.Name
	taken := map[string]bool{}
	for _, r := range in.Records {
		if r.Type == TypeA || r.Type == TypeAAAA || r.Type == TypeCNAME {
			taken[r.Name] = true
		}
	}
	var out []Record
	add := func(host, source string) {
		if host != zone && !strings.HasSuffix(host, "."+zone) {
			return
		}
		rel := strings.TrimSuffix(strings.TrimSuffix(host, zone), ".")
		if rel == "" {
			rel = "@"
		}
		if taken[rel] {
			return
		}
		taken[rel] = true
		for _, ip := range in.Settings.IPs {
			t := TypeA
			if ip.Is6() {
				t = TypeAAAA
			}
			out = append(out, Record{ZoneID: in.Zone.ID, Name: rel, Type: t, Value: ip.String(), Auto: true, Source: source})
		}
	}
	add(in.Settings.NS1, "nameserver")
	add(in.Settings.NS2, "nameserver")
	if in.Zone.AutoSites {
		for _, s := range in.Sites {
			for _, n := range s.Names {
				add(n, s.Domain)
			}
		}
	}
	return append(out, mailRecords(in, taken)...)
}

// relName returns host relative to zone ("" when outside it).
func relName(host, zone string) string {
	if host == zone {
		return "@"
	}
	if !strings.HasSuffix(host, "."+zone) {
		return ""
	}
	return strings.TrimSuffix(host, "."+zone)
}

func under(label, rel string) string {
	if rel == "@" {
		return label
	}
	return label + "." + rel
}

// mailRecords derives the mail server's A record (IPv4 only: the container
// publishes its ports on IPv4) and, per mail domain, MX + SPF + DKIM + DMARC.
// Manual records win: an MX at the name, a "v=spf1" TXT, any TXT/CNAME at the
// DKIM or DMARC name, and a CNAME at the domain name (nothing may sit next
// to a CNAME) each suppress the corresponding automatic record.
func mailRecords(in RenderInput, taken map[string]bool) []Record {
	if in.MailHost == "" {
		return nil
	}
	zone := in.Zone.Name
	var out []Record
	auto := func(r Record) {
		r.ZoneID, r.Auto, r.Source = in.Zone.ID, true, "posta"
		out = append(out, r)
	}
	if rel := relName(in.MailHost, zone); rel != "" && !taken[rel] {
		taken[rel] = true
		for _, ip := range in.Settings.IPs {
			if ip.Is4() {
				auto(Record{Name: rel, Type: TypeA, Value: ip.String()})
			}
		}
	}
	cname, mx, spf, txt := map[string]bool{}, map[string]bool{}, map[string]bool{}, map[string]bool{}
	for _, r := range in.Records {
		switch r.Type {
		case TypeCNAME:
			cname[r.Name] = true
		case TypeMX:
			mx[r.Name] = true
		case TypeTXT:
			txt[r.Name] = true
			if strings.HasPrefix(strings.ToLower(r.Value), "v=spf1") {
				spf[r.Name] = true
			}
		}
	}
	for _, d := range in.MailDomains {
		rel := relName(d.Name, zone)
		if rel == "" || cname[rel] {
			continue
		}
		if !mx[rel] {
			auto(Record{Name: rel, Type: TypeMX, Prio: 10, Value: in.MailHost})
		}
		if !spf[rel] {
			auto(Record{Name: rel, Type: TypeTXT, Value: SPFPolicy})
		}
		if sel := d.DKIMSelector; d.DKIMTXT != "" && sel != "" {
			if n := under(sel+"._domainkey", rel); !txt[n] && !cname[n] {
				auto(Record{Name: n, Type: TypeTXT, Value: d.DKIMTXT})
			}
		}
		if n := under("_dmarc", rel); !txt[n] && !cname[n] {
			auto(Record{Name: n, Type: TypeTXT, Value: DMARCPolicy})
		}
	}
	return out
}

var typeOrder = map[string]int{TypeNS: 0, TypeA: 1, TypeAAAA: 2, TypeCNAME: 3, TypeMX: 4, TypeTXT: 5, TypeSRV: 6, TypeCAA: 7}

// SortRecords orders records for display and rendering: apex first, then by
// name, type and value.
func SortRecords(rs []Record) {
	sort.SliceStable(rs, func(i, j int) bool {
		a, b := rs[i], rs[j]
		if (a.Name == "@") != (b.Name == "@") {
			return a.Name == "@"
		}
		if a.Name != b.Name {
			return a.Name < b.Name
		}
		if a.Type != b.Type {
			return typeOrder[a.Type] < typeOrder[b.Type]
		}
		if a.Prio != b.Prio {
			return a.Prio < b.Prio
		}
		return a.Value < b.Value
	})
}

// quoteTXT splits v into ≤255-byte character strings and quotes each one,
// escaping " and \ (the only escapes the validators accept).
func quoteTXT(v string) string {
	var parts []string
	for len(v) > 0 {
		n := min(255, len(v))
		chunk := v[:n]
		v = v[n:]
		chunk = strings.ReplaceAll(chunk, `\`, `\\`)
		chunk = strings.ReplaceAll(chunk, `"`, `\"`)
		parts = append(parts, `"`+chunk+`"`)
	}
	return strings.Join(parts, " ")
}

func rdata(r Record) string {
	switch r.Type {
	case TypeCNAME, TypeNS:
		return r.Value + "."
	case TypeMX:
		return strconv.Itoa(r.Prio) + " " + r.Value + "."
	case TypeSRV:
		return fmt.Sprintf("%d %d %d %s.", r.Prio, r.Weight, r.Port, r.Value)
	case TypeTXT:
		return quoteTXT(r.Value)
	case TypeCAA:
		return fmt.Sprintf(`%d %s "%s"`, r.Prio, r.Tag, r.Value)
	}
	return r.Value // A, AAAA
}

// Render builds the zone file: one record per line, absolute owner names,
// no parentheses, no comments and no $ directive other than $TTL — the exact
// shape ValidateZoneFile (and hp-dns.sh) accept.
func Render(in RenderInput) string {
	z := in.Zone
	ttl := z.DefaultTTL
	if ttl == 0 {
		ttl = 3600
	}
	var b strings.Builder
	fmt.Fprintf(&b, "$TTL %d\n", ttl)
	fmt.Fprintf(&b, "%s. %d IN SOA %s. %s. %d %d %d %d %d\n", z.Name, ttl, in.Settings.NS1, in.Settings.rname(),
		z.Serial, z.Refresh, z.Retry, z.Expire, z.Minimum)
	fmt.Fprintf(&b, "%s. %d IN NS %s.\n", z.Name, ttl, in.Settings.NS1)
	fmt.Fprintf(&b, "%s. %d IN NS %s.\n", z.Name, ttl, in.Settings.NS2)
	all := append(append([]Record{}, in.Records...), AutoRecords(in)...)
	SortRecords(all)
	for _, r := range all {
		t := r.TTL
		if t == 0 {
			t = ttl
		}
		fmt.Fprintf(&b, "%s. %d IN %s %s\n", r.FQDN(z.Name), t, r.Type, rdata(r))
	}
	return b.String()
}

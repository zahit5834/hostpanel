package dns

import (
	"bufio"
	"net/netip"
	"os"
	"strings"
	"testing"
	"time"
)

func testSettings() Settings {
	return Settings{NS1: "ns1.ornek.com", NS2: "ns2.ornek.com", Hostmaster: "hostmaster@ornek.com",
		IPs: []netip.Addr{netip.MustParseAddr("185.48.180.32"), netip.MustParseAddr("2a01:4f8::1")}}
}

func TestRecordNormalize(t *testing.T) {
	ok := []Record{
		{Name: "@", Type: "a", Value: "1.2.3.4"},
		{Name: "", Type: "AAAA", Value: "2001:DB8::1"},
		{Name: "www.ornek.com", Type: "CNAME", Value: "ornek.com."},
		{Name: "www.ornek.com.", Type: "CNAME", Value: "@"},
		{Name: "*", Type: "A", Value: "1.2.3.4"},
		{Name: "*.app", Type: "A", Value: "1.2.3.4"},
		{Name: "_dmarc", Type: "TXT", Value: `v=DMARC1; p=none; rua="mailto:x@ornek.com"`},
		{Name: "@", Type: "MX", Prio: 10, Value: "mail.ornek.com"},
		{Name: "_sip._tcp", Type: "SRV", Prio: 10, Weight: 5, Port: 5060, Value: "sip.ornek.com"},
		{Name: "@", Type: "CAA", Prio: 0, Tag: "issue", Value: "letsencrypt.org"},
		{Name: "sub", Type: "NS", Value: "ns.baska.com"},
		{Name: "x", Type: "TXT", TTL: 60, Value: strings.Repeat("a", MaxTXT)},
	}
	for _, r := range ok {
		if err := r.Normalize("ornek.com"); err != nil {
			t.Errorf("%+v: %v", r, err)
		}
	}
	r := Record{Name: "WWW.Ornek.com", Type: "cname", Value: "Ornek.COM."}
	if err := r.Normalize("ornek.com"); err != nil || r.Name != "www" || r.Type != "CNAME" || r.Value != "ornek.com" {
		t.Fatalf("%+v %v", r, err)
	}
	bad := []Record{
		{Name: "@", Type: "A", Value: "1.2.3"},
		{Name: "@", Type: "A", Value: "::1"},
		{Name: "@", Type: "AAAA", Value: "1.2.3.4"},
		{Name: "@", Type: "AAAA", Value: "::ffff:1.2.3.4"},
		{Name: "@", Type: "CNAME", Value: "x.ornek.com"},
		{Name: "@", Type: "NS", Value: "ns.baska.com"},
		{Name: "www", Type: "CNAME", Value: "localhost"},
		{Name: "www", Type: "CNAME", Value: "x.com;id"},
		{Name: "a b", Type: "A", Value: "1.2.3.4"},
		{Name: "x.*", Type: "A", Value: "1.2.3.4"},
		{Name: "-x", Type: "A", Value: "1.2.3.4"},
		{Name: "www.baska.com.", Type: "A", Value: "1.2.3.4"},
		{Name: "x", Type: "A", TTL: 30, Value: "1.2.3.4"},
		{Name: "x", Type: "A", TTL: 9999999, Value: "1.2.3.4"},
		{Name: "x", Type: "TXT", Value: ""},
		{Name: "x", Type: "TXT", Value: strings.Repeat("a", MaxTXT+1)},
		{Name: "x", Type: "TXT", Value: "çok"},
		{Name: "x", Type: "TXT", Value: "a\nb"},
		{Name: "@", Type: "MX", Prio: 70000, Value: "mail.ornek.com"},
		{Name: "x", Type: "SRV", Port: -1, Value: "a.ornek.com"},
		{Name: "@", Type: "CAA", Prio: 1, Tag: "issue", Value: "x"},
		{Name: "@", Type: "CAA", Tag: "tbs", Value: "x"},
		{Name: "@", Type: "CAA", Tag: "issue", Value: `a"b`},
		{Name: "@", Type: "PTR", Value: "x.ornek.com"},
		{Name: "@", Type: "SOA", Value: "x"},
	}
	for _, r := range bad {
		if err := r.Normalize("ornek.com"); err == nil {
			t.Errorf("accepted %+v", r)
		}
	}
}

func TestConflicts(t *testing.T) {
	others := []Record{{ID: 1, Name: "www", Type: TypeA, Value: "1.2.3.4"}, {ID: 2, Name: "mail", Type: TypeCNAME, Value: "x.com"}}
	if err := CheckConflicts(Record{Name: "www", Type: TypeCNAME, Value: "ornek.com"}, others); err == nil {
		t.Fatal("CNAME next to A accepted")
	}
	if err := CheckConflicts(Record{Name: "mail", Type: TypeA, Value: "1.2.3.4"}, others); err == nil {
		t.Fatal("A next to CNAME accepted")
	}
	if err := CheckConflicts(Record{Name: "www", Type: TypeA, Value: "1.2.3.4"}, others); err == nil {
		t.Fatal("duplicate accepted")
	}
	if err := CheckConflicts(Record{Name: "www", Type: TypeA, Value: "5.6.7.8"}, others); err != nil {
		t.Fatal(err)
	}
}

func TestZoneForAndSerial(t *testing.T) {
	zones := []string{"ornek.com", "shop.ornek.com", "baska.net"}
	for host, want := range map[string]string{
		"ornek.com": "ornek.com", "www.ornek.com": "ornek.com", "a.shop.ornek.com": "shop.ornek.com",
		"shop.ornek.com": "shop.ornek.com", "xornek.com": "", "ornek.com.tr": "",
	} {
		if got := ZoneFor(host, zones); got != want {
			t.Errorf("ZoneFor(%s) = %q, want %q", host, got, want)
		}
	}
	day := time.Date(2026, 11, 7, 23, 0, 0, 0, time.UTC)
	if s := NextSerial(0, day); s != 2026110700 {
		t.Fatal(s)
	}
	if s := NextSerial(2026110700, day); s != 2026110701 {
		t.Fatal(s)
	}
	if s := NextSerial(2026110599, day); s != 2026110700 {
		t.Fatal(s)
	}
	if s := NextSerial(2026120105, day); s != 2026120106 { // never goes backwards
		t.Fatal(s)
	}
}

func TestRenderGolden(t *testing.T) {
	z := Zone{ID: 1, Name: "ornek.com", Serial: 2026110701, DefaultTTL: 3600, Refresh: 3600, Retry: 900, Expire: 1209600, Minimum: 300, AutoSites: true}
	recs := []Record{
		{Name: "@", Type: TypeMX, Prio: 10, Value: "mail.ornek.com"},
		{Name: "blog", Type: TypeCNAME, Value: "ornek.com"}, // manual CNAME wins over the alias' auto record
		{Name: "dkim._domainkey", Type: TypeTXT, TTL: 300, Value: strings.Repeat("k", 300) + `"\`},
		{Name: "@", Type: TypeCAA, Tag: "issue", Value: "letsencrypt.org"},
	}
	in := RenderInput{Zone: z, Records: recs, Settings: testSettings(),
		Sites: []SiteNames{{Domain: "ornek.com", Names: []string{"ornek.com", "www.ornek.com", "blog.ornek.com"}}}}
	got := Render(in)
	want := `$TTL 3600
ornek.com. 3600 IN SOA ns1.ornek.com. hostmaster.ornek.com. 2026110701 3600 900 1209600 300
ornek.com. 3600 IN NS ns1.ornek.com.
ornek.com. 3600 IN NS ns2.ornek.com.
ornek.com. 3600 IN A 185.48.180.32
ornek.com. 3600 IN AAAA 2a01:4f8::1
ornek.com. 3600 IN MX 10 mail.ornek.com.
ornek.com. 3600 IN CAA 0 issue "letsencrypt.org"
blog.ornek.com. 3600 IN CNAME ornek.com.
dkim._domainkey.ornek.com. 300 IN TXT "` + strings.Repeat("k", 255) + `" "` + strings.Repeat("k", 45) + `\"\\"
ns1.ornek.com. 3600 IN A 185.48.180.32
ns1.ornek.com. 3600 IN AAAA 2a01:4f8::1
ns2.ornek.com. 3600 IN A 185.48.180.32
ns2.ornek.com. 3600 IN AAAA 2a01:4f8::1
www.ornek.com. 3600 IN A 185.48.180.32
www.ornek.com. 3600 IN AAAA 2a01:4f8::1
`
	if got != want {
		t.Fatalf("render:\n%s\nwant:\n%s", got, want)
	}
	if err := ValidateZoneFile(got, "ornek.com"); err != nil {
		t.Fatal(err)
	}
	// Auto site records off: only the nameserver glue remains automatic.
	in.Zone.AutoSites = false
	for _, r := range AutoRecords(in) {
		if r.Source != "nameserver" {
			t.Fatalf("auto record with AutoSites off: %+v", r)
		}
	}
	// Nameservers outside the zone get no glue.
	in.Settings.NS1, in.Settings.NS2 = "ns1.baska.net", "ns2.baska.net"
	if a := AutoRecords(in); len(a) != 0 {
		t.Fatalf("%+v", a)
	}
}

func TestSettingsValidate(t *testing.T) {
	s := testSettings()
	if err := s.Validate(); err != nil {
		t.Fatal(err)
	}
	for _, mod := range []func(*Settings){
		func(s *Settings) { s.NS2 = s.NS1 },
		func(s *Settings) { s.NS1 = "ns1" },
		func(s *Settings) { s.Hostmaster = "ad.soyad@ornek.com" },
		func(s *Settings) { s.Hostmaster = "x" },
		func(s *Settings) { s.IPs = nil },
		func(s *Settings) { s.IPs = []netip.Addr{netip.MustParseAddr("10.0.0.5")} },
		func(s *Settings) { s.IPs = []netip.Addr{netip.MustParseAddr("127.0.0.1")} },
	} {
		x := testSettings()
		mod(&x)
		if err := x.Validate(); err == nil {
			t.Errorf("accepted %+v", x)
		}
	}
}

const zoneHead = "$TTL 3600\nornek.com. 3600 IN SOA ns1.ornek.com. hostmaster.ornek.com. 1 2 3 4 5\n"

func TestValidateZoneFileGood(t *testing.T) {
	b, err := os.ReadFile("../../deploy/scripts/testdata_zone_good.txt")
	if err != nil {
		t.Fatal(err)
	}
	if err := ValidateZoneFile(string(b), "ornek.com"); err != nil {
		t.Fatal(err)
	}
}

func TestValidateZoneFileBadLines(t *testing.T) {
	f, err := os.Open("../../deploy/scripts/testdata_zone_bad.txt")
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	n := 0
	for sc.Scan() {
		n++
		if err := ValidateZoneFile(zoneHead+sc.Text()+"\n", "ornek.com"); err == nil {
			t.Errorf("accepted: %s", sc.Text())
		}
	}
	if n < 30 {
		t.Fatalf("only %d test lines", n)
	}
	for _, c := range []string{
		"",                               // empty
		zoneHead,                         // fine, used below as control
		"ornek.com. 3600 IN A 1.2.3.4\n", // no $TTL
		"$TTL 3600\nornek.com. 3600 IN A 1.2.3.4\n", // no SOA
		zoneHead + "x.ornek.com. 60 IN A 1.2.3.4",   // no final newline
		zoneHead + "x.ornek.com. 60 IN A 1.2.3.4\r\n",
	} {
		err := ValidateZoneFile(c, "ornek.com")
		if c == zoneHead {
			if err != nil {
				t.Fatal(err)
			}
			continue
		}
		if err == nil {
			t.Errorf("accepted %q", c)
		}
	}
}

func TestWildcardSiteRecord(t *testing.T) {
	z := Zone{ID: 1, Name: "ornek.com", Serial: 2026111201, DefaultTTL: 3600, Refresh: 3600, Retry: 900, Expire: 1209600, Minimum: 300, AutoSites: true}
	in := RenderInput{Zone: z, Settings: testSettings(),
		Sites: []SiteNames{{Domain: "ornek.com", Names: []string{"ornek.com", "*.ornek.com"}}}}
	got := Render(in)
	if !strings.Contains(got, "\n*.ornek.com. 3600 IN A 185.48.180.32\n") {
		t.Fatalf("wildcard A missing:\n%s", got)
	}
	if err := ValidateZoneFile(got, "ornek.com"); err != nil {
		t.Fatal(err)
	}
	// A manual "*" record wins.
	in.Records = []Record{{Name: "*", Type: TypeCNAME, Value: "ornek.com"}}
	for _, r := range AutoRecords(in) {
		if r.Name == "*" {
			t.Fatalf("auto * despite manual record: %+v", r)
		}
	}
}

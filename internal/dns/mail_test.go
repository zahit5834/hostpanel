package dns

import (
	"strings"
	"testing"
)

func TestMailRecords(t *testing.T) {
	z := Zone{ID: 1, Name: "ornek.com", Serial: 2026111101, DefaultTTL: 3600, Refresh: 3600, Retry: 900, Expire: 1209600, Minimum: 300}
	dkim := "v=DKIM1; k=rsa; p=" + strings.Repeat("A", 392)
	in := RenderInput{Zone: z, Settings: testSettings(), MailHost: "mail.ornek.com",
		MailDomains: []MailDomain{
			{Name: "ornek.com", DKIMSelector: "mail", DKIMTXT: dkim},
			{Name: "sub.ornek.com", DKIMSelector: "mail"}, // key not created yet
		}}
	got := Render(in)
	for _, want := range []string{
		"mail.ornek.com. 3600 IN A 185.48.180.32\n",
		"ornek.com. 3600 IN MX 10 mail.ornek.com.\n",
		"ornek.com. 3600 IN TXT \"v=spf1 mx ~all\"\n",
		"mail._domainkey.ornek.com. 3600 IN TXT \"v=DKIM1; k=rsa; p=",
		"_dmarc.ornek.com. 3600 IN TXT \"v=DMARC1; p=quarantine\"\n",
		"sub.ornek.com. 3600 IN MX 10 mail.ornek.com.\n",
		"_dmarc.sub.ornek.com. 3600 IN TXT",
		"_autodiscover._tcp.ornek.com. 3600 IN SRV 0 0 443 mail.ornek.com.\n",
		"_imaps._tcp.ornek.com. 3600 IN SRV 0 1 993 mail.ornek.com.\n",
		"_submissions._tcp.ornek.com. 3600 IN SRV 0 1 465 mail.ornek.com.\n",
		"_submission._tcp.sub.ornek.com. 3600 IN SRV 0 1 587 mail.ornek.com.\n",
	} {
		if !strings.Contains(got, want) {
			t.Errorf("missing %q in\n%s", want, got)
		}
	}
	// IPv4 only for the mail host; no DKIM record without a key.
	if strings.Contains(got, "mail.ornek.com. 3600 IN AAAA") || strings.Contains(got, "mail._domainkey.sub.") {
		t.Fatalf("unexpected record:\n%s", got)
	}
	// Mail records do not depend on AutoSites (off here).
	if err := ValidateZoneFile(got, "ornek.com"); err != nil {
		t.Fatal(err)
	}

	// Manual records win.
	in.Records = []Record{
		{Name: "@", Type: TypeMX, Prio: 5, Value: "mx.baska.net"},
		{Name: "@", Type: TypeTXT, Value: "v=spf1 include:_spf.google.com ~all"},
		{Name: "_dmarc", Type: TypeTXT, Value: "v=DMARC1; p=reject"},
		{Name: "mail", Type: TypeA, Value: "203.0.113.9"},
		{Name: "sub", Type: TypeCNAME, Value: "ornek.com"},
	}
	for _, r := range AutoRecords(in) {
		switch {
		case r.Source != "posta" && r.Source != "nameserver":
			t.Errorf("source %+v", r)
		case r.Source == "posta" && r.Name != "mail._domainkey" && r.Type != TypeSRV:
			t.Errorf("manual record overridden by %+v", r)
		}
	}
	if err := ValidateZoneFile(Render(in), "ornek.com"); err != nil {
		t.Fatal(err)
	}

	// Mail host outside the zone: MX points there, no A record here.
	in.Records, in.MailHost = nil, "mail.baska.net"
	got = Render(in)
	if !strings.Contains(got, "ornek.com. 3600 IN MX 10 mail.baska.net.\n") || strings.Contains(got, "mail.baska.net. 3600 IN A") {
		t.Fatalf("outside host:\n%s", got)
	}
	// No mail server: nothing.
	in.MailHost = ""
	for _, r := range AutoRecords(in) {
		if r.Source == "posta" {
			t.Fatalf("%+v", r)
		}
	}
}

func TestMailClientAndReportRecords(t *testing.T) {
	z := Zone{ID: 1, Name: "ornek.com", Serial: 2026111101, DefaultTTL: 3600, Refresh: 3600, Retry: 900, Expire: 1209600, Minimum: 300}
	in := RenderInput{Zone: z, Settings: testSettings(), MailHost: "mail.ornek.com",
		MailDomains:    []MailDomain{{Name: "ornek.com", DMARC: "v=DMARC1; p=reject; rua=mailto:dmarc@ornek.com"}},
		MailExtraHosts: []string{"autoconfig.ornek.com", "autodiscover.ornek.com", "autoconfig.baska.net"},
		MailReports:    []string{"musteri.net._report._dmarc.ornek.com", "x.com._report._dmarc.baska.net"},
	}
	got := Render(in)
	for _, want := range []string{
		"_dmarc.ornek.com. 3600 IN TXT \"v=DMARC1; p=reject; rua=mailto:dmarc@ornek.com\"\n",
		"autoconfig.ornek.com. 3600 IN A 185.48.180.32\n",
		"autodiscover.ornek.com. 3600 IN A 185.48.180.32\n",
		"musteri.net._report._dmarc.ornek.com. 3600 IN TXT \"v=DMARC1\"\n",
	} {
		if !strings.Contains(got, want) {
			t.Errorf("missing %q in\n%s", want, got)
		}
	}
	if strings.Contains(got, "baska.net") || strings.Contains(got, "x.com._report") {
		t.Fatalf("names outside the zone:\n%s", got)
	}
	if err := ValidateZoneFile(got, "ornek.com"); err != nil {
		t.Fatal(err)
	}
	// Manual records at those names win.
	in.Records = []Record{
		{Name: "autoconfig", Type: TypeCNAME, Value: "elsewhere.net"},
		{Name: "_imaps._tcp", Type: TypeSRV, Prio: 5, Weight: 0, Port: 993, Value: "imap.elsewhere.net"},
		{Name: "musteri.net._report._dmarc", Type: TypeTXT, Value: "v=DMARC1"},
	}
	for _, r := range AutoRecords(in) {
		if r.Name == "autoconfig" || r.Name == "_imaps._tcp" || r.Name == "musteri.net._report._dmarc" {
			t.Errorf("manual record overridden by %+v", r)
		}
	}
}

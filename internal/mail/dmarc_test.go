package mail

import (
	"archive/zip"
	"bytes"
	"compress/gzip"
	"context"
	"encoding/base64"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// googleXML follows the shape of Google's aggregate reports.
const googleXML = `<?xml version="1.0" encoding="UTF-8" ?>
<feedback>
  <report_metadata>
    <org_name>google.com</org_name>
    <email>noreply-dmarc-support@google.com</email>
    <extra_contact_info>https://support.google.com/a/answer/2466580</extra_contact_info>
    <report_id>12345678901234567890</report_id>
    <date_range><begin>1794355200</begin><end>1794441599</end></date_range>
  </report_metadata>
  <policy_published><domain>ornek.com</domain><adkim>r</adkim><aspf>r</aspf><p>quarantine</p><sp>quarantine</sp><pct>100</pct><np>quarantine</np></policy_published>
  <record>
    <row><source_ip>185.48.180.32</source_ip><count>12</count>
      <policy_evaluated><disposition>none</disposition><dkim>pass</dkim><spf>pass</spf></policy_evaluated></row>
    <identifiers><header_from>ornek.com</header_from></identifiers>
    <auth_results><dkim><domain>ornek.com</domain><result>pass</result><selector>mail</selector></dkim><spf><domain>ornek.com</domain><result>pass</result></spf></auth_results>
  </record>
  <record>
    <row><source_ip>203.0.113.7</source_ip><count>3</count>
      <policy_evaluated><disposition>quarantine</disposition><dkim>fail</dkim><spf>fail</spf></policy_evaluated></row>
    <identifiers><header_from>ornek.com</header_from></identifiers>
    <auth_results><spf><domain>spoof.example</domain><result>softfail</result></spf></auth_results>
  </record>
</feedback>`

// microsoftXML follows Outlook.com's shape (namespace, <envelope_to>).
const microsoftXML = `<?xml version="1.0"?>
<feedback xmlns:xsd="http://www.w3.org/2001/XMLSchema" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">
  <version>1.0</version>
  <report_metadata><org_name>Outlook.com</org_name><email>dmarcreport@microsoft.com</email>
    <report_id>a1b2c3d4e5f60718293a4b5c6d7e8f90</report_id><date_range><begin>1794355200</begin><end>1794441600</end></date_range></report_metadata>
  <policy_published><domain>ornek.com</domain><adkim>r</adkim><aspf>r</aspf><p>quarantine</p><sp>quarantine</sp><pct>100</pct><fo>0</fo></policy_published>
  <record><row><source_ip>2001:db8::25</source_ip><count>2</count><policy_evaluated><disposition>none</disposition><dkim>pass</dkim><spf>fail</spf></policy_evaluated></row>
    <identifiers><envelope_to>hotmail.com</envelope_to><envelope_from>ornek.com</envelope_from><header_from>ornek.com</header_from></identifiers>
    <auth_results><dkim><domain>ornek.com</domain><selector>mail</selector><result>pass</result></dkim><spf><domain>ornek.com</domain><scope>mfrom</scope><result>fail</result></spf></auth_results></record>
</feedback>`

func reportMail(t *testing.T, ctype, name string, payload []byte) []byte {
	t.Helper()
	b64 := base64.StdEncoding.EncodeToString(payload)
	var lines []string
	for len(b64) > 76 {
		lines, b64 = append(lines, b64[:76]), b64[76:]
	}
	lines = append(lines, b64)
	return []byte("From: noreply-dmarc-support@google.com\r\nTo: dmarc@ornek.com\r\nSubject: Report domain: ornek.com\r\n" +
		"MIME-Version: 1.0\r\nContent-Type: multipart/mixed; boundary=\"b1\"\r\n\r\n--b1\r\nContent-Type: text/plain\r\n\r\nThis is an aggregate report.\r\n" +
		"--b1\r\nContent-Type: " + ctype + "; name=\"" + name + "\"\r\nContent-Disposition: attachment; filename=\"" + name + "\"\r\n" +
		"Content-Transfer-Encoding: base64\r\n\r\n" + strings.Join(lines, "\r\n") + "\r\n--b1--\r\n")
}

func zipOf(t *testing.T, name string, data []byte) []byte {
	var b bytes.Buffer
	zw := zip.NewWriter(&b)
	w, _ := zw.Create(name)
	w.Write(data)
	zw.Close()
	return b.Bytes()
}

func gzipOf(data []byte) []byte {
	var b bytes.Buffer
	gw := gzip.NewWriter(&b)
	gw.Write(data)
	gw.Close()
	return b.Bytes()
}

func TestParseReportMail(t *testing.T) {
	cases := map[string][]byte{
		"zip":  reportMail(t, "application/zip", "google.com!ornek.com!1794355200!1794441599.zip", zipOf(t, "google.com!ornek.com.xml", []byte(googleXML))),
		"gzip": reportMail(t, "application/gzip", "outlook.com!ornek.com!1794355200!1794441600.xml.gz", gzipOf([]byte(microsoftXML))),
		"xml":  reportMail(t, "text/xml", "r.xml", []byte(googleXML)),
	}
	for name, raw := range cases {
		fbs, err := ParseReportMail(bytes.NewReader(raw))
		if err != nil || len(fbs) != 1 {
			t.Fatalf("%s: %v %d", name, err, len(fbs))
		}
		f := fbs[0]
		if f.Domain != "ornek.com" || f.Policy != "quarantine" || f.Begin != 1794355200 || len(f.Records) == 0 {
			t.Fatalf("%s: %+v", name, f)
		}
	}
	fbs, _ := ParseReportMail(bytes.NewReader(cases["gzip"]))
	if r := fbs[0].Records[0]; r.SourceIP != "2001:db8::25" || r.DKIM != "pass" || r.SPF != "fail" || r.Count != 2 {
		t.Fatalf("microsoft record %+v", r)
	}
	// A plain mail without a report is skipped, not an error to retry.
	if _, err := ParseReportMail(strings.NewReader("From: a@b.c\r\nSubject: hi\r\n\r\nhello\r\n")); err == nil || !strings.Contains(err.Error(), "raporu yok") {
		t.Fatal(err)
	}
	// Broken attachments fail cleanly.
	for _, raw := range [][]byte{
		reportMail(t, "application/zip", "x.zip", []byte("not a zip")),
		reportMail(t, "application/gzip", "x.gz", []byte("not gzip")),
		reportMail(t, "text/xml", "x.xml", []byte("<feedback><report_metadata>")),
		reportMail(t, "text/xml", "x.xml", []byte(`<!DOCTYPE f [<!ENTITY x SYSTEM "file:///etc/passwd">]><feedback><report_metadata><org_name>&x;</org_name></report_metadata></feedback>`)),
	} {
		if _, err := ParseReportMail(bytes.NewReader(raw)); err == nil {
			t.Fatal("broken report accepted")
		}
	}
	// Zip bomb: 30 MB of zeros compresses to a few KB.
	bomb := zipOf(t, "x.xml", append([]byte("<feedback>"), make([]byte, 30<<20)...))
	if _, err := ParseReportMail(bytes.NewReader(reportMail(t, "application/zip", "x.zip", bomb))); err == nil || !strings.Contains(err.Error(), "büyük") {
		t.Fatalf("zip bomb: %v", err)
	}
	gbomb := gzipOf(make([]byte, 30<<20))
	if _, err := ParseReportMail(bytes.NewReader(reportMail(t, "application/gzip", "x.gz", gbomb))); err == nil || !strings.Contains(err.Error(), "büyük") {
		t.Fatalf("gzip bomb: %v", err)
	}
}

func TestDMARCValueAndReports(t *testing.T) {
	d := Domain{Name: "ornek.com", DMARCPolicy: "reject"}
	if v := DMARCValue(d, ""); v != "v=DMARC1; p=reject" {
		t.Fatal(v)
	}
	if v := DMARCValue(Domain{Name: "x.com"}, "dmarc@ornek.com"); v != "v=DMARC1; p=quarantine; rua=mailto:dmarc@ornek.com" {
		t.Fatal(v)
	}
	got := ReportNames([]Domain{{Name: "ornek.com"}, {Name: "sub.ornek.com"}, {Name: "musteri.com.tr"}}, "dmarc@ornek.com")
	if strings.Join(got, ",") != "musteri.com.tr._report._dmarc.ornek.com" {
		t.Fatal(got)
	}
	if ReportNames([]Domain{{Name: "x.com"}}, "") != nil {
		t.Fatal("no report address, no names")
	}
}

func TestSyncReportsStore(t *testing.T) {
	ctx := context.Background()
	s := newTestService(t)
	dir := t.TempDir()
	s.ReportsDir = dir
	os.WriteFile(filepath.Join(dir, "1.M1"), reportMail(t, "application/zip", "g.zip", zipOf(t, "g.xml", []byte(googleXML))), 0o640)
	os.WriteFile(filepath.Join(dir, "2.M2"), reportMail(t, "application/gzip", "m.xml.gz", gzipOf([]byte(microsoftXML))), 0o640)
	os.WriteFile(filepath.Join(dir, "3.M3"), reportMail(t, "application/zip", "g.zip", zipOf(t, "g.xml", []byte(googleXML))), 0o640) // same report again
	os.WriteFile(filepath.Join(dir, "4.M4"), []byte("From: a@b.c\r\n\r\nhi\r\n"), 0o640)
	os.WriteFile(filepath.Join(dir, "5.M5"), reportMail(t, "application/zip", "x.zip", []byte("broken")), 0o640)
	if err := s.SetReportAddress(ctx, "dmarc@ornek.com"); err == nil {
		t.Fatal("report address without a mailbox accepted")
	}
	s.Fake.setAccount("dmarc@ornek.com")
	if err := s.SetReportAddress(ctx, "info@ornek.com"); err == nil {
		t.Fatal("non-dmarc local part accepted")
	}
	if err := s.SetReportAddress(ctx, "dmarc@ornek.com"); err != nil {
		t.Fatal(err)
	}
	res, err := s.SyncReports(ctx)
	if err != nil || res.Files != 5 || res.Reports != 2 || res.Failed != 1 {
		t.Fatalf("%+v %v", res, err)
	}
	res, _ = s.SyncReports(ctx) // nothing new
	if res.Parsed != 0 || res.Failed != 0 {
		t.Fatalf("second sync %+v", res)
	}
	sum, err := s.DMARCSummaries(ctx, time.Unix(1794355200, 0))
	if err != nil || len(sum) != 1 {
		t.Fatal(sum, err)
	}
	d := sum[0]
	if d.Total != 17 || d.Pass != 14 || d.DKIM != 14 || d.SPF != 12 || d.Reports != 2 || len(d.Sources) != 3 || d.Sources[0].IP != "185.48.180.32" {
		t.Fatalf("%+v", d)
	}
	if d.Sources[1].IP != "203.0.113.7" || d.Sources[1].Failing() != 3 || d.PassPct() != 82 {
		t.Fatalf("%+v", d.Sources)
	}
	if strings.Join(d.Orgs, ",") != "Outlook.com,google.com" {
		t.Fatal(d.Orgs)
	}
}

// newTestService returns a service with a running server and ornek.com.
func newTestService(t *testing.T) *Service {
	t.Helper()
	s, _, _ := testService(t)
	ctx := context.Background()
	srv := Server{Image: DefaultImage, Hostname: "mail.ornek.com", LEEmail: "a@ornek.com", MemoryMB: 1024, MsgLimitMB: 25, Status: StatusRunning}
	if err := s.Store.InsertServer(ctx, &srv); err != nil {
		t.Fatal(err)
	}
	d := Domain{Name: "ornek.com"}
	if err := s.Store.InsertDomain(ctx, &d); err != nil {
		t.Fatal(err)
	}
	return s
}

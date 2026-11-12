package mail

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/xml"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/zahit5834/hostpanel/internal/dns"
	"github.com/zahit5834/hostpanel/internal/domains"
	"github.com/zahit5834/hostpanel/internal/jobs"
	"github.com/zahit5834/hostpanel/internal/store"
)

// settingAutoconf is "1" once the mail certificate also holds the
// autoconfig./autodiscover. names of the mail host's parent domain.
const settingAutoconf = "mail_autoconf"

// AutoconfNames are the client set-up names served by the mail vhost
// (autoconfig./autodiscover. of the mail host's parent domain). Thunderbird
// falls back to autoconfig.<MX parent domain>, so one certificate covers
// every mail domain.
func AutoconfNames(host string) []string {
	_, base, ok := strings.Cut(host, ".")
	if !ok || !strings.Contains(base, ".") {
		return nil
	}
	return []string{"autoconfig." + base, "autodiscover." + base}
}

// AutoconfReady reports whether the certificate holds the set-up names.
func (s *Service) AutoconfReady(ctx context.Context) bool {
	return store.GetSetting(ctx, s.DB, settingAutoconf, "") == "1"
}

// StartCertExpand queues adding the set-up names to the mail certificate.
func (s *Service) StartCertExpand(ctx context.Context) (int64, error) {
	srv, err := s.server(ctx)
	if err != nil {
		return 0, err
	}
	if srv.Status != StatusRunning && srv.Status != StatusStopped {
		return 0, errors.New("posta sunucusu kurulumu tamamlanmadı")
	}
	names := AutoconfNames(srv.Hostname)
	if len(names) == 0 {
		return 0, errors.New("posta sunucusunun adı otomatik ayar için uygun değil")
	}
	for _, n := range names {
		if s.NameTaken != nil {
			if err := s.NameTaken(ctx, n); err != nil {
				return 0, err
			}
		}
	}
	return s.Jobs.Submit(ctx, jobs.Spec{Kind: "mail.cert.expand", TargetType: "mail", TargetID: srv.Hostname,
		Summary: "Posta sertifikasına otomatik ayar adları ekleniyor", Params: map[string]any{"server_id": srv.ID}})
}

func (s *Service) jobCertExpand(ctx context.Context, l *jobs.Log, p map[string]any) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	srv, err := s.Store.Server(ctx)
	if err != nil || srv.ID != paramID(p, "server_id") {
		return errors.New("sunucu kaydı bulunamadı")
	}
	names := AutoconfNames(srv.Hostname)
	if len(names) == 0 {
		return errors.New("posta sunucusunun adı otomatik ayar için uygun değil")
	}
	if !s.DryRun {
		for _, n := range names {
			if err := s.resolvesHere(ctx, l, n); err != nil {
				return err
			}
		}
	}
	l.Printf("Let's Encrypt sertifikası genişletiliyor: %s + %s", srv.Hostname, strings.Join(names, ", "))
	if _, err := s.helper(ctx, l, nil, nil, 5*time.Minute, "cert", srv.Hostname, srv.LEEmail, "autoconf"); err != nil {
		return fmt.Errorf("sertifika alınamadı: %w", err)
	}
	store.SetSetting(ctx, s.DB, settingAutoconf, "1")
	l.Printf("Hazır. Thunderbird posta adresi + şifreyle sunucuyu kendisi bulur (MX → %s); Outlook SRV _autodiscover kaydıyla.", names[0])
	return nil
}

// AppleProfile returns an unsigned .mobileconfig for one mailbox (IMAP 993
// SSL, SMTP 465 SSL). It holds no password: iOS/macOS asks for it when the
// profile is installed. The UUIDs derive from address and host, so a second
// download replaces the same profile.
func AppleProfile(addr, host string) []byte {
	sum := sha256.Sum256([]byte("hostpanel-mobileconfig:" + addr + "|" + host))
	uuid := func(b []byte) string {
		return fmt.Sprintf("%X-%X-%X-%X-%X", b[0:4], b[4:6], b[6:8], b[8:10], b[10:16])
	}
	outer, inner := uuid(sum[:16]), uuid(sum[16:])
	esc := func(s string) string {
		var b bytes.Buffer
		xml.EscapeText(&b, []byte(s))
		return b.String()
	}
	a, h := esc(addr), esc(host)
	var b bytes.Buffer
	b.WriteString(`<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>PayloadContent</key>
  <array>
    <dict>
`)
	kv := func(k, v string) { fmt.Fprintf(&b, "      <key>%s</key><string>%s</string>\n", k, v) }
	ki := func(k string, v int) { fmt.Fprintf(&b, "      <key>%s</key><integer>%d</integer>\n", k, v) }
	kb := func(k string, v bool) { fmt.Fprintf(&b, "      <key>%s</key><%t/>\n", k, v) }
	kv("EmailAccountDescription", a)
	kv("EmailAccountName", a)
	kv("EmailAccountType", "EmailTypeIMAP")
	kv("EmailAddress", a)
	kv("IncomingMailServerAuthentication", "EmailAuthPassword")
	kv("IncomingMailServerHostName", h)
	ki("IncomingMailServerPortNumber", 993)
	kb("IncomingMailServerUseSSL", true)
	kv("IncomingMailServerUsername", a)
	kv("OutgoingMailServerAuthentication", "EmailAuthPassword")
	kv("OutgoingMailServerHostName", h)
	ki("OutgoingMailServerPortNumber", 465)
	kb("OutgoingMailServerUseSSL", true)
	kv("OutgoingMailServerUsername", a)
	kb("OutgoingPasswordSameAsIncomingPassword", true)
	kv("PayloadDescription", "E-posta hesabı ("+h+")")
	kv("PayloadDisplayName", a)
	kv("PayloadIdentifier", "hostpanel.mail.account."+inner)
	kv("PayloadType", "com.apple.mail.managed")
	kv("PayloadUUID", inner)
	ki("PayloadVersion", 1)
	kb("PreventAppSheet", false)
	kb("PreventMove", false)
	kb("SMIMEEnabled", false)
	b.WriteString(`    </dict>
  </array>
`)
	top := func(k, v string) { fmt.Fprintf(&b, "  <key>%s</key><string>%s</string>\n", k, v) }
	top("PayloadDescription", "Posta sunucusu "+h+" için hesap ayarları. Şifre kurulum sırasında sorulur.")
	top("PayloadDisplayName", "E-posta: "+a)
	top("PayloadIdentifier", "hostpanel.mail."+outer)
	b.WriteString("  <key>PayloadRemovalDisallowed</key><false/>\n")
	top("PayloadType", "Configuration")
	top("PayloadUUID", outer)
	b.WriteString("  <key>PayloadVersion</key><integer>1</integer>\n</dict>\n</plist>\n")
	return b.Bytes()
}

// --- DNS ---

// ZoneInfo is what the DNS service publishes for the mail server.
func (s *Service) ZoneInfo(ctx context.Context) dns.MailInfo {
	host, ds := s.DNSInfo(ctx)
	if host == "" {
		return dns.MailInfo{}
	}
	rua := s.ReportAddress(ctx)
	mi := dns.MailInfo{Host: host, ExtraHosts: AutoconfNames(host), Reports: ReportNames(ds, rua)}
	for _, d := range ds {
		mi.Domains = append(mi.Domains, dns.MailDomain{Name: d.Name, DKIMSelector: d.DKIMSelector, DKIMTXT: d.DKIMTXT,
			DMARC: DMARCValue(d, rua)})
	}
	return mi
}

// DMARC policies a domain can publish.
var DMARCPolicies = []string{"none", "quarantine", "reject"}

// ValidDMARCPolicy reports whether p is a known policy.
func ValidDMARCPolicy(p string) bool {
	for _, x := range DMARCPolicies {
		if x == p {
			return true
		}
	}
	return false
}

// DMARCValue is the _dmarc TXT of d (with the report address, if any).
func DMARCValue(d Domain, reportAddr string) string {
	p := d.DMARCPolicy
	if !ValidDMARCPolicy(p) {
		p = "quarantine"
	}
	v := "v=DMARC1; p=" + p
	if reportAddr != "" {
		v += "; rua=mailto:" + reportAddr
	}
	return v
}

// ReportNames are the "<domain>._report._dmarc.<report domain>" names that
// authorize reports for domains of another organizational domain.
func ReportNames(ds []Domain, reportAddr string) []string {
	rd := DomainOf(reportAddr)
	if rd == "" {
		return nil
	}
	org := domains.Registrable(rd)
	var out []string
	for _, d := range ds {
		if domains.Registrable(d.Name) != org {
			out = append(out, d.Name+"._report._dmarc."+rd)
		}
	}
	return out
}

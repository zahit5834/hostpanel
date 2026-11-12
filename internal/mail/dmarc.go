package mail

import (
	"archive/zip"
	"bytes"
	"compress/gzip"
	"context"
	"encoding/base64"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"mime"
	"mime/multipart"
	"mime/quotedprintable"
	"net/mail"
	"net/netip"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/zahit5834/hostpanel/internal/store"
)

// DMARC aggregate reports (RFC 7489 appendix C) arriving in the report
// mailbox dmarc@<domain>. The panel never reads a maildir: hp-mail.sh
// dmarc-sync copies that one mailbox to ReportsDir, and each copy is parsed
// once here.
const (
	ReportLocal      = "dmarc"
	ReportsDir       = "/var/lib/hostpanel-mail-reports"
	settingReportAdr = "dmarc_report_addr"

	maxReportMail = 10 << 20 // one message
	maxReportXML  = 20 << 20 // after decompression (zip bomb bound)
	maxParts      = 20
	reportKeep    = 180 * 24 * time.Hour
)

// Feedback is the part of an aggregate report the panel keeps.
type Feedback struct {
	Org      string `xml:"report_metadata>org_name"`
	ReportID string `xml:"report_metadata>report_id"`
	Begin    int64  `xml:"report_metadata>date_range>begin"`
	End      int64  `xml:"report_metadata>date_range>end"`
	Domain   string `xml:"policy_published>domain"`
	Policy   string `xml:"policy_published>p"`
	Records  []struct {
		SourceIP    string `xml:"row>source_ip"`
		Count       int64  `xml:"row>count"`
		Disposition string `xml:"row>policy_evaluated>disposition"`
		DKIM        string `xml:"row>policy_evaluated>dkim"`
		SPF         string `xml:"row>policy_evaluated>spf"`
		HeaderFrom  string `xml:"identifiers>header_from"`
	} `xml:"record"`
}

var tokenRe = regexp.MustCompile(`^[A-Za-z0-9._@:+/=-]*$`)

func clean(s string, n int) string {
	s = strings.TrimSpace(s)
	if len(s) > n {
		s = s[:n]
	}
	b := []byte(s)
	for i, c := range b {
		if c < 0x20 || c == 0x7f {
			b[i] = ' '
		}
	}
	return string(b)
}

func word(s string) string {
	s = strings.ToLower(strings.TrimSpace(s))
	switch s {
	case "pass", "fail", "none", "quarantine", "reject", "softfail", "neutral", "temperror", "permerror":
		return s
	}
	return "?"
}

// validate checks and normalizes a parsed report.
func (f *Feedback) validate() error {
	f.Org, f.ReportID = clean(f.Org, 200), clean(f.ReportID, 200)
	f.Domain = strings.ToLower(strings.TrimSuffix(strings.TrimSpace(f.Domain), "."))
	if f.Org == "" || f.ReportID == "" || f.Domain == "" || len(f.Domain) > 253 || !tokenRe.MatchString(f.Domain) {
		return errors.New("rapor üst bilgisi eksik")
	}
	if f.End < f.Begin || f.Begin <= 0 {
		return errors.New("geçersiz tarih aralığı")
	}
	f.Policy = word(f.Policy)
	kept := f.Records[:0]
	for _, r := range f.Records {
		a, err := netip.ParseAddr(strings.TrimSpace(r.SourceIP))
		if err != nil || r.Count <= 0 || r.Count > 1e9 {
			continue
		}
		r.SourceIP = a.Unmap().String()
		r.Disposition, r.DKIM, r.SPF = word(r.Disposition), word(r.DKIM), word(r.SPF)
		r.HeaderFrom = strings.ToLower(clean(r.HeaderFrom, 253))
		kept = append(kept, r)
		if len(kept) >= 5000 {
			break
		}
	}
	f.Records = kept
	return nil
}

// ParseReportMail extracts the aggregate reports from one mail: zip, gzip or
// plain XML parts (encoding/xml does not resolve external entities).
func ParseReportMail(r io.Reader) ([]Feedback, error) {
	msg, err := mail.ReadMessage(io.LimitReader(r, maxReportMail+1))
	if err != nil {
		return nil, fmt.Errorf("ileti okunamadı: %w", err)
	}
	var out []Feedback
	parts := 0
	var walk func(h map[string][]string, body io.Reader, depth int) error
	walk = func(h map[string][]string, body io.Reader, depth int) error {
		ct := firstHeader(h, "Content-Type")
		mt, params, _ := mime.ParseMediaType(ct)
		if strings.HasPrefix(mt, "multipart/") {
			if depth >= 4 || params["boundary"] == "" {
				return nil
			}
			mr := multipart.NewReader(body, params["boundary"])
			for {
				p, err := mr.NextRawPart()
				if err == io.EOF {
					return nil
				}
				if err != nil {
					return err
				}
				if parts++; parts > maxParts {
					return nil
				}
				if err := walk(p.Header, p, depth+1); err != nil {
					return err
				}
			}
		}
		name := ""
		if _, dp, err := mime.ParseMediaType(firstHeader(h, "Content-Disposition")); err == nil {
			name = dp["filename"]
		}
		if name == "" {
			name = params["name"]
		}
		kind := reportKind(mt, strings.ToLower(name))
		if kind == "" {
			return nil
		}
		raw, err := io.ReadAll(io.LimitReader(decodeTE(firstHeader(h, "Content-Transfer-Encoding"), body), maxReportMail+1))
		if err != nil {
			return err
		}
		fbs, err := decodeReport(kind, raw)
		if err != nil {
			return err
		}
		out = append(out, fbs...)
		return nil
	}
	if err := walk(msg.Header, msg.Body, 0); err != nil {
		return out, err
	}
	if len(out) == 0 {
		return nil, errors.New("ekte DMARC raporu yok")
	}
	return out, nil
}

func firstHeader(h map[string][]string, k string) string {
	if v := h[k]; len(v) > 0 {
		return v[0]
	}
	return ""
}

func decodeTE(te string, r io.Reader) io.Reader {
	switch strings.ToLower(strings.TrimSpace(te)) {
	case "base64":
		return base64.NewDecoder(base64.StdEncoding, newlineStripper{r})
	case "quoted-printable":
		return quotedprintable.NewReader(r)
	}
	return r
}

// newlineStripper drops CR/LF so base64.NewDecoder sees one stream.
type newlineStripper struct{ r io.Reader }

func (n newlineStripper) Read(p []byte) (int, error) {
	for {
		c, err := n.r.Read(p)
		j := 0
		for _, b := range p[:c] {
			if b != '\r' && b != '\n' && b != ' ' && b != '\t' {
				p[j] = b
				j++
			}
		}
		if j > 0 || err != nil {
			return j, err
		}
	}
}

func reportKind(mt, name string) string {
	switch {
	case mt == "application/zip" || mt == "application/x-zip-compressed" || strings.HasSuffix(name, ".zip"):
		return "zip"
	case mt == "application/gzip" || mt == "application/x-gzip" || strings.HasSuffix(name, ".gz"):
		return "gzip"
	case mt == "text/xml" || mt == "application/xml" || strings.HasSuffix(name, ".xml"):
		return "xml"
	}
	return ""
}

func decodeReport(kind string, raw []byte) ([]Feedback, error) {
	var docs [][]byte
	switch kind {
	case "zip":
		zr, err := zip.NewReader(bytes.NewReader(raw), int64(len(raw)))
		if err != nil {
			return nil, fmt.Errorf("zip açılamadı: %w", err)
		}
		total := int64(0)
		for i, f := range zr.File {
			if i >= 5 || !strings.HasSuffix(strings.ToLower(f.Name), ".xml") {
				continue
			}
			rc, err := f.Open()
			if err != nil {
				return nil, fmt.Errorf("zip: %w", err)
			}
			b, err := io.ReadAll(io.LimitReader(rc, maxReportXML-total+1))
			rc.Close()
			if err != nil {
				return nil, fmt.Errorf("zip: %w", err)
			}
			if total += int64(len(b)); total > maxReportXML {
				return nil, errors.New("rapor çok büyük (sıkıştırma sınırı)")
			}
			docs = append(docs, b)
		}
	case "gzip":
		zr, err := gzip.NewReader(bytes.NewReader(raw))
		if err != nil {
			return nil, fmt.Errorf("gzip açılamadı: %w", err)
		}
		b, err := io.ReadAll(io.LimitReader(zr, maxReportXML+1))
		if err != nil {
			return nil, fmt.Errorf("gzip: %w", err)
		}
		if len(b) > maxReportXML {
			return nil, errors.New("rapor çok büyük (sıkıştırma sınırı)")
		}
		docs = append(docs, b)
	default:
		docs = append(docs, raw)
	}
	var out []Feedback
	for _, d := range docs {
		var f Feedback
		dec := xml.NewDecoder(bytes.NewReader(d))
		dec.Strict = true
		if err := dec.Decode(&f); err != nil {
			return nil, fmt.Errorf("XML ayrıştırılamadı: %w", err)
		}
		if err := f.validate(); err != nil {
			return nil, err
		}
		out = append(out, f)
	}
	return out, nil
}

// --- report mailbox ---

// ReportAddress is the DMARC report mailbox ("" = reports not collected).
func (s *Service) ReportAddress(ctx context.Context) string {
	a := store.GetSetting(ctx, s.DB, settingReportAdr, "")
	if l, _, ok := SplitAddress(a); !ok || l != ReportLocal || !ValidAddress(a) {
		return ""
	}
	return a
}

// SetReportAddress chooses the report mailbox (an existing dmarc@ mailbox
// of a panel mail domain; "" stops collecting). Every domain's _dmarc
// record then carries rua=mailto:<addr>.
func (s *Service) SetReportAddress(ctx context.Context, addr string) error {
	addr = NormalizeAddress(addr)
	if addr != "" {
		if l, _, ok := SplitAddress(addr); !ok || l != ReportLocal {
			return fmt.Errorf("rapor kutusu %s@<alan adı> olmalı", ReportLocal)
		}
		s.mu.Lock()
		_, _, err := s.mailbox(ctx, addr)
		s.mu.Unlock()
		if err != nil {
			return fmt.Errorf("%s: %w (önce bu posta kutusunu oluşturun)", addr, err)
		}
	}
	if err := store.SetSetting(ctx, s.DB, settingReportAdr, addr); err != nil {
		return err
	}
	s.changedAll(ctx)
	return nil
}

// SetDMARCPolicy changes the published policy of a domain.
func (s *Service) SetDMARCPolicy(ctx context.Context, domainID int64, policy string) error {
	if !ValidDMARCPolicy(policy) {
		return errors.New("geçersiz DMARC politikası")
	}
	d, err := s.Store.Domain(ctx, domainID)
	if err != nil {
		return errors.New("alan adı bulunamadı")
	}
	if err := s.Store.SetDMARCPolicy(ctx, d.ID, policy); err != nil {
		return err
	}
	s.changed(ctx, d.Name)
	return nil
}

func (s *Service) changedAll(ctx context.Context) {
	ds, _ := s.Store.Domains(ctx, 0)
	names := make([]string, 0, len(ds)+1)
	for _, d := range ds {
		names = append(names, d.Name)
	}
	if h := s.Host(ctx); h != "" {
		names = append(names, h)
	}
	s.changed(ctx, names...)
}

// SyncResult tells what one report sync did.
type SyncResult struct {
	Files, Parsed, Failed, Reports int
}

// SyncReports copies the report mailbox (root) and parses the new copies.
// Only one sync runs at a time (the files are processed sequentially, so
// memory stays at one message).
func (s *Service) SyncReports(ctx context.Context) (SyncResult, error) {
	var res SyncResult
	addr := s.ReportAddress(ctx)
	if addr == "" {
		return res, errors.New("DMARC rapor kutusu seçilmedi")
	}
	if !s.syncMu.TryLock() {
		return res, errors.New("raporlar zaten işleniyor")
	}
	defer s.syncMu.Unlock()
	if _, err := s.helper(ctx, nil, nil, nil, 5*time.Minute, "dmarc-sync", addr); err != nil {
		return res, err
	}
	dir := s.ReportsDir
	if dir == "" {
		dir = ReportsDir
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return res, nil
		}
		return res, err
	}
	now := time.Now()
	for _, e := range entries {
		if !e.Type().IsRegular() || strings.HasPrefix(e.Name(), ".") {
			continue
		}
		res.Files++
		if seen, _ := s.Store.ReportFileSeen(ctx, e.Name()); seen {
			continue
		}
		status, detail, n := s.parseReportFile(ctx, filepath.Join(dir, e.Name()))
		if status == "error" {
			res.Failed++
		} else {
			res.Parsed++
		}
		res.Reports += n
		s.Store.MarkReportFile(ctx, e.Name(), now, status, detail)
		if ctx.Err() != nil {
			return res, ctx.Err()
		}
	}
	s.Store.PurgeReports(ctx, now.Add(-reportKeep))
	return res, nil
}

func (s *Service) parseReportFile(ctx context.Context, path string) (status, detail string, n int) {
	f, err := os.Open(path)
	if err != nil {
		return "error", err.Error(), 0
	}
	defer f.Close()
	fbs, err := ParseReportMail(f)
	if err != nil && len(fbs) == 0 {
		if err.Error() == "ekte DMARC raporu yok" {
			return "skipped", err.Error(), 0
		}
		return "error", clean(err.Error(), 300), 0
	}
	for _, fb := range fbs {
		ok, ierr := s.Store.InsertReport(ctx, fb)
		if ierr != nil {
			return "error", clean(ierr.Error(), 300), n
		}
		if ok {
			n++
		}
	}
	return "ok", "", n
}

// DMARCSource is one sending IP for a domain over the period.
type DMARCSource struct {
	IP                string
	Count, Pass       int64
	DKIMPass, SPFPass int64
}

// Failing is the number of messages that failed DMARC.
func (x DMARCSource) Failing() int64 { return x.Count - x.Pass }

// DMARCSummary aggregates one domain's reports since a time.
type DMARCSummary struct {
	Domain                 string
	Reports                int
	Total, Pass, DKIM, SPF int64
	Sources                []DMARCSource // most messages first, at most 20
	Orgs                   []string
}

// PassPct is the DMARC pass share (0–100).
func (d DMARCSummary) PassPct() int { return pct(d.Pass, d.Total) }

// DKIMPct and SPFPct are the aligned pass shares.
func (d DMARCSummary) DKIMPct() int { return pct(d.DKIM, d.Total) }
func (d DMARCSummary) SPFPct() int  { return pct(d.SPF, d.Total) }

func pct(a, b int64) int {
	if b <= 0 {
		return 0
	}
	return int(a * 100 / b)
}

// DMARCSummaries returns one summary per reported domain since t.
func (s *Service) DMARCSummaries(ctx context.Context, since time.Time) ([]DMARCSummary, error) {
	out, err := s.Store.ReportSummaries(ctx, since)
	sort.Slice(out, func(i, j int) bool { return out[i].Domain < out[j].Domain })
	return out, err
}

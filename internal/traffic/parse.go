// Package traffic turns a site's nginx access log (default "combined"
// format) into daily statistics: requests, bandwidth, unique visitors, bot
// requests, status classes and top pages. Complete days are stored in
// traffic_daily by the daily maintenance (logrotate keeps ~14 days of raw
// logs); today is computed when the page is opened. No background work.
package traffic

import (
	"bufio"
	"bytes"
	"compress/gzip"
	"errors"
	"io"
	"os"
	"sort"
	"strconv"
	"strings"
	"time"
)

// Limits that keep one scan's memory bounded on busy sites.
const (
	maxIPs      = 200_000 // distinct visitors tracked per day ("200000+" after)
	maxPaths    = 5_000   // distinct pages tracked per day (rest → OtherPath)
	maxLine     = 16 << 10
	maxPathLen  = 200
	TopN        = 10
	OtherPath   = "(diğer)"
	maxRotated  = 30
	dayLayout   = "2006-01-02"
	MaxBackfill = 13 // days before today that rotated logs reliably cover
)

// PathCount is one row of the top pages list.
type PathCount struct {
	Path  string `json:"p"`
	Count int64  `json:"n"`
}

// Day is one day's statistics for one site.
type Day struct {
	Day      string // YYYY-MM-DD (server local time, as nginx writes it)
	Requests int64  // all requests (bots included)
	Bytes    int64  // response body bytes
	Visitors int64  // distinct client IPs of non-bot requests
	Bots     int64
	S2, S3   int64
	S4, S5   int64
	Top      []PathCount // non-bot pages, static assets excluded
	Capped   bool        // visitor or page tracking hit its limit
}

// Errors5xxPct is the share of 5xx responses (0–100).
func (d Day) Errors5xxPct() float64 {
	if d.Requests == 0 {
		return 0
	}
	return float64(d.S5) * 100 / float64(d.Requests)
}

// Entry is one parsed access log line.
type Entry struct {
	IP     string
	Day    string
	Path   string
	Status int
	Bytes  int64
	Bot    bool
}

var months = map[string]string{"Jan": "01", "Feb": "02", "Mar": "03", "Apr": "04", "May": "05", "Jun": "06",
	"Jul": "07", "Aug": "08", "Sep": "09", "Oct": "10", "Nov": "11", "Dec": "12"}

// ParseLine parses a "combined" line:
//
//	1.2.3.4 - - [11/Nov/2026:18:00:00 +0300] "GET /a?b HTTP/1.1" 200 512 "ref" "agent"
//
// ok is false for lines that are not in that format.
func ParseLine(line string) (e Entry, ok bool) {
	sp := strings.IndexByte(line, ' ')
	if sp <= 0 {
		return e, false
	}
	e.IP = line[:sp]
	lb := strings.IndexByte(line, '[')
	if lb < 0 || len(line) < lb+12 {
		return e, false
	}
	ts := line[lb+1 : lb+12] // 11/Nov/2026
	mon, okm := months[ts[3:6]]
	if !okm || ts[2] != '/' || ts[6] != '/' || !digits(ts[0:2]) || !digits(ts[7:11]) {
		return e, false
	}
	e.Day = ts[7:11] + "-" + mon + "-" + ts[0:2]
	rest := line[lb+12:]
	q := strings.Index(rest, "] \"")
	if q < 0 {
		return e, false
	}
	rest = rest[q+3:]
	endReq := strings.IndexByte(rest, '"')
	if endReq < 0 {
		return e, false
	}
	req := rest[:endReq]
	rest = strings.TrimPrefix(rest[endReq+1:], " ")
	// status and bytes
	f1 := strings.IndexByte(rest, ' ')
	if f1 < 0 {
		return e, false
	}
	st, err := strconv.Atoi(rest[:f1])
	if err != nil || st < 100 || st > 999 {
		return e, false
	}
	e.Status = st
	rest = rest[f1+1:]
	f2 := strings.IndexByte(rest, ' ')
	if f2 < 0 {
		f2 = len(rest)
	}
	e.Bytes, _ = strconv.ParseInt(rest[:f2], 10, 64)
	// path: second field of the request line, without the query string
	if a := strings.IndexByte(req, ' '); a > 0 {
		p := req[a+1:]
		if b := strings.IndexByte(p, ' '); b >= 0 {
			p = p[:b]
		}
		if c := strings.IndexAny(p, "?#"); c >= 0 {
			p = p[:c]
		}
		if strings.HasPrefix(p, "/") && len(p) <= maxPathLen && printable(p) {
			e.Path = p
		}
	}
	// user agent: the last quoted field
	if rest = rest[f2:]; strings.HasSuffix(rest, "\"") {
		if i := strings.LastIndex(rest[:len(rest)-1], "\""); i >= 0 {
			e.Bot = IsBot(rest[i+1 : len(rest)-1])
		}
	}
	return e, true
}

func digits(s string) bool {
	for i := 0; i < len(s); i++ {
		if s[i] < '0' || s[i] > '9' {
			return false
		}
	}
	return true
}

func printable(s string) bool {
	for i := 0; i < len(s); i++ {
		if s[i] < 0x21 || s[i] > 0x7e {
			return false
		}
	}
	return true
}

var botWords = []string{"bot", "crawl", "spider", "slurp", "curl/", "wget/", "python-requests", "go-http-client", "headless", "monitor"}

// IsBot classifies a user agent (empty and "-" count as bots: browsers
// always send one).
func IsBot(ua string) bool {
	if ua == "" || ua == "-" {
		return true
	}
	l := strings.ToLower(ua)
	for _, w := range botWords {
		if strings.Contains(l, w) {
			return true
		}
	}
	return false
}

var assetExt = []string{".css", ".js", ".mjs", ".map", ".png", ".jpg", ".jpeg", ".gif", ".svg", ".ico", ".webp", ".avif",
	".woff", ".woff2", ".ttf", ".eot", ".otf", ".mp4", ".webm", ".json", ".xml", ".txt"}

func isAsset(p string) bool {
	l := strings.ToLower(p)
	for _, x := range assetExt {
		if strings.HasSuffix(l, x) {
			return true
		}
	}
	return false
}

// skip reports lines that are not visitor traffic: local requests (the
// panel's health checks go through nginx from 127.0.0.1), ACME challenges
// and the panel's DNS probe.
func skip(e Entry) bool {
	if e.IP == "127.0.0.1" || e.IP == "::1" {
		return true
	}
	return strings.HasPrefix(e.Path, "/.well-known/acme-challenge/") || e.Path == "/.well-known/hostpanel-probe"
}

// agg accumulates one day.
type agg struct {
	d      Day
	ips    map[string]struct{}
	paths  map[string]int64
	capped bool
}

func newAgg(day string) *agg {
	return &agg{d: Day{Day: day}, ips: map[string]struct{}{}, paths: map[string]int64{}}
}

func (a *agg) add(e Entry) {
	a.d.Requests++
	a.d.Bytes += e.Bytes
	switch e.Status / 100 {
	case 2:
		a.d.S2++
	case 3:
		a.d.S3++
	case 4:
		a.d.S4++
	case 5:
		a.d.S5++
	}
	if e.Bot {
		a.d.Bots++
		return
	}
	if _, ok := a.ips[e.IP]; !ok {
		if len(a.ips) < maxIPs {
			a.ips[e.IP] = struct{}{}
		} else {
			a.capped = true
		}
	}
	if e.Path == "" || isAsset(e.Path) || e.Status >= 400 {
		return
	}
	if _, ok := a.paths[e.Path]; ok || len(a.paths) < maxPaths {
		a.paths[e.Path]++
	} else {
		a.paths[OtherPath]++
		a.capped = true
	}
}

func (a *agg) day() Day {
	d := a.d
	d.Visitors = int64(len(a.ips))
	d.Capped = a.capped
	d.Top = topPaths(a.paths, TopN)
	return d
}

func topPaths(m map[string]int64, n int) []PathCount {
	out := make([]PathCount, 0, len(m))
	for p, c := range m {
		out = append(out, PathCount{p, c})
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Count != out[j].Count {
			return out[i].Count > out[j].Count
		}
		return out[i].Path < out[j].Path
	})
	if len(out) > n {
		out = out[:n]
	}
	return out
}

// logFile is one access log, current or rotated.
type logFile struct {
	path  string
	mtime time.Time
	gz    bool
}

// files lists base, base.1, base.2.gz, … (newest first; logrotate's
// delaycompress leaves .1 uncompressed).
func files(base string) []logFile {
	var out []logFile
	for i := 0; i <= maxRotated; i++ {
		p := base
		if i > 0 {
			p = base + "." + strconv.Itoa(i)
		}
		for _, cand := range []logFile{{path: p}, {path: p + ".gz", gz: true}} {
			if i == 0 && cand.gz {
				continue
			}
			if fi, err := os.Stat(cand.path); err == nil && fi.Mode().IsRegular() {
				cand.mtime = fi.ModTime()
				out = append(out, cand)
				break
			}
		}
	}
	return out
}

// Scan aggregates the days in want from base and its rotated copies.
// Files whose last write is before oldest cannot contain a wanted day and
// end the scan.
func Scan(base string, want map[string]bool, oldest time.Time) (map[string]Day, error) {
	aggs := map[string]*agg{}
	var firstErr error
	for _, f := range files(base) {
		if f.mtime.Before(oldest) {
			break
		}
		if err := scanFile(f, want, aggs); err != nil && firstErr == nil {
			firstErr = err
		}
	}
	out := make(map[string]Day, len(aggs))
	for k, a := range aggs {
		out[k] = a.day()
	}
	return out, firstErr
}

func scanFile(f logFile, want map[string]bool, aggs map[string]*agg) error {
	fh, err := os.Open(f.path)
	if err != nil {
		return err
	}
	defer fh.Close()
	var r io.Reader = fh
	if f.gz {
		zr, err := gzip.NewReader(fh)
		if err != nil {
			return err
		}
		defer zr.Close()
		r = zr
	}
	return scanReader(r, want, aggs)
}

func scanReader(r io.Reader, want map[string]bool, aggs map[string]*agg) error {
	br := bufio.NewReaderSize(r, 64<<10)
	for {
		line, err := br.ReadSlice('\n')
		if errors.Is(err, bufio.ErrBufferFull) {
			// over-long line: skip the rest of it
			for errors.Is(err, bufio.ErrBufferFull) {
				_, err = br.ReadSlice('\n')
			}
			if err != nil && !errors.Is(err, io.EOF) {
				return err
			}
			continue
		}
		if len(line) > 0 && len(line) <= maxLine {
			if e, ok := ParseLine(string(bytes.TrimRight(line, "\r\n"))); ok && want[e.Day] && !skip(e) {
				a := aggs[e.Day]
				if a == nil {
					a = newAgg(e.Day)
					aggs[e.Day] = a
				}
				a.add(e)
			}
		}
		if err != nil {
			if errors.Is(err, io.EOF) {
				return nil
			}
			return err
		}
	}
}

// DayKey formats t as a traffic day.
func DayKey(t time.Time) string { return t.Format(dayLayout) }

// ParseDay parses a day key in loc.
func ParseDay(s string, loc *time.Location) (time.Time, error) {
	return time.ParseInLocation(dayLayout, s, loc)
}

package logs

import (
	"bufio"
	"os"
	"strings"
	"time"
)

// LineTime extracts the timestamp at the start of a log line in the formats
// the Log Center shows: RFC 3339 (panel auth.log, journal short-iso, Ubuntu
// 24.04 syslog files), the panel's JSON "time" field, nginx access
// ("[02/Jan/2006:15:04:05 -0700]"), nginx error / rclone ("2006/01/02 15:04:05",
// local time), fail2ban ("2006-01-02 15:04:05,000") and classic syslog
// ("Jan _2 15:04:05", year taken from now).
func LineTime(line string, now time.Time) (time.Time, bool) {
	if strings.HasPrefix(line, "{") {
		if _, rest, ok := strings.Cut(line, `"time":"`); ok {
			if v, _, ok := strings.Cut(rest, `"`); ok {
				return parseAny(v, rfcLayouts)
			}
		}
		return time.Time{}, false
	}
	if i := strings.IndexByte(line, '['); i >= 0 && i < 64 {
		if v, _, ok := strings.Cut(line[i+1:], "]"); ok {
			if t, err := time.Parse("02/Jan/2006:15:04:05 -0700", v); err == nil {
				return t, true
			}
		}
	}
	first, _, _ := strings.Cut(line, " ")
	if t, ok := parseAny(first, rfcLayouts); ok {
		return t, true
	}
	if len(line) >= 19 {
		for _, l := range localLayouts {
			if t, err := time.ParseInLocation(l, line[:19], time.Local); err == nil {
				return t, true
			}
		}
	}
	if len(line) >= 15 {
		if t, err := time.ParseInLocation(time.Stamp, line[:15], time.Local); err == nil {
			t = t.AddDate(now.Year(), 0, 0)
			if t.After(now.Add(24 * time.Hour)) { // December lines read in January
				t = t.AddDate(-1, 0, 0)
			}
			return t, true
		}
	}
	return time.Time{}, false
}

var rfcLayouts = []string{time.RFC3339Nano, "2006-01-02T15:04:05.999999999-0700"}

var localLayouts = []string{"2006/01/02 15:04:05", "2006-01-02 15:04:05"}

func parseAny(v string, layouts []string) (time.Time, bool) {
	for _, l := range layouts {
		if t, err := time.Parse(l, v); err == nil {
			return t, true
		}
	}
	return time.Time{}, false
}

// InRange reports whether line falls in [since, until]; zero bounds are open.
// Lines without a timestamp (stack traces, continuation lines) follow the
// previous line's decision, tracked in *prev.
func InRange(line string, since, until, now time.Time, prev *bool) bool {
	t, ok := LineTime(line, now)
	if !ok {
		return *prev
	}
	in := (since.IsZero() || !t.Before(since)) && (until.IsZero() || !t.After(until))
	*prev = in
	return in
}

// ScanLines reads path from the start and returns the last n lines for which
// keep returns true. Memory stays bounded by n, so whole (rotated) log files
// can be searched.
func ScanLines(path string, n int, keep func(string) bool) ([]string, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	ring := make([]string, 0, n)
	start := 0
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 64<<10), 1<<20)
	for sc.Scan() {
		l := sc.Text()
		if !keep(l) {
			continue
		}
		if len(ring) < n {
			ring = append(ring, l)
			continue
		}
		ring[start] = l
		start = (start + 1) % n
	}
	out := append(ring[start:len(ring):len(ring)], ring[:start]...)
	return out, sc.Err()
}

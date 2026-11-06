package logs

import (
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"
)

func TestLineTime(t *testing.T) {
	now := time.Date(2026, 1, 3, 12, 0, 0, 0, time.Local)
	loc := func(y int, m time.Month, d, h, mi, s int) time.Time {
		return time.Date(y, m, d, h, mi, s, 0, time.Local)
	}
	cases := []struct {
		line string
		want time.Time
	}{
		{"2026-11-05T12:00:00Z hostpanel: login failed ip=1.2.3.4", time.Date(2026, 11, 5, 12, 0, 0, 0, time.UTC)},
		{`{"time":"2026-11-05T15:00:00.123+03:00","level":"INFO","msg":"x"}`, time.Date(2026, 11, 5, 12, 0, 0, 123e6, time.UTC)},
		{"2026-11-05T15:00:00+0300 host hp-site-x[12]: started", time.Date(2026, 11, 5, 12, 0, 0, 0, time.UTC)},
		{`203.0.113.9 - - [05/Nov/2026:15:00:00 +0300] "GET / HTTP/1.1" 200 12`, time.Date(2026, 11, 5, 12, 0, 0, 0, time.UTC)},
		{"2026/11/05 15:00:00 [error] 123#123: *1 connect() failed", loc(2026, 11, 5, 15, 0, 0)},
		{"2026/11/05 15:00:00 INFO  : file.txt: Copied (new)", loc(2026, 11, 5, 15, 0, 0)},
		{"2026-11-05 15:00:00,123 fail2ban.actions [1]: NOTICE [sshd] Ban 192.0.2.1", loc(2026, 11, 5, 15, 0, 0)},
		{"Jan  2 08:00:00 host sshd[1]: Accepted publickey", loc(2026, 1, 2, 8, 0, 0)},
		{"Dec 31 23:00:00 host sshd[1]: Accepted publickey", loc(2025, 12, 31, 23, 0, 0)},
	}
	for _, c := range cases {
		got, ok := LineTime(c.line, now)
		if !ok || !got.Equal(c.want) {
			t.Errorf("%q → %v %v, want %v", c.line, got, ok, c.want)
		}
	}
	for _, l := range []string{"", "   at Foo.Bar()", "renewed example.com", "{\"msg\":\"no time\"}"} {
		if _, ok := LineTime(l, now); ok {
			t.Errorf("%q parsed", l)
		}
	}
}

func TestInRangeAndScan(t *testing.T) {
	var b strings.Builder
	for h := 0; h < 24; h++ {
		b.WriteString("2026-11-05T" + pad(h) + ":00:00Z line " + strconv.Itoa(h) + "\n")
		b.WriteString("    continuation " + strconv.Itoa(h) + "\n")
	}
	path := filepath.Join(t.TempDir(), "x.log")
	os.WriteFile(path, []byte(b.String()), 0o644)
	since := time.Date(2026, 11, 5, 10, 0, 0, 0, time.UTC)
	until := time.Date(2026, 11, 5, 12, 0, 0, 0, time.UTC)
	prev := true
	now := time.Now()
	got, err := ScanLines(path, 100, func(l string) bool { return InRange(l, since, until, now, &prev) })
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 6 || !strings.Contains(got[0], "line 10") || !strings.Contains(got[5], "continuation 12") {
		t.Fatalf("%q", got)
	}
	// Ring buffer keeps the last n matches in order.
	got, _ = ScanLines(path, 3, func(l string) bool { return strings.Contains(l, "line") })
	if len(got) != 3 || !strings.HasSuffix(got[0], "line 21") || !strings.HasSuffix(got[2], "line 23") {
		t.Fatalf("%q", got)
	}
}

func pad(n int) string {
	if n < 10 {
		return "0" + strconv.Itoa(n)
	}
	return strconv.Itoa(n)
}

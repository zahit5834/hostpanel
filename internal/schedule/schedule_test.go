package schedule

import (
	"testing"
	"time"
)

func TestScheduleCron(t *testing.T) {
	cases := []struct {
		in   Schedule
		want string
	}{
		{Schedule{Kind: "daily", Hour: 3, Minute: 30}, "30 3 * * *"},
		{Schedule{Kind: "weekly", Hour: 1, Weekday: 0}, "0 1 * * 0"},
		{Schedule{Kind: "monthly", Hour: 4, Minute: 5, Day: 28}, "5 4 28 * *"},
		{Schedule{Kind: "custom", Expr: "  15  2 * *   1-5 "}, "15 2 * * 1-5"},
	}
	for _, c := range cases {
		got, err := c.in.Cron()
		if err != nil || got != c.want {
			t.Errorf("%+v: got %q, %v; want %q", c.in, got, err, c.want)
		}
		if back := ScheduleOf(got); c.in.Kind != "custom" && (back.Kind != c.in.Kind || back.Hour != c.in.Hour || back.Minute != c.in.Minute) {
			t.Errorf("ScheduleOf(%q) = %+v", got, back)
		}
	}
	for _, bad := range []Schedule{
		{Kind: "daily", Hour: 24}, {Kind: "monthly", Hour: 1, Day: 31}, {Kind: "weekly", Weekday: 7},
		{Kind: "custom", Expr: "@every 1m"}, {Kind: "custom", Expr: "@daily"}, {Kind: "custom", Expr: "TZ=UTC 0 3 * * *"},
		{Kind: "custom", Expr: "0 0 3 * * *"}, {Kind: "custom", Expr: "61 3 * * *"}, {Kind: "hourly"},
	} {
		if expr, err := bad.Cron(); err == nil {
			t.Errorf("%+v accepted as %q", bad, expr)
		}
	}
}

func TestNextRun(t *testing.T) {
	loc := time.Local
	at := func(y int, m time.Month, d, h, min int) time.Time { return time.Date(y, m, d, h, min, 0, 0, loc) }
	cases := []struct {
		expr     string
		from     time.Time
		expected time.Time
	}{
		{"0 3 * * *", at(2026, 11, 5, 2, 59), at(2026, 11, 5, 3, 0)},
		{"0 3 * * *", at(2026, 11, 5, 3, 0), at(2026, 11, 6, 3, 0)}, // strictly after
		{"0 3 28 * *", at(2026, 2, 28, 4, 0), at(2026, 3, 28, 3, 0)},
		{"30 1 * * 0", at(2026, 11, 5, 12, 0), at(2026, 11, 8, 1, 30)}, // Thursday → Sunday
		{"0 0 31 12 *", at(2026, 12, 31, 0, 1), at(2027, 12, 31, 0, 0)},
	}
	for _, c := range cases {
		got, err := NextRun(c.expr, c.from)
		if err != nil || !got.Equal(c.expected) {
			t.Errorf("NextRun(%q, %v) = %v, %v; want %v", c.expr, c.from, got, err, c.expected)
		}
	}
	if Describe("30 1 * * 0") != "Her Pazar 01:30" || Describe("5 4 28 * *") != "Her ayın 28. günü 04:05" {
		t.Errorf("Describe: %q / %q", Describe("30 1 * * 0"), Describe("5 4 28 * *"))
	}
	for expr, want := range map[string]string{"* * * * *": "Her dakika", "*/5 * * * *": "5 dakikada bir", "7 * * * *": "Her saat başı :07"} {
		if got := Describe(expr); got != want {
			t.Errorf("Describe(%q) = %q, want %q", expr, got, want)
		}
	}
}

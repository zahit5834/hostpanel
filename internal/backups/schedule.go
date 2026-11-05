package backups

import (
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/robfig/cron/v3"
)

// Schedule is the plan form's schedule: a preset or a custom cron expression.
type Schedule struct {
	Kind    string // daily | weekly | monthly | custom
	Hour    int
	Minute  int
	Weekday int // 0 = Sunday (weekly)
	Day     int // 1–28 (monthly; 29–31 would skip short months)
	Expr    string
}

// Cron returns the 5-field expression for the schedule.
func (s Schedule) Cron() (string, error) {
	if s.Kind != "custom" && (s.Hour < 0 || s.Hour > 23 || s.Minute < 0 || s.Minute > 59) {
		return "", errors.New("geçersiz saat")
	}
	var expr string
	switch s.Kind {
	case "daily":
		expr = fmt.Sprintf("%d %d * * *", s.Minute, s.Hour)
	case "weekly":
		if s.Weekday < 0 || s.Weekday > 6 {
			return "", errors.New("geçersiz gün")
		}
		expr = fmt.Sprintf("%d %d * * %d", s.Minute, s.Hour, s.Weekday)
	case "monthly":
		if s.Day < 1 || s.Day > 28 {
			return "", errors.New("ayın günü 1–28 olmalı")
		}
		expr = fmt.Sprintf("%d %d %d * *", s.Minute, s.Hour, s.Day)
	case "custom":
		expr = strings.Join(strings.Fields(s.Expr), " ")
	default:
		return "", errors.New("geçersiz zamanlama")
	}
	if _, err := parse(expr); err != nil {
		return "", err
	}
	return expr, nil
}

var parser = cron.NewParser(cron.Minute | cron.Hour | cron.Dom | cron.Month | cron.Dow)

// parse accepts only plain 5-field expressions (no @every/descriptors, no
// TZ= prefix: plans run in the server's local time).
func parse(expr string) (cron.Schedule, error) {
	if len(strings.Fields(expr)) != 5 || strings.ContainsAny(expr, "@=") {
		return nil, errors.New("cron ifadesi 5 alanlı olmalı (dakika saat gün ay haftanın-günü)")
	}
	s, err := parser.Parse(expr)
	if err != nil {
		return nil, fmt.Errorf("geçersiz cron ifadesi: %v", err)
	}
	return s, nil
}

// NextRun is the first run strictly after t.
func NextRun(expr string, t time.Time) (time.Time, error) {
	s, err := parse(expr)
	if err != nil {
		return time.Time{}, err
	}
	n := s.Next(t)
	if n.IsZero() {
		return n, errors.New("bu ifade hiçbir zaman çalışmaz")
	}
	return n, nil
}

// ScheduleOf turns a stored expression back into form values.
func ScheduleOf(expr string) Schedule {
	f := strings.Fields(expr)
	if len(f) == 5 {
		min, e1 := strconv.Atoi(f[0])
		hour, e2 := strconv.Atoi(f[1])
		if e1 == nil && e2 == nil {
			switch {
			case f[2] == "*" && f[3] == "*" && f[4] == "*":
				return Schedule{Kind: "daily", Hour: hour, Minute: min}
			case f[2] == "*" && f[3] == "*":
				if wd, err := strconv.Atoi(f[4]); err == nil && wd >= 0 && wd <= 6 {
					return Schedule{Kind: "weekly", Hour: hour, Minute: min, Weekday: wd}
				}
			case f[3] == "*" && f[4] == "*":
				if d, err := strconv.Atoi(f[2]); err == nil && d >= 1 && d <= 28 {
					return Schedule{Kind: "monthly", Hour: hour, Minute: min, Day: d}
				}
			}
		}
	}
	return Schedule{Kind: "custom", Expr: expr, Hour: 3}
}

// Weekdays in Turkish, Sunday first (cron numbering).
var Weekdays = []string{"Pazar", "Pazartesi", "Salı", "Çarşamba", "Perşembe", "Cuma", "Cumartesi"}

// Describe renders the schedule in Turkish.
func Describe(expr string) string {
	s := ScheduleOf(expr)
	at := fmt.Sprintf("%02d:%02d", s.Hour, s.Minute)
	switch s.Kind {
	case "daily":
		return "Her gün " + at
	case "weekly":
		return "Her " + Weekdays[s.Weekday] + " " + at
	case "monthly":
		return fmt.Sprintf("Her ayın %d. günü %s", s.Day, at)
	}
	return "Özel: " + expr
}

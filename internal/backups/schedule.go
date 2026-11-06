package backups

import "github.com/zahit5834/hostpanel/internal/schedule"

// Aliases kept so backup code and templates read as before; the parser lives
// in internal/schedule (shared with site crons).
type Schedule = schedule.Schedule

var (
	NextRun    = schedule.NextRun
	ScheduleOf = schedule.ScheduleOf
	Describe   = schedule.Describe
	Weekdays   = schedule.Weekdays
)

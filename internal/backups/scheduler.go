package backups

import (
	"context"
	"time"
)

// maxSleep bounds one scheduler sleep so wall-clock jumps (NTP, DST) are
// noticed within a few hours instead of after a long monotonic timer.
const maxSleep = 6 * time.Hour

// Reschedule wakes the scheduler after a plan changed.
func (s *Service) Reschedule() {
	select {
	case s.wake <- struct{}{}:
	default:
	}
}

// RunScheduler sleeps on a single timer until the earliest due plan, submits
// it and repeats. It returns when ctx is cancelled.
func (s *Service) RunScheduler(ctx context.Context) {
	for {
		next := s.RunDue(ctx, s.now())
		d := maxSleep
		if !next.IsZero() {
			d = min(max(time.Until(next), time.Second), maxSleep)
		}
		t := time.NewTimer(d)
		select {
		case <-ctx.Done():
			t.Stop()
			return
		case <-t.C:
		case <-s.wake:
			t.Stop()
		}
	}
}

// RunDue submits every enabled plan whose time has come (a run missed while
// the panel was down runs once) and returns the earliest next run.
func (s *Service) RunDue(ctx context.Context, now time.Time) time.Time {
	plans, err := s.Store.Plans(ctx)
	if err != nil {
		if ctx.Err() == nil {
			s.Log.Error("backup scheduler", "err", err)
		}
		return now.Add(time.Minute)
	}
	var earliest time.Time
	for _, p := range plans {
		if !p.Enabled {
			continue
		}
		next := p.NextRunAt
		if next.IsZero() || !next.After(now) {
			if !next.IsZero() {
				if _, err := s.submitPlan(ctx, p, "zamanlanmış"); err != nil {
					s.Log.Warn("backup plan not started", "plan", p.Name, "err", err)
				}
			}
			n, err := NextRun(p.Schedule, now)
			if err != nil {
				continue
			}
			s.Store.SetPlanNext(ctx, p.ID, n)
			next = n
		}
		if earliest.IsZero() || next.Before(earliest) {
			earliest = next
		}
	}
	return earliest
}

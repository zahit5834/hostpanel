package sites

import (
	"context"
	"time"

	"github.com/zahit5834/hostpanel/internal/jobs"
)

// saga runs provisioning steps and, on failure, undoes the completed ones in
// reverse order. Undo runs on a fresh context so a canceled job still cleans up.
type saga struct {
	log  *jobs.Log
	undo []undoStep
}

type undoStep struct {
	name string
	fn   func(ctx context.Context) error
}

// step runs do; if it succeeds and undo is non-nil, undo is remembered.
func (s *saga) step(name string, do func() error, undo func(ctx context.Context) error) error {
	s.log.Printf("→ %s", name)
	if err := do(); err != nil {
		s.log.Printf("✗ %s: %v", name, err)
		return err
	}
	if undo != nil {
		s.undo = append(s.undo, undoStep{name: name, fn: undo})
	}
	return nil
}

// rollback undoes completed steps, newest first. Errors are logged, not returned:
// every undo is attempted.
func (s *saga) rollback() {
	if len(s.undo) == 0 {
		return
	}
	s.log.Printf("Geri alınıyor (%d adım)…", len(s.undo))
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	for i := len(s.undo) - 1; i >= 0; i-- {
		u := s.undo[i]
		if err := u.fn(ctx); err != nil {
			s.log.Printf("  geri alma başarısız (%s): %v", u.name, err)
		} else {
			s.log.Printf("  geri alındı: %s", u.name)
		}
	}
}

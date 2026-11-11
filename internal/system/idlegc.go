package system

import (
	"runtime/debug"
	"sync"
	"time"
)

// IdleGC hands freed memory back to the OS once the panel has been quiet
// for Delay: without it the garbage of the last page renders or jobs stays
// resident until the next GC cycle, which an idle panel never reaches (the
// live heap is ~2 MB, the idle RSS was ~3–5 MB higher). The timer exists
// only after activity; there is no periodic wake-up.
type IdleGC struct {
	Delay time.Duration
	Free  func() // debug.FreeOSMemory by default (tests)

	mu sync.Mutex
	t  *time.Timer
}

// Touch (re)arms the timer; call it when a request or job finishes.
func (g *IdleGC) Touch() {
	if g == nil {
		return
	}
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.t == nil {
		g.t = time.AfterFunc(g.Delay, g.run)
		return
	}
	g.t.Reset(g.Delay)
}

func (g *IdleGC) run() {
	if g.Free != nil {
		g.Free()
		return
	}
	debug.FreeOSMemory()
}

// Stop cancels a pending release (shutdown).
func (g *IdleGC) Stop() {
	if g == nil {
		return
	}
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.t != nil {
		g.t.Stop()
	}
}

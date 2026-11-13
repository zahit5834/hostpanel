package system

import (
	"sync/atomic"
	"testing"
	"time"
)

func TestIdleGC(t *testing.T) {
	var n atomic.Int32
	g := &IdleGC{Delay: 30 * time.Millisecond, Free: func() { n.Add(1) }}
	for i := 0; i < 5; i++ { // activity keeps pushing the release back
		g.Touch()
		time.Sleep(10 * time.Millisecond)
	}
	if n.Load() != 0 {
		t.Fatal("released while busy")
	}
	time.Sleep(80 * time.Millisecond)
	if n.Load() != 1 {
		t.Fatalf("released %d times", n.Load())
	}
	time.Sleep(60 * time.Millisecond)
	if n.Load() != 1 {
		t.Fatal("periodic release without activity")
	}
	g.Touch()
	g.Stop()
	time.Sleep(60 * time.Millisecond)
	if n.Load() != 1 {
		t.Fatal("released after Stop")
	}
	var nilGC *IdleGC
	nilGC.Touch()
}

func TestPageOutBinary(t *testing.T) {
	// The test binary's own read-only mappings are advised; the process keeps
	// running (pages fault back in), which is the point.
	if n := PageOutBinary(); n <= 0 {
		t.Fatalf("PageOutBinary = %d, want > 0", n)
	}
	if n := PageOutBinary(); n <= 0 { // idempotent
		t.Fatalf("second PageOutBinary = %d", n)
	}
}

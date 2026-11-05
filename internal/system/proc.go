// Package system reads host metrics directly from /proc and statfs (no external tools).
package system

import (
	"bufio"
	"os"
	"strconv"
	"strings"
	"syscall"
	"time"
)

// Snapshot is the instant host state shown on the dashboard.
type Snapshot struct {
	Hostname   string
	Uptime     time.Duration
	Load1      float64
	Load5      float64
	Load15     float64
	MemTotal   uint64 // bytes
	MemAvail   uint64
	DiskTotal  uint64
	DiskFree   uint64
	PanelRSS   uint64
	Goroutines int
}

// MemUsedPct is the RAM in use as a percentage.
func (s Snapshot) MemUsedPct() int { return pct(s.MemTotal-s.MemAvail, s.MemTotal) }

// DiskUsedPct is the root filesystem usage.
func (s Snapshot) DiskUsedPct() int { return pct(s.DiskTotal-s.DiskFree, s.DiskTotal) }

func pct(a, b uint64) int {
	if b == 0 {
		return 0
	}
	return int(a * 100 / b)
}

// Read collects a snapshot. Missing files yield zero values rather than errors.
func Read() Snapshot {
	var s Snapshot
	s.Hostname, _ = os.Hostname()
	if b, err := os.ReadFile("/proc/uptime"); err == nil {
		if f := strings.Fields(string(b)); len(f) > 0 {
			sec, _ := strconv.ParseFloat(f[0], 64)
			s.Uptime = time.Duration(sec) * time.Second
		}
	}
	if b, err := os.ReadFile("/proc/loadavg"); err == nil {
		if f := strings.Fields(string(b)); len(f) >= 3 {
			s.Load1, _ = strconv.ParseFloat(f[0], 64)
			s.Load5, _ = strconv.ParseFloat(f[1], 64)
			s.Load15, _ = strconv.ParseFloat(f[2], 64)
		}
	}
	mem := readKV("/proc/meminfo")
	s.MemTotal, s.MemAvail = mem["MemTotal"]*1024, mem["MemAvailable"]*1024
	s.PanelRSS = readKV("/proc/self/status")["VmRSS"] * 1024
	var st syscall.Statfs_t
	if syscall.Statfs("/", &st) == nil {
		s.DiskTotal = st.Blocks * uint64(st.Bsize)
		s.DiskFree = st.Bavail * uint64(st.Bsize)
	}
	return s
}

// readKV parses "Key:   123 kB" style files.
func readKV(path string) map[string]uint64 {
	out := map[string]uint64{}
	f, err := os.Open(path)
	if err != nil {
		return out
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		k, v, ok := strings.Cut(sc.Text(), ":")
		if !ok {
			continue
		}
		fields := strings.Fields(v)
		if len(fields) == 0 {
			continue
		}
		if n, err := strconv.ParseUint(fields[0], 10, 64); err == nil {
			out[k] = n
		}
	}
	return out
}

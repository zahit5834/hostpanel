package system

import (
	"bufio"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

// CPUTimes is the aggregate "cpu" line of /proc/stat (clock ticks).
type CPUTimes struct {
	Busy, Total uint64
}

// ProcStatPath is overridable in tests.
var ProcStatPath = "/proc/stat"

// ReadCPU reads the aggregate CPU counters.
func ReadCPU() (CPUTimes, bool) {
	f, err := os.Open(ProcStatPath)
	if err != nil {
		return CPUTimes{}, false
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	if !sc.Scan() {
		return CPUTimes{}, false
	}
	return parseCPULine(sc.Text())
}

func parseCPULine(line string) (CPUTimes, bool) {
	f := strings.Fields(line)
	if len(f) < 5 || f[0] != "cpu" {
		return CPUTimes{}, false
	}
	var t CPUTimes
	for i, v := range f[1:] {
		if i >= 8 { // guest/guest_nice are already included in user/nice
			break
		}
		n, err := strconv.ParseUint(v, 10, 64)
		if err != nil {
			return CPUTimes{}, false
		}
		t.Total += n
		if i != 3 && i != 4 { // idle, iowait
			t.Busy += n
		}
	}
	return t, true
}

// CPUPercent is the busy share between two samples (-1 = unknown).
func CPUPercent(prev, cur CPUTimes) int {
	if cur.Total <= prev.Total || cur.Busy < prev.Busy {
		return -1
	}
	return int((cur.Busy - prev.Busy) * 100 / (cur.Total - prev.Total))
}

// CgroupRoot is overridable in tests.
var CgroupRoot = "/sys/fs/cgroup/system.slice"

// UnitUsage is a systemd service's cgroup counters.
type UnitUsage struct {
	MemBytes uint64
	CPUUsec  uint64
	At       time.Time
	OK       bool
}

// ReadUnit reads memory.current and cpu.stat usage_usec of <unit>.service.
// cgroupfs is world-readable, no privileges needed.
func ReadUnit(unit string) UnitUsage {
	dir := filepath.Join(CgroupRoot, unit+".service")
	u := UnitUsage{At: time.Now()}
	b, err := os.ReadFile(filepath.Join(dir, "memory.current"))
	if err != nil {
		return u
	}
	u.MemBytes, _ = strconv.ParseUint(strings.TrimSpace(string(b)), 10, 64)
	if b, err := os.ReadFile(filepath.Join(dir, "cpu.stat")); err == nil {
		for _, line := range strings.Split(string(b), "\n") {
			if v, ok := strings.CutPrefix(line, "usage_usec "); ok {
				u.CPUUsec, _ = strconv.ParseUint(strings.TrimSpace(v), 10, 64)
			}
		}
	}
	u.OK = true
	return u
}

// UnitCPUPercent is CPU use between two samples as % of one core (-1 = unknown).
func UnitCPUPercent(prev, cur UnitUsage) int {
	el := cur.At.Sub(prev.At).Microseconds()
	if !prev.OK || !cur.OK || el <= 0 || cur.CPUUsec < prev.CPUUsec {
		return -1
	}
	return int((cur.CPUUsec - prev.CPUUsec) * 100 / uint64(el))
}

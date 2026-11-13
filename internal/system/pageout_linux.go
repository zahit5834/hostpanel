//go:build linux

package system

import (
	"bufio"
	"os"
	"strconv"
	"strings"
	"syscall"
)

// madvPageout is MADV_PAGEOUT (Linux 5.4+); not in package syscall.
const madvPageout = 21

// PageOutBinary hands the panel binary's resident code/data pages back to the
// kernel (madvise MADV_PAGEOUT on its file mappings). They are clean and
// file-backed: nothing is written anywhere, the next request faults the pages
// it needs back in from the page cache or disk. An idle panel otherwise keeps
// every page any request ever touched (~19 MB of its RSS). Returns the bytes
// advised; errors (old kernel, unreadable maps) are ignored — it is only a hint.
func PageOutBinary() int64 {
	exe, err := os.Readlink("/proc/self/exe")
	if err != nil {
		return 0
	}
	exe = strings.TrimSuffix(exe, " (deleted)")
	f, err := os.Open("/proc/self/maps")
	if err != nil {
		return 0
	}
	defer f.Close()
	var total int64
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		// start-end perms offset dev inode path
		fields := strings.Fields(sc.Text())
		if len(fields) < 6 || strings.TrimSuffix(strings.Join(fields[5:], " "), " (deleted)") != exe {
			continue
		}
		perms := fields[1]
		if len(perms) < 4 || perms[1] == 'w' || perms[3] != 'p' { // never dirty data pages
			continue
		}
		lo, hi, ok := strings.Cut(fields[0], "-")
		if !ok {
			continue
		}
		start, err1 := strconv.ParseUint(lo, 16, 64)
		end, err2 := strconv.ParseUint(hi, 16, 64)
		if err1 != nil || err2 != nil || end <= start {
			continue
		}
		if _, _, e := syscall.Syscall(syscall.SYS_MADVISE, uintptr(start), uintptr(end-start), madvPageout); e == 0 {
			total += int64(end - start)
		}
	}
	return total
}

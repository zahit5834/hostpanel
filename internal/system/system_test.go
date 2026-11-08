package system

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestCPUPercent(t *testing.T) {
	a, ok := parseCPULine("cpu  100 0 100 700 100 0 0 0 0 0")
	if !ok || a.Total != 1000 || a.Busy != 200 {
		t.Fatalf("%+v %v", a, ok)
	}
	b, _ := parseCPULine("cpu  150 0 150 1500 200 0 0 0 5 5") // guest fields ignored
	if p := CPUPercent(a, b); p != 10 {                       // busy +100 of total +1000
		t.Fatalf("pct %d", p)
	}
	if CPUPercent(b, a) != -1 || CPUPercent(a, a) != -1 {
		t.Fatal("non-increasing samples must be unknown")
	}
	if _, ok := parseCPULine("cpu0 1 2 3 4"); ok {
		t.Fatal("per-core line accepted")
	}
}

func TestReadUnit(t *testing.T) {
	dir := t.TempDir()
	old := CgroupRoot
	CgroupRoot = dir
	t.Cleanup(func() { CgroupRoot = old })
	if ReadUnit("hp-site-x").OK {
		t.Fatal("missing unit reported OK")
	}
	u := filepath.Join(dir, "hp-site-x.service")
	os.MkdirAll(u, 0o755)
	os.WriteFile(filepath.Join(u, "memory.current"), []byte("52428800\n"), 0o644)
	os.WriteFile(filepath.Join(u, "cpu.stat"), []byte("usage_usec 1000000\nuser_usec 800000\n"), 0o644)
	a := ReadUnit("hp-site-x")
	if !a.OK || a.MemBytes != 50<<20 || a.CPUUsec != 1000000 {
		t.Fatalf("%+v", a)
	}
	b := a
	b.At, b.CPUUsec = a.At.Add(2*time.Second), 2000000 // 1 s CPU in 2 s = 50 %
	if p := UnitCPUPercent(a, b); p != 50 {
		t.Fatalf("pct %d", p)
	}
	if UnitCPUPercent(UnitUsage{}, b) != -1 {
		t.Fatal("first sample must be unknown")
	}
}

const ufwOut = `installed=yes
active=yes
protected=22,80,443,2222,8443
---
[ 1] OpenSSH                    ALLOW IN    Anywhere
[ 2] 22/tcp                     ALLOW IN    Anywhere
[ 3] 80,443/tcp                 ALLOW IN    Anywhere
[ 4] 1433/tcp                   ALLOW IN    203.0.113.7                # hostpanel-mssql
[ 5] 8080/tcp                   ALLOW IN    198.51.100.0/24            # hostpanel
[ 6] 2000:3000/tcp              ALLOW IN    Anywhere
[ 7] 9000/udp                   DENY IN     192.0.2.1
[ 8] Anywhere                   ALLOW IN    10.0.0.5
[ 9] 8080/tcp (v6)              ALLOW IN    Anywhere (v6)              # hostpanel
[10] 53/udp                     ALLOW IN    Anywhere                   # hostpanel-dns
[11] 5432/tcp                   ALLOW IN    203.0.113.7                # hostpanel-pg
`

func TestParseUFW(t *testing.T) {
	st := ParseUFW(ufwOut)
	if !st.Installed || !st.Active || len(st.Protected) != 5 || len(st.Rules) != 11 {
		t.Fatalf("%+v", st)
	}
	r := st.Rules[4]
	if r.No != 5 || r.To != "8080/tcp" || r.Action != "ALLOW IN" || r.From != "198.51.100.0/24" || r.Comment != "hostpanel" {
		t.Fatalf("%+v", r)
	}
	locked := map[int]bool{1: true, 2: true, 3: true, 4: true, 5: false, 6: true, 7: false, 8: true, 9: false, 10: true, 11: true}
	for _, r := range st.Rules {
		if (r.Locked != "") != locked[r.No] {
			t.Errorf("rule %d (%s) locked=%q", r.No, r.To, r.Locked)
		}
	}
	if st.Rules[6].Action != "DENY IN" || st.Rules[8].To != "8080/tcp (v6)" {
		t.Fatalf("%+v %+v", st.Rules[6], st.Rules[8])
	}
	if h := RuleHash(st.Rules[4].Line); len(h) != 16 || h == RuleHash(st.Rules[8].Line) {
		t.Fatal(h)
	}
	if ParseUFW("installed=yes\nactive=no\nprotected=22\n---\n").Active {
		t.Fatal("inactive parsed as active")
	}
}

func TestUFWRuleInput(t *testing.T) {
	prot := []int{22, 80, 443, 8443}
	good := []UFWRuleInput{
		{"allow", "8080", "tcp", ""},
		{"allow", "6000:6100", "udp", "10.0.0.0/8"},
		{"deny", "3306", "any", "192.0.2.1"},
		{"allow", "22", "tcp", "2001:db8::/32"}, // allowing a protected port is fine
	}
	for _, in := range good {
		if err := in.Validate(prot); err != nil {
			t.Errorf("%+v: %v", in, err)
		}
	}
	bad := []UFWRuleInput{
		{"limit", "80", "tcp", ""},
		{"allow", "0", "tcp", ""},
		{"allow", "70000", "tcp", ""},
		{"allow", "6100:6000", "tcp", ""},
		{"allow", "6000:6100", "any", ""},
		{"allow", "80 --dry-run", "tcp", ""},
		{"allow", "80", "icmp", ""},
		{"allow", "80", "tcp", "0.0.0.0/0"},
		{"allow", "80", "tcp", "::/0"},
		{"allow", "80", "tcp", "example.com"},
		{"deny", "22", "tcp", ""},
		{"deny", "8000:9000", "tcp", ""}, // covers 8443
		{"deny", "443", "any", "192.0.2.1"},
	}
	for _, in := range bad {
		if err := in.Validate(prot); err == nil {
			t.Errorf("%+v accepted", in)
		}
	}
	in := UFWRuleInput{"allow", " 8080 ", "tcp", " "}
	in.Validate(prot)
	if in.Port != "8080" || in.From != "any" {
		t.Fatalf("%+v", in)
	}
	if !strings.Contains((&UFWRuleInput{"deny", "22", "tcp", ""}).Validate(prot).Error(), "22") {
		t.Fatal("message should name the port")
	}
}

func TestPortsOverlap(t *testing.T) {
	for _, c := range []struct {
		spec string
		p    int
		want bool
	}{{"22", 22, true}, {"20:30", 22, true}, {"80,443", 443, true}, {"8080", 80, false}, {"1:21", 22, false}} {
		if PortsOverlap(c.spec, c.p) != c.want {
			t.Errorf("%s %d", c.spec, c.p)
		}
	}
}

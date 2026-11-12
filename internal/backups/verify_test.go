package backups

import "testing"

func TestParseVerify(t *testing.T) {
	out := "noise\ncheck=sums ok 4 dosya\ncheck=archive files.tar.zst ok 12 öğe\nmssql=shop hpvf-20261112-101010-abcd-shop.bak\ncheck=pg app skip PostgreSQL çalışmıyor\nmssql=bad\n"
	checks, staged := parseVerify(out)
	if len(checks) != 3 || checks[0] != "sums ok 4 dosya" || len(staged) != 1 || staged[0] != [2]string{"shop", "hpvf-20261112-101010-abcd-shop.bak"} {
		t.Fatalf("%q %q", checks, staged)
	}
}

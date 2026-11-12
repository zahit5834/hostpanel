package sysmaint

import (
	"testing"
)

func TestParseCleanList(t *testing.T) {
	out := "predelete\tx.com/pre-delete-20261001-101500.tar.zst\t1024\t1790000000\t\n" +
		"docker-image\tsha256:abcd\t2048\t1790000001\tmcr.microsoft.com/mssql/server:2025-CU9-ubuntu-24.04\n" +
		"bad line\n" + "apt\tapt\tnotanumber\t1\t\n"
	items := ParseCleanList(out)
	if len(items) != 2 || items[0].Cat != "predelete" || items[0].Bytes != 1024 || items[1].Label == "" || items[1].Time.Unix() != 1790000001 {
		t.Fatalf("%+v", items)
	}
}

func TestCleanDeleteRules(t *testing.T) {
	s := &Service{DryRun: true}
	dir := t.TempDir()
	for _, c := range []struct{ cat, id string }{{"mail", "x"}, {"predelete", "../etc/passwd"}, {"nope", "x"}, {"apt", "a b"}, {"uploads", "upload-1.zip"}} {
		if err := s.CleanDelete(t.Context(), dir, c.cat, c.id); err == nil {
			t.Errorf("%s %s accepted", c.cat, c.id)
		}
	}
}

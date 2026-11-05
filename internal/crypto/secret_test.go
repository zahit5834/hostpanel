package crypto

import (
	"os"
	"path/filepath"
	"testing"
)

func TestSealOpenRoundTripAndTamper(t *testing.T) {
	path := filepath.Join(t.TempDir(), "master.key")
	key, err := LoadKey(path, true, true)
	if err != nil {
		t.Fatal(err)
	}
	st, _ := os.Stat(path)
	if st.Mode().Perm() != 0o600 {
		t.Fatalf("key mode %o", st.Mode().Perm())
	}
	box, err := New(key)
	if err != nil {
		t.Fatal(err)
	}
	s, err := box.SealString("p@ss")
	if err != nil {
		t.Fatal(err)
	}
	got, err := box.OpenString(s)
	if err != nil || got != "p@ss" {
		t.Fatalf("got %q, %v", got, err)
	}
	b := []byte(s)
	b[len(b)-3] ^= 1
	if _, err := box.OpenString(string(b)); err == nil {
		t.Fatal("tampered ciphertext accepted")
	}
	// Reload must return the same key.
	key2, err := LoadKey(path, false, true)
	if err != nil || string(key2) != string(key) {
		t.Fatal("reload mismatch")
	}
}

func TestLoadKeyRejectsLoosePerms(t *testing.T) {
	path := filepath.Join(t.TempDir(), "master.key")
	if _, err := LoadKey(path, true, true); err != nil {
		t.Fatal(err)
	}
	os.Chmod(path, 0o644)
	if _, err := LoadKey(path, false, true); err == nil {
		t.Fatal("expected perm error")
	}
	if _, err := LoadKey(path, false, false); err != nil {
		t.Fatalf("non-strict should accept: %v", err)
	}
}

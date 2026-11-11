package pubdns

import (
	"context"
	"encoding/binary"
	"errors"
	"net"
	"net/netip"
	"testing"
	"time"
)

// fakeServer answers A/PTR queries from a table; names with no entry get
// NXDOMAIN, "fail." gets SERVFAIL. A stray datagram with a wrong id is sent
// before every real answer.
func fakeServer(t *testing.T, a map[string]string, ptr map[string]string) string {
	t.Helper()
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { pc.Close() })
	go func() {
		buf := make([]byte, 512)
		for {
			n, from, err := pc.ReadFrom(buf)
			if err != nil {
				return
			}
			q := buf[:n]
			name, end, err := readName(q, 12)
			if err != nil {
				continue
			}
			qtype := binary.BigEndian.Uint16(q[end:])
			stray := append([]byte(nil), q[:end+4]...)
			stray[0] ^= 0xFF
			stray[2] |= 0x80
			pc.WriteTo(stray, from)

			resp := append([]byte(nil), q[:end+4]...)
			resp[2] |= 0x80 // QR
			resp[3] = 0x80  // RA, rcode 0
			var answers [][]byte
			switch {
			case name == "fail":
				resp[3] |= 2
			case qtype == typeA && a[name] != "":
				ip := netip.MustParseAddr(a[name]).As4()
				// CNAME first (other type, skipped), then A via a compression pointer
				answers = append(answers, rec(5, []byte{3, 'w', 'w', 'w', 0xC0, 12}), rec(1, ip[:]))
			case qtype == typePTR && ptr[name] != "":
				var rd []byte
				for _, l := range splitDots(ptr[name]) {
					rd = append(rd, byte(len(l)))
					rd = append(rd, l...)
				}
				answers = append(answers, rec(12, append(rd, 0)))
			default:
				resp[3] |= 3
			}
			binary.BigEndian.PutUint16(resp[6:], uint16(len(answers)))
			for _, an := range answers {
				resp = append(resp, an...)
			}
			pc.WriteTo(resp, from)
		}
	}()
	return pc.LocalAddr().String()
}

func rec(typ uint16, rdata []byte) []byte {
	b := []byte{0xC0, 12, 0, 0, 0, 1, 0, 0, 0, 60, 0, 0}
	binary.BigEndian.PutUint16(b[2:], typ)
	binary.BigEndian.PutUint16(b[10:], uint16(len(rdata)))
	return append(b, rdata...)
}

func splitDots(s string) []string {
	var out []string
	start := 0
	for i := 0; i <= len(s); i++ {
		if i == len(s) || s[i] == '.' {
			out = append(out, s[start:i])
			start = i + 1
		}
	}
	return out
}

func TestLookup(t *testing.T) {
	ctx := context.Background()
	srv := fakeServer(t, map[string]string{"mail.ornek.com": "203.0.113.7"},
		map[string]string{"7.113.0.203.in-addr.arpa": "mail.ornek.com"})
	// first server is dead (nothing listens) → the next one answers
	dead, _ := net.ListenPacket("udp", "127.0.0.1:0")
	deadAddr := dead.LocalAddr().String()
	dead.Close()
	r := &Resolver{Servers: []string{deadAddr, srv}, Timeout: 500 * time.Millisecond}

	got, err := r.LookupA(ctx, "mail.ornek.com.")
	if err != nil || len(got) != 1 || got[0] != netip.MustParseAddr("203.0.113.7") {
		t.Fatalf("A = %v, %v", got, err)
	}
	if _, err := r.LookupA(ctx, "yok.ornek.com"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("missing name: %v", err)
	}
	names, err := r.LookupPTR(ctx, netip.MustParseAddr("203.0.113.7"))
	if err != nil || len(names) != 1 || names[0] != "mail.ornek.com" {
		t.Fatalf("PTR = %v, %v", names, err)
	}
	if _, err := (&Resolver{Servers: []string{srv}, Timeout: time.Second}).LookupA(ctx, "fail"); err == nil || errors.Is(err, ErrNotFound) {
		t.Fatalf("SERVFAIL: %v", err)
	}
	for _, bad := range []string{"", "a..b", string(make([]byte, 64)) + ".com"} {
		if _, err := r.LookupA(ctx, bad); err == nil {
			t.Errorf("accepted %q", bad)
		}
	}
}

func TestParseRejectsLoops(t *testing.T) {
	q, id, _ := buildQuery("x.com", typeA)
	resp := append([]byte(nil), q...)
	resp[2] |= 0x80
	binary.BigEndian.PutUint16(resp[6:], 1)
	resp = append(resp, 0xC0, byte(len(q))) // pointer to itself
	if _, err := parse(resp, id, typeA); err == nil {
		t.Fatal("pointer loop accepted")
	}
	if _, err := parse(resp[:5], id, typeA); err == nil {
		t.Fatal("short accepted")
	}
}

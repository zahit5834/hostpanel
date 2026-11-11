package mail

import (
	"context"
	"errors"
	"net/netip"
	"strings"
	"testing"

	"github.com/zahit5834/hostpanel/internal/pubdns"
)

type fakePublic struct {
	a   map[string][]netip.Addr
	err error
}

func (f fakePublic) LookupA(_ context.Context, host string) ([]netip.Addr, error) {
	if f.err != nil {
		return nil, f.err
	}
	if a, ok := f.a[host]; ok {
		return a, nil
	}
	return nil, pubdns.ErrNotFound
}

func (f fakePublic) LookupPTR(context.Context, netip.Addr) ([]string, error) {
	return nil, pubdns.ErrNotFound
}

// The public answer wins over /etc/hosts (Ubuntu: 127.0.1.1 <own hostname>);
// without public DNS, loopback answers from the system resolver are ignored.
func TestLookupAPublic(t *testing.T) {
	ctx := context.Background()
	ip := netip.MustParseAddr("203.0.113.7")
	s := &Service{PublicDNS: fakePublic{a: map[string][]netip.Addr{"localhost": {ip}}}}
	if got, err := s.lookupA(ctx, "localhost"); err != nil || len(got) != 1 || got[0] != ip {
		t.Fatalf("public = %v, %v", got, err)
	}
	if _, err := s.lookupA(ctx, "yok.example"); lookupErr(err) != "kayıt yok" {
		t.Fatalf("not found = %v", err)
	}
	s.PublicDNS = fakePublic{err: errors.New("genel DNS sunucularına ulaşılamadı")}
	_, err := s.lookupA(ctx, "localhost")
	if err == nil || !strings.Contains(err.Error(), "/etc/hosts") {
		t.Fatalf("loopback fallback = %v", err)
	}
}

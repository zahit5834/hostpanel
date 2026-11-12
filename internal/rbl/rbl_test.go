package rbl

import (
	"context"
	"net"
	"net/netip"
	"strings"
	"testing"
)

func TestQueryName(t *testing.T) {
	zen, _ := ByID("zen")
	dbl, _ := ByID("dbl")
	key := "abcdefghijklmnopqrstuvwxyz"
	cases := []struct {
		l      List
		target string
		key    string
		want   string
	}{
		{zen, "185.48.180.32", "", "32.180.48.185.zen.spamhaus.org"},
		{zen, "185.48.180.32", key, "32.180.48.185." + key + ".zen.dq.spamhaus.net"},
		{zen, "2001:db8::1", "", ""}, // IPv4 only
		{zen, "mail.ornek.com", "", ""},
		{dbl, "ornek.com", "", "ornek.com.dbl.spamhaus.org"},
		{dbl, "ornek.com", key, "ornek.com." + key + ".dbl.dq.spamhaus.net"},
		{dbl, "185.48.180.32", "", ""}, // never an address on the DBL
	}
	for _, c := range cases {
		if got := QueryName(c.l, c.target, c.key); got != c.want {
			t.Errorf("%s %s: %q, want %q", c.l.ID, c.target, got, c.want)
		}
	}
	spamcop, _ := ByID("spamcop")
	if got := QueryName(spamcop, "1.2.3.4", key); got != "4.3.2.1.bl.spamcop.net" {
		t.Errorf("non-Spamhaus list must ignore the DQS key: %s", got)
	}
}

func TestClassify(t *testing.T) {
	zen, _ := ByID("zen")
	dbl, _ := ByID("dbl")
	nx := &net.DNSError{Err: "no such host", IsNotFound: true}
	cases := []struct {
		l      List
		addrs  []string
		err    error
		status string
	}{
		{zen, nil, nx, StatusClean},
		{zen, []string{"127.0.0.2"}, nil, StatusListed},
		{zen, []string{"127.0.0.4", "127.0.0.11"}, nil, StatusListed},
		{zen, []string{"127.255.255.254"}, nil, StatusRefused},
		{zen, []string{"127.255.255.255"}, nil, StatusRefused},
		{zen, nil, &net.DNSError{Err: "i/o timeout", IsTimeout: true}, StatusError},
		{zen, []string{"10.0.0.1"}, nil, StatusError}, // wildcard / hijacked answer
		{dbl, []string{"127.0.1.2"}, nil, StatusListed},
		{dbl, []string{"127.0.1.255"}, nil, StatusRefused},
	}
	for _, c := range cases {
		st, codes, detail := Classify(c.l, c.addrs, c.err)
		if st != c.status {
			t.Errorf("%s %v %v: %s (%s), want %s", c.l.ID, c.addrs, c.err, st, detail, c.status)
		}
		if st == StatusListed && len(codes) == 0 {
			t.Error("listed without codes")
		}
	}
	_, _, d := Classify(zen, []string{"127.255.255.254"}, nil)
	if !strings.Contains(d, "DQS") {
		t.Errorf("refusal must point at DQS: %s", d)
	}
}

type fakeRes map[string][]string

func (f fakeRes) LookupHost(_ context.Context, h string) ([]string, error) {
	if a, ok := f[h]; ok {
		return a, nil
	}
	return nil, &net.DNSError{Err: "no such host", Name: h, IsNotFound: true}
}

func TestCheckTargets(t *testing.T) {
	r := fakeRes{"4.3.2.1.bl.spamcop.net": {"127.0.0.2"}, "ornek.com.dbl.spamhaus.org": {"127.0.1.2"}}
	res := Check(context.Background(), r, "", []netip.Addr{netip.MustParseAddr("1.2.3.4"), netip.MustParseAddr("2001:db8::1")}, []string{"ornek.com"})
	ipLists := 0
	for _, l := range Lists {
		if l.Kind == KindIP {
			ipLists++
		}
	}
	if len(res) != ipLists+1 {
		t.Fatalf("%d results: %+v", len(res), res)
	}
	listed := 0
	for _, x := range res {
		if x.Status == StatusListed {
			listed++
			if !(x.List == "spamcop" && x.Target == "1.2.3.4" || x.List == "dbl" && x.Target == "ornek.com") {
				t.Errorf("unexpected listing %+v", x)
			}
		}
	}
	if listed != 2 {
		t.Fatalf("listed %d", listed)
	}
}

func TestValidDQSKey(t *testing.T) {
	if !ValidDQSKey("abcdefghijklmnopqrstuvwxyz") || ValidDQSKey("short") || ValidDQSKey("ABCDEFGHIJKLMNOPQRSTUVWXYZ") ||
		ValidDQSKey("abcdefghijklmnopqrstuvwxy.") {
		t.Fatal("ValidDQSKey")
	}
}

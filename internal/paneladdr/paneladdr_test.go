package paneladdr

import "testing"

func TestName(t *testing.T) {
	tk := Taken{Bases: []string{"ornek.com", "site.org"}, Names: map[string]string{"www.ornek.com": "site ornek.com"},
		Manual: map[string]string{"eski.ornek.com": "CNAME"}}
	if n, err := Name(" Panel ", "ornek.com", tk); err != nil || n != "panel.ornek.com" {
		t.Fatalf("%q %v", n, err)
	}
	for _, c := range [][2]string{{"www", "ornek.com"}, {"eski", "ornek.com"}, {"panel", "yok.com"}, {"-x", "ornek.com"}, {"a_b", "site.org"}, {"", "site.org"}} {
		if _, err := Name(c[0], c[1], tk); err == nil {
			t.Fatalf("%v accepted", c)
		}
	}
}

func TestNext(t *testing.T) {
	cases := []struct{ cur, want Addr }{
		{Addr{Port: 8443}, Addr{Domain: "p.x.com", Port: 443, IPPort: 8443}},
		{Addr{Port: 9443}, Addr{Domain: "p.x.com", Port: 443, IPPort: 9443}},
		{Addr{Domain: "old.x.com", Port: 443}, Addr{Domain: "p.x.com", Port: 443, IPPort: 8443}},
		{Addr{Domain: "old.x.com", Port: 443, IPPort: 7443}, Addr{Domain: "p.x.com", Port: 443, IPPort: 7443}},
	}
	for _, c := range cases {
		if got := c.cur.next("p.x.com"); got != c.want {
			t.Fatalf("%+v → %+v want %+v", c.cur, got, c.want)
		}
	}
	if got := (Addr{Domain: "p.x.com", Port: 443, IPPort: 9443}).next(""); got != (Addr{Port: 9443}) || got.FallbackPort() != 9443 || got.URL() != "" {
		t.Fatalf("clear %+v", got)
	}
	if u := (Addr{Domain: "p.x.com", Port: 8443}).URL(); u != "https://p.x.com:8443" {
		t.Fatal(u)
	}
	if b := Bases([]string{"b.com", "a.com"}, []string{"a.com", ""}); len(b) != 2 || b[0] != "a.com" {
		t.Fatal(b)
	}
}

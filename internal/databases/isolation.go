package databases

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"io"
	"slices"
	"strings"
)

// ConnectFunc opens (and verifies, i.e. logs in) a session as login on db.
type ConnectFunc func(ctx context.Context, login, pw, db string) (LoginSession, error)

// IsolationTest proves that two customer logins cannot see or touch each
// other's databases. It creates two temporary logins + databases (prefix
// hpiso_), runs the checks in both directions, prints one line per check to w
// and always cleans up. It returns an error if any check failed.
func IsolationTest(ctx context.Context, w io.Writer, admin DatabaseProvider, connect ConnectFunc) (err error) {
	b := make([]byte, 3)
	rand.Read(b)
	sfx := hex.EncodeToString(b)
	type party struct{ login, pw, db string }
	a := party{IsolationPrefix + sfx + "_a", GeneratePassword(), IsolationPrefix + sfx + "_adb"}
	c := party{IsolationPrefix + sfx + "_b", GeneratePassword(), IsolationPrefix + sfx + "_bdb"}

	failed := 0
	check := func(name string, cerr error) {
		if cerr != nil {
			failed++
			fmt.Fprintf(w, "✗ %s: %v\n", name, cerr)
			return
		}
		fmt.Fprintf(w, "✓ %s\n", name)
	}
	cleanup := func() {
		cctx := context.WithoutCancel(ctx)
		for _, p := range []party{a, c} {
			if derr := admin.Drop(cctx, p.db, ""); derr != nil {
				fmt.Fprintf(w, "! temizlik: %s silinemedi: %v\n", p.db, derr)
			}
			if derr := admin.DropLogin(cctx, p.login); derr != nil {
				fmt.Fprintf(w, "! temizlik: %s silinemedi: %v\n", p.login, derr)
			}
		}
		fmt.Fprintln(w, "Geçici login ve veritabanları silindi.")
	}

	fmt.Fprintf(w, "Geçici loginler: %s, %s\n", a.login, c.login)
	defer cleanup()
	for _, p := range []party{a, c} {
		if err := admin.CreateLogin(ctx, p.login, p.pw); err != nil {
			return fmt.Errorf("login oluşturulamadı: %w", err)
		}
		if err := admin.CreateDatabase(ctx, p.db, p.login); err != nil {
			return fmt.Errorf("veritabanı oluşturulamadı: %w", err)
		}
	}

	for _, pair := range [][2]party{{a, c}, {c, a}} {
		me, other := pair[0], pair[1]
		fmt.Fprintf(w, "— %s olarak:\n", me.login)
		s, cerr := connect(ctx, me.login, me.pw, "")
		check("giriş yapabiliyor", cerr)
		if cerr != nil {
			continue
		}
		sa, cerr := s.IsSysadmin(ctx)
		if cerr == nil && sa {
			cerr = fmt.Errorf("login sysadmin rolünde")
		}
		check("sysadmin değil", cerr)
		vis, cerr := s.VisibleDatabases(ctx)
		check("veritabanı listesi okunabiliyor", cerr)
		if cerr == nil {
			check("kendi veritabanını görüyor ("+me.db+")", expect(slices.Contains(vis, me.db), "listede yok: "+strings.Join(vis, ", ")))
			check("diğer müşterinin veritabanını görmüyor ("+other.db+")", expect(!slices.Contains(vis, other.db), "listede görünüyor"))
		}
		check("kendi veritabanında tablo oluşturup okuyabiliyor", s.WriteProbe(ctx, me.db))
		check("diğer veritabanının kataloğunu okuyamıyor", mustFail(s.TryAccess(ctx, other.db)))
		_, cerr = connect(ctx, me.login, me.pw, other.db)
		check("diğer veritabanına doğrudan bağlanamıyor", mustFail(cerr))
	}
	_, cerr := connect(ctx, a.login, c.pw, "")
	check("yanlış şifreyle giriş reddediliyor", mustFail(cerr))

	if failed > 0 {
		return fmt.Errorf("izolasyon testi başarısız: %d kontrol geçmedi", failed)
	}
	fmt.Fprintln(w, "İzolasyon testi başarılı: müşteriler birbirinin veritabanını göremiyor ve erişemiyor.")
	return nil
}

func expect(ok bool, msg string) error {
	if ok {
		return nil
	}
	return fmt.Errorf("%s", msg)
}

func mustFail(err error) error {
	if err == nil {
		return fmt.Errorf("işlem başarılı oldu, reddedilmeliydi")
	}
	return nil
}

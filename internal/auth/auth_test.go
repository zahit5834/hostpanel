package auth

import (
	"context"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/pquerna/otp"
	"github.com/pquerna/otp/totp"

	"github.com/zahit5834/hostpanel/internal/crypto"
	"github.com/zahit5834/hostpanel/internal/store"
)

func newService(t *testing.T) *Service {
	t.Helper()
	dir := t.TempDir()
	db, err := store.Open(filepath.Join(dir, "t.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	if err := store.Migrate(context.Background(), db); err != nil {
		t.Fatal(err)
	}
	key, _ := crypto.LoadKey(filepath.Join(dir, "k"), true, true)
	box, _ := crypto.New(key)
	return New(db, box, key)
}

func TestPasswordHash(t *testing.T) {
	h, err := HashPassword("correct horse")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(h, "$argon2id$v=19$m=19456,t=2,p=1$") {
		t.Fatal(h)
	}
	if ok, _ := VerifyPassword("correct horse", h); !ok {
		t.Fatal("valid password rejected")
	}
	if ok, _ := VerifyPassword("wrong", h); ok {
		t.Fatal("wrong password accepted")
	}
}

func TestLoginFlowAndRateLimit(t *testing.T) {
	s := newService(t)
	ctx := context.Background()
	if err := s.SetAdminPassword(ctx, "admin", "pw123456"); err != nil {
		t.Fatal(err)
	}
	if _, ok := s.CheckPassword(ctx, "admin", "pw123456"); !ok {
		t.Fatal("login failed")
	}
	if _, ok := s.CheckPassword(ctx, "root", "pw123456"); ok {
		t.Fatal("wrong username accepted")
	}
	for i := 0; i < MaxFailures; i++ {
		if err := s.CheckRate(ctx, "9.9.9.9"); err != nil {
			t.Fatalf("limited too early at %d", i)
		}
		s.RecordAttempt(ctx, "9.9.9.9", false)
	}
	if err := s.CheckRate(ctx, "9.9.9.9"); err != ErrRateLimited {
		t.Fatal("not rate limited")
	}
	if err := s.CheckRate(ctx, "8.8.8.8"); err != nil {
		t.Fatal("other IP limited")
	}

	tok, _ := s.CreateSession(ctx, AdminID, StageMFA, "1.1.1.1", "ua")
	se, err := s.LookupSession(ctx, tok)
	if err != nil || se.Stage != StageMFA || se.CSRF == "" {
		t.Fatalf("%v %+v", err, se)
	}
	tok2, _ := s.PromoteSession(ctx, tok, se, "1.1.1.1", "ua")
	if _, err := s.LookupSession(ctx, tok); err == nil {
		t.Fatal("old session still valid after promote")
	}
	if se, _ := s.LookupSession(ctx, tok2); se == nil || se.Stage != StageFull {
		t.Fatal("promoted session missing")
	}
	// Password reset revokes sessions.
	s.SetAdminPassword(ctx, "admin", "newpass99")
	if _, err := s.LookupSession(ctx, tok2); err == nil {
		t.Fatal("session survived password reset")
	}
}

func TestTOTPAndRecovery(t *testing.T) {
	s := newService(t)
	ctx := context.Background()
	s.SetAdminPassword(ctx, "admin", "pw123456")
	setup, err := s.NewTOTP("admin")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(setup.QRImage, "data:image/png;base64,") {
		t.Fatal("no qr")
	}
	gen := func(at time.Time) string {
		c, _ := totp.GenerateCodeCustom(setup.Secret, at, totp.ValidateOpts{Period: 30, Digits: otp.DigitsSix, Algorithm: otp.AlgorithmSHA1})
		return c
	}
	if _, err := s.EnableTOTP(ctx, setup.Sealed, "000000"); err == nil {
		t.Fatal("bad code accepted")
	}
	codes, err := s.EnableTOTP(ctx, setup.Sealed, gen(time.Now().Add(-30*time.Second)))
	if err != nil || len(codes) != 10 {
		t.Fatalf("%v %d", err, len(codes))
	}
	u, _ := s.Admin(ctx)
	if !u.TOTPEnabled {
		t.Fatal("not enabled")
	}
	if _, ok := s.VerifySecondFactor(ctx, u, gen(time.Now())); !ok {
		t.Fatal("valid totp rejected")
	}
	// Replay of the same step must fail.
	if _, ok := s.VerifySecondFactor(ctx, u, gen(time.Now())); ok {
		t.Fatal("totp replay accepted")
	}
	if used, ok := s.VerifySecondFactor(ctx, u, strings.ToLower(codes[0])); !ok || !used {
		t.Fatal("recovery code rejected")
	}
	if _, ok := s.VerifySecondFactor(ctx, u, codes[0]); ok {
		t.Fatal("recovery code reused")
	}
	if n := s.RecoveryCodesLeft(ctx); n != 9 {
		t.Fatalf("left=%d", n)
	}
}

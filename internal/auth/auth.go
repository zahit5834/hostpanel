package auth

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/base32"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"image/png"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/pquerna/otp"
	"github.com/pquerna/otp/totp"

	"github.com/zahit5834/hostpanel/internal/crypto"
	"github.com/zahit5834/hostpanel/internal/store"
)

// AdminID is the only account.
const AdminID = 1

// Session lifetimes: sliding idle timeout plus an absolute cap.
const (
	SessionIdle     = 12 * time.Hour
	SessionAbsolute = 7 * 24 * time.Hour
	MFAStageTTL     = 5 * time.Minute
	// ElevatedFor is how long a login or a re-authentication unlocks critical
	// actions (deletes, secret reveals, SSH/firewall changes …).
	ElevatedFor = 10 * time.Minute
)

// Login rate limit: failures per IP inside the window.
const (
	MaxFailures   = 5
	FailureWindow = 15 * time.Minute
)

// Session stages.
const (
	StageFull = "full"
	StageMFA  = "mfa" // password verified, TOTP pending
)

// ErrRateLimited is returned while an IP is locked out.
var ErrRateLimited = errors.New("too many failed attempts")

// User is the admin account.
type User struct {
	ID           int64
	Username     string
	PasswordHash string
	TOTPSecret   string // sealed
	TOTPEnabled  bool
}

// Session is a logged-in browser.
type Session struct {
	IDHash        string // sha256 of the token: identifies the row, useless as a cookie
	UserID        int64
	CSRF          string
	Stage         string
	IP            string
	UserAgent     string
	CreatedAt     time.Time
	LastSeen      time.Time
	ElevatedUntil time.Time
}

// Elevated reports whether critical actions are unlocked right now.
func (se *Session) Elevated(now time.Time) bool { return now.Before(se.ElevatedUntil) }

// Service ties together users, sessions and 2FA.
type Service struct {
	db     *sql.DB
	box    *crypto.Box
	macKey []byte // derived from master key; hashes recovery codes
	Issuer string
}

// New creates the service. masterKey keys the recovery-code HMAC.
func New(db *sql.DB, box *crypto.Box, masterKey []byte) *Service {
	mac := hmac.New(sha256.New, masterKey)
	mac.Write([]byte("hostpanel recovery codes v1"))
	return &Service{db: db, box: box, macKey: mac.Sum(nil), Issuer: "HostPanel"}
}

func hashToken(tok string) string {
	h := sha256.Sum256([]byte(tok))
	return hex.EncodeToString(h[:])
}

// --- users ---

// Admin loads the admin account.
func (s *Service) Admin(ctx context.Context) (User, error) {
	var u User
	err := s.db.QueryRowContext(ctx, `SELECT id, username, password_hash, totp_secret, totp_enabled FROM users WHERE id=?`, AdminID).
		Scan(&u.ID, &u.Username, &u.PasswordHash, &u.TOTPSecret, &u.TOTPEnabled)
	return u, err
}

// SetAdminPassword creates the admin if missing or replaces its password, and
// revokes all sessions so a reset also kicks out anyone holding an old session.
func (s *Service) SetAdminPassword(ctx context.Context, username, pw string) error {
	h, err := HashPassword(pw)
	if err != nil {
		return err
	}
	now := time.Now().Unix()
	_, err = s.db.ExecContext(ctx, `INSERT INTO users(id, username, password_hash, created_at, updated_at)
		VALUES(?,?,?,?,?) ON CONFLICT(id) DO UPDATE SET username=excluded.username,
		password_hash=excluded.password_hash, updated_at=excluded.updated_at`, AdminID, username, h, now, now)
	if err != nil {
		return err
	}
	_, err = s.db.ExecContext(ctx, `DELETE FROM sessions WHERE user_id=?`, AdminID)
	return err
}

// DisableTOTP turns 2FA off (CLI recovery path).
func (s *Service) DisableTOTP(ctx context.Context) error {
	_, err := s.db.ExecContext(ctx, `UPDATE users SET totp_enabled=0, totp_secret='' WHERE id=?`, AdminID)
	if err == nil {
		_, err = s.db.ExecContext(ctx, `DELETE FROM recovery_codes WHERE user_id=?`, AdminID)
	}
	return err
}

// CheckPassword verifies username+password. Always runs argon2 to avoid a
// timing oracle on the username.
func (s *Service) CheckPassword(ctx context.Context, username, pw string) (User, bool) {
	u, err := s.Admin(ctx)
	if err != nil {
		VerifyPassword(pw, dummyHash())
		return User{}, false
	}
	ok, _ := VerifyPassword(pw, u.PasswordHash)
	return u, ok && hmac.Equal([]byte(username), []byte(u.Username))
}

// dummyHash is computed lazily so startup doesn't pay an argon2 run (and its 19 MiB).
var dummyHash = sync.OnceValue(func() string {
	h, _ := HashPassword("dummy-password-for-timing")
	return h
})

// --- rate limiting ---

// CheckRate returns ErrRateLimited when ip has too many recent failures.
// Counting from the DB (indexed) keeps no in-memory state and survives restarts.
func (s *Service) CheckRate(ctx context.Context, ip string) error {
	var n int
	since := time.Now().Add(-FailureWindow).Unix()
	if err := s.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM login_attempts WHERE ip=? AND success=0 AND ts>?`, ip, since).Scan(&n); err != nil {
		return err
	}
	if n >= MaxFailures {
		return ErrRateLimited
	}
	return nil
}

// RecordAttempt stores a login attempt; a success clears the IP's failures.
func (s *Service) RecordAttempt(ctx context.Context, ip string, success bool) {
	s.db.ExecContext(ctx, `INSERT INTO login_attempts(ts, ip, success) VALUES(?,?,?)`, time.Now().Unix(), ip, success)
	if success {
		s.db.ExecContext(ctx, `DELETE FROM login_attempts WHERE ip=? AND success=0`, ip)
	}
}

// IsKnownIP reports whether ip has logged in successfully before (for "new IP" alerts).
func (s *Service) IsKnownIP(ctx context.Context, ip string) bool {
	var n int
	s.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM login_attempts WHERE ip=? AND success=1`, ip).Scan(&n)
	return n > 0
}

// --- sessions ---

// CreateSession issues a new session token (returned raw; only its hash is stored).
func (s *Service) CreateSession(ctx context.Context, userID int64, stage, ip, ua string) (string, error) {
	tok := RandomToken(32)
	now := time.Now()
	exp := now.Add(SessionIdle)
	if stage == StageMFA {
		exp = now.Add(MFAStageTTL)
	}
	if len(ua) > 200 {
		ua = ua[:200]
	}
	var elevated int64
	if stage == StageFull {
		elevated = now.Add(ElevatedFor).Unix() // the admin just proved who they are
	}
	_, err := s.db.ExecContext(ctx, `INSERT INTO sessions(id_hash, user_id, csrf_token, stage, ip, user_agent, created_at, last_seen, expires_at, elevated_until)
		VALUES(?,?,?,?,?,?,?,?,?,?)`, hashToken(tok), userID, RandomToken(32), stage, ip, ua, now.Unix(), now.Unix(), exp.Unix(), elevated)
	return tok, err
}

// LookupSession returns the session for tok and slides its expiry.
func (s *Service) LookupSession(ctx context.Context, tok string) (*Session, error) {
	if tok == "" {
		return nil, sql.ErrNoRows
	}
	var se Session
	var created, lastSeen, exp, elevated int64
	se.IDHash = hashToken(tok)
	err := s.db.QueryRowContext(ctx, `SELECT user_id, csrf_token, stage, ip, user_agent, created_at, last_seen, expires_at, elevated_until
		FROM sessions WHERE id_hash=?`, se.IDHash).Scan(&se.UserID, &se.CSRF, &se.Stage, &se.IP, &se.UserAgent, &created, &lastSeen, &exp, &elevated)
	if err != nil {
		return nil, err
	}
	now := time.Now()
	se.CreatedAt, se.LastSeen, se.ElevatedUntil = time.Unix(created, 0), time.Unix(lastSeen, 0), time.Unix(elevated, 0)
	if now.Unix() >= exp || now.Sub(se.CreatedAt) > SessionAbsolute {
		s.DeleteSession(ctx, tok)
		return nil, sql.ErrNoRows
	}
	// Write at most once a minute to avoid a DB write on every request.
	if se.Stage == StageFull && now.Unix()-lastSeen > 60 {
		s.db.ExecContext(ctx, `UPDATE sessions SET last_seen=?, expires_at=? WHERE id_hash=?`,
			now.Unix(), now.Add(SessionIdle).Unix(), hashToken(tok))
	}
	return &se, nil
}

// PromoteSession replaces an MFA-stage session with a fresh full session
// (new token, preventing session fixation across the 2FA step).
func (s *Service) PromoteSession(ctx context.Context, oldTok string, se *Session, ip, ua string) (string, error) {
	s.DeleteSession(ctx, oldTok)
	return s.CreateSession(ctx, se.UserID, StageFull, ip, ua)
}

// DeleteSession logs a session out.
func (s *Service) DeleteSession(ctx context.Context, tok string) {
	s.db.ExecContext(ctx, `DELETE FROM sessions WHERE id_hash=?`, hashToken(tok))
}

// Elevate unlocks critical actions for ElevatedFor (after /reauth).
func (s *Service) Elevate(ctx context.Context, idHash string) error {
	_, err := s.db.ExecContext(ctx, `UPDATE sessions SET elevated_until=? WHERE id_hash=? AND stage=?`,
		time.Now().Add(ElevatedFor).Unix(), idHash, StageFull)
	return err
}

// ListSessions returns the user's live full sessions, most recent first.
func (s *Service) ListSessions(ctx context.Context, userID int64) ([]Session, error) {
	now := time.Now()
	rows, err := s.db.QueryContext(ctx, `SELECT id_hash, user_id, stage, ip, user_agent, created_at, last_seen, elevated_until
		FROM sessions WHERE user_id=? AND stage=? AND expires_at>? AND created_at>? ORDER BY last_seen DESC`,
		userID, StageFull, now.Unix(), now.Add(-SessionAbsolute).Unix())
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Session
	for rows.Next() {
		var se Session
		var created, lastSeen, elevated int64
		if err := rows.Scan(&se.IDHash, &se.UserID, &se.Stage, &se.IP, &se.UserAgent, &created, &lastSeen, &elevated); err != nil {
			return nil, err
		}
		se.CreatedAt, se.LastSeen, se.ElevatedUntil = time.Unix(created, 0), time.Unix(lastSeen, 0), time.Unix(elevated, 0)
		out = append(out, se)
	}
	return out, rows.Err()
}

// RevokeSession ends one session by its id hash; false when there was none.
func (s *Service) RevokeSession(ctx context.Context, userID int64, idHash string) bool {
	res, err := s.db.ExecContext(ctx, `DELETE FROM sessions WHERE id_hash=? AND user_id=?`, idHash, userID)
	if err != nil {
		return false
	}
	n, _ := res.RowsAffected()
	return n == 1
}

// RevokeOthers ends every session of the user except keep; returns how many.
func (s *Service) RevokeOthers(ctx context.Context, userID int64, keep string) int {
	res, err := s.db.ExecContext(ctx, `DELETE FROM sessions WHERE user_id=? AND id_hash<>?`, userID, keep)
	if err != nil {
		return 0
	}
	n, _ := res.RowsAffected()
	return int(n)
}

// Attempt is one row of the login history.
type Attempt struct {
	TS      time.Time
	IP      string
	Success bool
}

// RecentAttempts returns the newest login attempts (failures are kept for a
// day, successes for 180 days).
func (s *Service) RecentAttempts(ctx context.Context, limit int) ([]Attempt, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT ts, ip, success FROM login_attempts ORDER BY ts DESC, id DESC LIMIT ?`, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Attempt
	for rows.Next() {
		var a Attempt
		var ts int64
		if err := rows.Scan(&ts, &a.IP, &a.Success); err != nil {
			return nil, err
		}
		a.TS = time.Unix(ts, 0)
		out = append(out, a)
	}
	return out, rows.Err()
}

// PurgeExpired removes dead sessions and old login attempts.
func (s *Service) PurgeExpired(ctx context.Context) {
	now := time.Now()
	s.db.ExecContext(ctx, `DELETE FROM sessions WHERE expires_at < ? OR created_at < ?`, now.Unix(), now.Add(-SessionAbsolute).Unix())
	// Keep successful logins (known-IP list) for 180 days, failures for 1 day.
	s.db.ExecContext(ctx, `DELETE FROM login_attempts WHERE (success=0 AND ts < ?) OR ts < ?`,
		now.Add(-24*time.Hour).Unix(), now.Add(-180*24*time.Hour).Unix())
}

// --- TOTP ---

// TOTPSetup is a pending enrollment shown to the admin.
type TOTPSetup struct {
	Secret  string // base32, shown for manual entry
	Sealed  string // stored in the form until confirmed
	QRImage string // data: URI
}

// NewTOTP generates a secret and QR code for the admin.
func (s *Service) NewTOTP(account string) (TOTPSetup, error) {
	key, err := totp.Generate(totp.GenerateOpts{Issuer: s.Issuer, AccountName: account, Period: 30, Digits: otp.DigitsSix, Algorithm: otp.AlgorithmSHA1})
	if err != nil {
		return TOTPSetup{}, err
	}
	img, err := key.Image(240, 240)
	if err != nil {
		return TOTPSetup{}, err
	}
	var buf bytes.Buffer
	if err := png.Encode(&buf, img); err != nil {
		return TOTPSetup{}, err
	}
	sealed, err := s.box.SealString(key.Secret())
	if err != nil {
		return TOTPSetup{}, err
	}
	return TOTPSetup{
		Secret:  key.Secret(),
		Sealed:  sealed,
		QRImage: "data:image/png;base64," + base64.StdEncoding.EncodeToString(buf.Bytes()),
	}, nil
}

// validateTOTP checks code against a sealed secret, allowing ±1 step of clock skew
// and rejecting reuse of an already accepted time step (replay protection).
func (s *Service) validateTOTP(ctx context.Context, sealed, code string) bool {
	secret, err := s.box.OpenString(sealed)
	if err != nil {
		return false
	}
	code = strings.TrimSpace(code)
	now := time.Now()
	last, _ := strconv.ParseInt(store.GetSetting(ctx, s.db, "totp_last_step", "0"), 10, 64)
	for _, d := range []int64{0, -1, 1} {
		t := now.Add(time.Duration(d) * 30 * time.Second)
		step := t.Unix() / 30
		if step <= last {
			continue
		}
		ok, _ := totp.ValidateCustom(code, secret, t, totp.ValidateOpts{Period: 30, Skew: 0, Digits: otp.DigitsSix, Algorithm: otp.AlgorithmSHA1})
		if ok {
			store.SetSetting(ctx, s.db, "totp_last_step", strconv.FormatInt(step, 10))
			return true
		}
	}
	return false
}

// EnableTOTP confirms enrollment with a first valid code and returns fresh recovery codes.
func (s *Service) EnableTOTP(ctx context.Context, sealed, code string) ([]string, error) {
	if _, err := s.box.OpenString(sealed); err != nil {
		return nil, errors.New("geçersiz kurulum verisi")
	}
	if !s.validateTOTP(ctx, sealed, code) {
		return nil, errors.New("doğrulama kodu hatalı")
	}
	if _, err := s.db.ExecContext(ctx, `UPDATE users SET totp_secret=?, totp_enabled=1, updated_at=? WHERE id=?`, sealed, time.Now().Unix(), AdminID); err != nil {
		return nil, err
	}
	return s.RegenerateRecoveryCodes(ctx)
}

// VerifySecondFactor accepts a TOTP code or an unused recovery code.
func (s *Service) VerifySecondFactor(ctx context.Context, u User, code string) (usedRecovery bool, ok bool) {
	code = strings.TrimSpace(code)
	if len(code) == 6 && s.validateTOTP(ctx, u.TOTPSecret, code) {
		return false, true
	}
	return true, s.useRecoveryCode(ctx, u.ID, code)
}

// --- recovery codes ---

// Recovery codes are random 50-bit values hashed with HMAC-SHA256 keyed by the
// master key: fast to check (no argon2 cost per code) yet useless to an attacker
// holding only a DB copy.
func (s *Service) hashRecovery(code string) string {
	norm := strings.ToUpper(strings.ReplaceAll(strings.TrimSpace(code), "-", ""))
	m := hmac.New(sha256.New, s.macKey)
	m.Write([]byte(norm))
	return hex.EncodeToString(m.Sum(nil))
}

// RegenerateRecoveryCodes replaces all codes with 10 new ones.
func (s *Service) RegenerateRecoveryCodes(ctx context.Context) ([]string, error) {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	if _, err := tx.ExecContext(ctx, `DELETE FROM recovery_codes WHERE user_id=?`, AdminID); err != nil {
		return nil, err
	}
	enc := base32.StdEncoding.WithPadding(base32.NoPadding)
	codes := make([]string, 10)
	for i := range codes {
		raw := make([]byte, 7) // 56 random bits; first 50 are used
		if _, err := rand.Read(raw); err != nil {
			return nil, err
		}
		c := enc.EncodeToString(raw)[:10]
		codes[i] = c[:5] + "-" + c[5:]
		if _, err := tx.ExecContext(ctx, `INSERT INTO recovery_codes(user_id, code_hash) VALUES(?,?)`, AdminID, s.hashRecovery(codes[i])); err != nil {
			return nil, err
		}
	}
	return codes, tx.Commit()
}

// RecoveryCodesLeft counts unused codes.
func (s *Service) RecoveryCodesLeft(ctx context.Context) int {
	var n int
	s.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM recovery_codes WHERE user_id=? AND used_at IS NULL`, AdminID).Scan(&n)
	return n
}

func (s *Service) useRecoveryCode(ctx context.Context, userID int64, code string) bool {
	if len(code) < 10 {
		return false
	}
	res, err := s.db.ExecContext(ctx, `UPDATE recovery_codes SET used_at=? WHERE user_id=? AND code_hash=? AND used_at IS NULL`,
		time.Now().Unix(), userID, s.hashRecovery(code))
	if err != nil {
		return false
	}
	n, _ := res.RowsAffected()
	return n == 1
}

// String helps debugging without leaking secrets.
func (u User) String() string {
	return fmt.Sprintf("User{%d %s 2fa=%v}", u.ID, u.Username, u.TOTPEnabled)
}

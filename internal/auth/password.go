// Package auth handles the admin account: passwords, sessions, TOTP 2FA,
// recovery codes and login rate limiting.
package auth

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"math/big"
	"runtime/debug"
	"strings"

	"golang.org/x/crypto/argon2"
)

// argon2id parameters: OWASP's minimum recommendation (19 MiB, t=2, p=1).
// Higher memory would spike RSS on every login, which conflicts with the panel's RAM budget.
const (
	argonMemory  = 19 * 1024
	argonTime    = 2
	argonThreads = 1
	argonKeyLen  = 32
	saltLen      = 16
)

// argonKey runs argon2id and then hands its 19 MiB work buffer straight back
// to the OS. Without this the Go runtime keeps the pages for minutes and idle
// RSS stays ~40 MB after a single login. Logins are rare, so the forced GC
// (~1 ms on this small heap) is cheap.
func argonKey(pw, salt []byte, t, m uint32, p uint8, keyLen uint32) []byte {
	key := argon2.IDKey(pw, salt, t, m, p, keyLen)
	debug.FreeOSMemory()
	return key
}

// HashPassword returns a PHC-formatted argon2id hash.
func HashPassword(pw string) (string, error) {
	salt := make([]byte, saltLen)
	if _, err := rand.Read(salt); err != nil {
		return "", err
	}
	key := argonKey([]byte(pw), salt, argonTime, argonMemory, argonThreads, argonKeyLen)
	b64 := base64.RawStdEncoding
	return fmt.Sprintf("$argon2id$v=%d$m=%d,t=%d,p=%d$%s$%s",
		argon2.Version, argonMemory, argonTime, argonThreads, b64.EncodeToString(salt), b64.EncodeToString(key)), nil
}

// VerifyPassword checks pw against a PHC argon2id hash in constant time.
func VerifyPassword(pw, encoded string) (bool, error) {
	parts := strings.Split(encoded, "$")
	if len(parts) != 6 || parts[1] != "argon2id" {
		return false, errors.New("unsupported hash format")
	}
	var version int
	if _, err := fmt.Sscanf(parts[2], "v=%d", &version); err != nil || version != argon2.Version {
		return false, errors.New("unsupported argon2 version")
	}
	var m uint32
	var t uint32
	var p uint8
	if _, err := fmt.Sscanf(parts[3], "m=%d,t=%d,p=%d", &m, &t, &p); err != nil {
		return false, err
	}
	b64 := base64.RawStdEncoding
	salt, err := b64.DecodeString(parts[4])
	if err != nil {
		return false, err
	}
	want, err := b64.DecodeString(parts[5])
	if err != nil {
		return false, err
	}
	got := argonKey([]byte(pw), salt, t, m, p, uint32(len(want)))
	return subtle.ConstantTimeCompare(got, want) == 1, nil
}

const pwAlphabet = "abcdefghijkmnpqrstuvwxyzABCDEFGHJKLMNPQRSTUVWXYZ23456789"

// RandomPassword returns a strong random password without ambiguous characters.
func RandomPassword(n int) string {
	var sb strings.Builder
	max := big.NewInt(int64(len(pwAlphabet)))
	for i := 0; i < n; i++ {
		idx, err := rand.Int(rand.Reader, max)
		if err != nil {
			panic(err) // crypto/rand failing is unrecoverable
		}
		sb.WriteByte(pwAlphabet[idx.Int64()])
	}
	return sb.String()
}

// RandomToken returns n random bytes encoded as URL-safe base64.
func RandomToken(n int) string {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}
	return base64.RawURLEncoding.EncodeToString(b)
}

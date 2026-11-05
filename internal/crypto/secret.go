// Package crypto encrypts secrets at rest with AES-256-GCM.
package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"os"
	"path/filepath"
)

const keySize = 32

// Box seals and opens secrets with the master key.
type Box struct {
	aead cipher.AEAD
}

// New builds a Box from a raw 32-byte key.
func New(key []byte) (*Box, error) {
	if len(key) != keySize {
		return nil, fmt.Errorf("master key must be %d bytes, got %d", keySize, len(key))
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	return &Box{aead: aead}, nil
}

// LoadKey reads the key file. If create is true and the file is missing, a new
// key is generated with mode 0600. When strict is true, a key file readable by
// group/others is rejected: a leaked master key exposes every stored secret.
func LoadKey(path string, create, strict bool) ([]byte, error) {
	st, err := os.Stat(path)
	if errors.Is(err, os.ErrNotExist) && create {
		key := make([]byte, keySize)
		if _, err := rand.Read(key); err != nil {
			return nil, err
		}
		if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
			return nil, err
		}
		if err := os.WriteFile(path, key, 0o600); err != nil {
			return nil, err
		}
		return key, nil
	}
	if err != nil {
		return nil, fmt.Errorf("master key: %w", err)
	}
	if strict && st.Mode().Perm()&0o077 != 0 {
		return nil, fmt.Errorf("master key %s has mode %o, want 600", path, st.Mode().Perm())
	}
	key, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	if len(key) != keySize {
		return nil, fmt.Errorf("master key %s: want %d bytes, got %d", path, keySize, len(key))
	}
	return key, nil
}

// Seal encrypts plaintext and returns base64(nonce||ciphertext).
func (b *Box) Seal(plaintext []byte) (string, error) {
	nonce := make([]byte, b.aead.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return "", err
	}
	out := b.aead.Seal(nonce, nonce, plaintext, nil)
	return base64.StdEncoding.EncodeToString(out), nil
}

// Open reverses Seal. Any tampering yields an error.
func (b *Box) Open(sealed string) ([]byte, error) {
	raw, err := base64.StdEncoding.DecodeString(sealed)
	if err != nil {
		return nil, fmt.Errorf("decode secret: %w", err)
	}
	ns := b.aead.NonceSize()
	if len(raw) < ns+b.aead.Overhead() {
		return nil, errors.New("secret too short")
	}
	pt, err := b.aead.Open(nil, raw[:ns], raw[ns:], nil)
	if err != nil {
		return nil, errors.New("secret authentication failed")
	}
	return pt, nil
}

// SealString is a convenience wrapper.
func (b *Box) SealString(s string) (string, error) { return b.Seal([]byte(s)) }

// OpenString is a convenience wrapper.
func (b *Box) OpenString(s string) (string, error) {
	pt, err := b.Open(s)
	return string(pt), err
}

// Package ssl manages TLS certificates: Let's Encrypt via certbot (webroot),
// CSR generation and verification/installation of purchased certificates.
package ssl

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"regexp"
	"strings"
	"time"
	"unicode/utf8"
)

// Key types offered for CSRs.
const (
	KeyRSA2048 = "rsa2048"
	KeyRSA4096 = "rsa4096"
	KeyECP256  = "ecdsa-p256"
)

// KeyTypes maps form values to labels.
var KeyTypes = []struct{ ID, Label string }{
	{KeyRSA2048, "RSA 2048"}, {KeyRSA4096, "RSA 4096"}, {KeyECP256, "ECDSA P-256"},
}

// GenerateKey creates a private key of type t.
func GenerateKey(t string) (crypto.Signer, error) {
	switch t {
	case KeyRSA2048:
		return rsa.GenerateKey(rand.Reader, 2048)
	case KeyRSA4096:
		return rsa.GenerateKey(rand.Reader, 4096)
	case KeyECP256:
		return ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	}
	return nil, fmt.Errorf("bilinmeyen anahtar tipi: %s", t)
}

// MarshalKey encodes a private key as PKCS#8 PEM.
func MarshalKey(k crypto.Signer) (string, error) {
	der, err := x509.MarshalPKCS8PrivateKey(k)
	if err != nil {
		return "", err
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})), nil
}

// ParseKey reads the first private key block (PKCS#8, PKCS#1 or SEC1).
// Encrypted keys are rejected: nginx would need the passphrase at every start.
func ParseKey(text string) (crypto.Signer, error) {
	rest := []byte(text)
	for {
		var b *pem.Block
		b, rest = pem.Decode(rest)
		if b == nil {
			return nil, errors.New("private key bulunamadı (PEM bekleniyor)")
		}
		if b.Type == "ENCRYPTED PRIVATE KEY" || b.Headers["Proc-Type"] != "" {
			return nil, errors.New("parolalı private key desteklenmiyor; önce parolayı kaldırın (openssl pkey -in key.pem -out key-plain.pem)")
		}
		var k any
		var err error
		switch b.Type {
		case "PRIVATE KEY":
			k, err = x509.ParsePKCS8PrivateKey(b.Bytes)
		case "RSA PRIVATE KEY":
			k, err = x509.ParsePKCS1PrivateKey(b.Bytes)
		case "EC PRIVATE KEY":
			k, err = x509.ParseECPrivateKey(b.Bytes)
		default:
			continue
		}
		if err != nil {
			return nil, fmt.Errorf("private key okunamadı: %w", err)
		}
		s, ok := k.(crypto.Signer)
		if !ok {
			return nil, errors.New("desteklenmeyen private key türü")
		}
		return s, nil
	}
}

// KeyLabel describes a public key ("RSA 2048", "ECDSA P-256").
func KeyLabel(pub any) string {
	switch k := pub.(type) {
	case *rsa.PublicKey:
		return fmt.Sprintf("RSA %d", k.N.BitLen())
	case *ecdsa.PublicKey:
		return "ECDSA " + k.Curve.Params().Name
	case ed25519.PublicKey:
		return "Ed25519"
	}
	return "bilinmiyor"
}

func samePublicKey(a, b any) bool {
	type eq interface{ Equal(crypto.PublicKey) bool }
	if x, ok := a.(eq); ok {
		return x.Equal(b)
	}
	return false
}

// --- CSR ---

// Subject holds the optional distinguished-name fields of a CSR.
type Subject struct {
	Country  string `json:"c"`
	State    string `json:"st"`
	Locality string `json:"l"`
	Org      string `json:"o"`
	OrgUnit  string `json:"ou"`
	Email    string `json:"email"`
}

// CSRInput is the CSR form.
type CSRInput struct {
	CommonName string
	SANs       []string
	Subject    Subject
	KeyType    string
}

var (
	countryRe = regexp.MustCompile(`^[A-Z]{2}$`)
	// Length is checked separately: a counted repeat of Unicode classes
	// ({0,64}) compiles to ~1.4 MB of rune sets kept for the process lifetime.
	dnTextRe   = regexp.MustCompile(`^[\p{L}\p{N} .,&'()/-]*$`)
	emailRe    = regexp.MustCompile(`^[A-Za-z0-9._%+-]{1,64}@[A-Za-z0-9.-]{1,253}\.[A-Za-z]{2,63}$`)
	hostnameRe = regexp.MustCompile(`^(\*\.)?([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$`)
)

// ValidEmail is the ACME / CSR e-mail rule (mirrored by validate_email in lib.sh).
func ValidEmail(s string) bool { return emailRe.MatchString(s) }

// Validate normalises and checks the input. Wildcard names are allowed in
// CSRs (purchased wildcard certificates), not for Let's Encrypt.
func (in *CSRInput) Validate() error {
	in.CommonName = strings.ToLower(strings.TrimSpace(in.CommonName))
	if !hostnameRe.MatchString(in.CommonName) {
		return errors.New("geçersiz ortak ad (CN): alan adı bekleniyor")
	}
	seen := map[string]bool{in.CommonName: true}
	sans := []string{in.CommonName}
	for _, n := range in.SANs {
		n = strings.ToLower(strings.TrimSpace(n))
		if n == "" || seen[n] {
			continue
		}
		if !hostnameRe.MatchString(n) {
			return fmt.Errorf("geçersiz SAN: %s", n)
		}
		seen[n] = true
		sans = append(sans, n)
	}
	if len(sans) > 100 {
		return errors.New("en fazla 100 alan adı")
	}
	in.SANs = sans
	s := &in.Subject
	s.Country = strings.ToUpper(strings.TrimSpace(s.Country))
	if s.Country != "" && !countryRe.MatchString(s.Country) {
		return errors.New("ülke kodu iki harf olmalı (örn. TR)")
	}
	for _, f := range []*string{&s.State, &s.Locality, &s.Org, &s.OrgUnit} {
		*f = strings.TrimSpace(*f)
		if utf8.RuneCountInString(*f) > 64 {
			return fmt.Errorf("en fazla 64 karakter: %q", *f)
		}
		if !dnTextRe.MatchString(*f) {
			return fmt.Errorf("geçersiz karakter: %q", *f)
		}
	}
	s.Email = strings.TrimSpace(s.Email)
	if s.Email != "" && !ValidEmail(s.Email) {
		return errors.New("geçersiz e-posta")
	}
	switch in.KeyType {
	case KeyRSA2048, KeyRSA4096, KeyECP256:
	default:
		return errors.New("anahtar tipi seçin")
	}
	return nil
}

var oidEmail = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 1}

// CreateCSR builds a PEM CSR. SANs always include the CN (CAs require it).
func CreateCSR(key crypto.Signer, in CSRInput) (string, error) {
	name := pkix.Name{CommonName: in.CommonName}
	add := func(dst *[]string, v string) {
		if v != "" {
			*dst = []string{v}
		}
	}
	add(&name.Country, in.Subject.Country)
	add(&name.Province, in.Subject.State)
	add(&name.Locality, in.Subject.Locality)
	add(&name.Organization, in.Subject.Org)
	add(&name.OrganizationalUnit, in.Subject.OrgUnit)
	if in.Subject.Email != "" {
		name.ExtraNames = append(name.ExtraNames, pkix.AttributeTypeAndValue{Type: oidEmail, Value: in.Subject.Email})
	}
	der, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{Subject: name, DNSNames: in.SANs}, key)
	if err != nil {
		return "", err
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: der})), nil
}

// --- certificates ---

// Info is what the UI and DB keep about a certificate.
type Info struct {
	Subject     string
	Issuer      string
	Names       []string
	NotBefore   time.Time
	NotAfter    time.Time
	Serial      string
	Fingerprint string
	KeyType     string
}

// InfoOf summarises a leaf certificate.
func InfoOf(c *x509.Certificate) Info {
	issuer := c.Issuer.CommonName
	if len(c.Issuer.Organization) > 0 {
		if issuer == "" {
			issuer = c.Issuer.Organization[0]
		} else {
			issuer = c.Issuer.Organization[0] + " · " + issuer
		}
	}
	sum := sha256.Sum256(c.Raw)
	names := c.DNSNames
	if len(names) == 0 && c.Subject.CommonName != "" {
		names = []string{c.Subject.CommonName}
	}
	return Info{
		Subject: c.Subject.CommonName, Issuer: issuer, Names: names,
		NotBefore: c.NotBefore, NotAfter: c.NotAfter,
		Serial: strings.ToUpper(c.SerialNumber.Text(16)), Fingerprint: hex.EncodeToString(sum[:]),
		KeyType: KeyLabel(c.PublicKey),
	}
}

// ParseCerts decodes every CERTIFICATE block. A private key pasted into a
// certificate field is an error (it would otherwise end up in a public file).
func ParseCerts(text string) ([]*x509.Certificate, error) {
	var out []*x509.Certificate
	rest := []byte(text)
	for {
		var b *pem.Block
		b, rest = pem.Decode(rest)
		if b == nil {
			break
		}
		switch {
		case b.Type == "CERTIFICATE":
			c, err := x509.ParseCertificate(b.Bytes)
			if err != nil {
				return nil, fmt.Errorf("sertifika okunamadı: %w", err)
			}
			out = append(out, c)
		case strings.Contains(b.Type, "PRIVATE KEY"):
			return nil, errors.New("sertifika alanında private key var; key'i ayrı alana yapıştırın")
		}
	}
	if strings.TrimSpace(string(rest)) != "" && len(out) == 0 {
		return nil, errors.New("PEM biçiminde sertifika bekleniyor (-----BEGIN CERTIFICATE-----)")
	}
	return out, nil
}

// EncodeCerts returns certs as concatenated PEM.
func EncodeCerts(certs []*x509.Certificate) string {
	var b strings.Builder
	for _, c := range certs {
		b.Write(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: c.Raw}))
	}
	return b.String()
}

// LeafInfo parses a fullchain PEM and summarises its first certificate.
func LeafInfo(fullchain string) (Info, error) {
	certs, err := ParseCerts(fullchain)
	if err != nil {
		return Info{}, err
	}
	if len(certs) == 0 {
		return Info{}, errors.New("sertifika bulunamadı")
	}
	return InfoOf(certs[0]), nil
}

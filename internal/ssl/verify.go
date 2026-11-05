package ssl

import (
	"bytes"
	"crypto/rsa"
	"crypto/x509"
	"fmt"
	"strings"
	"time"
)

// Check levels.
const (
	LevelOK   = "ok"
	LevelWarn = "warn"
	LevelErr  = "err"
)

// Check is one line of the verification report.
type Check struct {
	Level string
	Text  string
}

// Report is the result of Verify. Install is allowed only when OK.
type Report struct {
	Checks    []Check
	OK        bool
	Info      Info
	FullChain string // leaf + intermediates in the right order, roots dropped
	KeyPEM    string // normalised PKCS#8
}

func (r *Report) add(level, format string, a ...any) {
	r.Checks = append(r.Checks, Check{level, fmt.Sprintf(format, a...)})
}

// VerifyInput is what the install form provides.
type VerifyInput struct {
	CertPEM  string // the certificate (may also contain the chain)
	ChainPEM string // CA bundle / intermediates
	KeyPEM   string
	Primary  string   // must be covered
	Names    []string // other names the site serves (warned if missing)
}

func isSelfSigned(c *x509.Certificate) bool {
	return bytes.Equal(c.RawIssuer, c.RawSubject) && c.CheckSignatureFrom(c) == nil
}

// Verify checks a purchased certificate before installation: key match,
// name coverage, chain completeness/order, validity dates and key strength.
// roots nil means the system pool.
func Verify(in VerifyInput, now time.Time, roots *x509.CertPool) Report {
	var r Report
	key, err := ParseKey(in.KeyPEM)
	if err != nil {
		r.add(LevelErr, "%v", err)
		return r
	}
	certs, err := ParseCerts(in.CertPEM)
	if err != nil {
		r.add(LevelErr, "Sertifika: %v", err)
		return r
	}
	chain, err := ParseCerts(in.ChainPEM)
	if err != nil {
		r.add(LevelErr, "CA bundle: %v", err)
		return r
	}
	if len(certs) == 0 {
		r.add(LevelErr, "Sertifika (CRT) boş")
		return r
	}
	all := dedupe(append(append([]*x509.Certificate{}, certs...), chain...))

	// 1. Key match: the leaf is the certificate whose public key is ours.
	var leaf *x509.Certificate
	for _, c := range all {
		if samePublicKey(c.PublicKey, key.Public()) {
			leaf = c
			break
		}
	}
	if leaf == nil {
		r.add(LevelErr, "Private key bu sertifikayla eşleşmiyor (public key'ler farklı). Doğru CSR/key'i seçtiğinizden emin olun.")
		return r
	}
	r.add(LevelOK, "Private key sertifikayla eşleşiyor (%s)", KeyLabel(leaf.PublicKey))
	if k, ok := key.(*rsa.PrivateKey); ok && k.N.BitLen() < 2048 {
		r.add(LevelErr, "RSA anahtarı %d bit; en az 2048 olmalı", k.N.BitLen())
	}
	if leaf.IsCA {
		r.add(LevelWarn, "Sertifika bir CA sertifikası olarak işaretli")
	}
	r.Info = InfoOf(leaf)

	// 2. Names.
	if err := leaf.VerifyHostname(in.Primary); err != nil {
		r.add(LevelErr, "Sertifika %s alan adını kapsamıyor (kapsanan: %s)", in.Primary, strings.Join(r.Info.Names, ", "))
	} else {
		r.add(LevelOK, "%s kapsanıyor", in.Primary)
	}
	var missing []string
	for _, n := range in.Names {
		if n != in.Primary && leaf.VerifyHostname(n) != nil {
			missing = append(missing, n)
		}
	}
	if len(missing) > 0 {
		r.add(LevelWarn, "Şu adlar sertifikada yok, HTTPS'te uyarı verir: %s", strings.Join(missing, ", "))
	}

	// 3. Dates.
	switch days := int(leaf.NotAfter.Sub(now).Hours() / 24); {
	case now.Before(leaf.NotBefore):
		r.add(LevelErr, "Sertifika henüz geçerli değil (başlangıç %s)", leaf.NotBefore.Local().Format("02.01.2006 15:04"))
	case now.After(leaf.NotAfter):
		r.add(LevelErr, "Sertifikanın süresi dolmuş (%s)", leaf.NotAfter.Local().Format("02.01.2006"))
	case days < 30:
		r.add(LevelWarn, "Sertifikanın bitmesine %d gün kaldı (%s)", days, leaf.NotAfter.Local().Format("02.01.2006"))
	default:
		r.add(LevelOK, "Geçerlilik: %s – %s (%d gün kaldı)", leaf.NotBefore.Local().Format("02.01.2006"), leaf.NotAfter.Local().Format("02.01.2006"), days)
	}

	// 4. Chain: walk issuer links from the leaf.
	ordered := []*x509.Certificate{leaf}
	used := map[*x509.Certificate]bool{leaf: true}
	var root *x509.Certificate
	for cur := leaf; !isSelfSigned(cur); {
		var next *x509.Certificate
		for _, c := range all {
			if !used[c] && bytes.Equal(cur.RawIssuer, c.RawSubject) && cur.CheckSignatureFrom(c) == nil {
				next = c
				break
			}
		}
		if next == nil {
			break
		}
		used[next] = true
		if isSelfSigned(next) {
			root = next
			break
		}
		ordered = append(ordered, next)
		cur = next
	}
	if root != nil {
		r.add(LevelWarn, "Kök sertifika (%s) zincirden çıkarıldı; tarayıcılarda zaten bulunur", root.Subject.CommonName)
	}
	if extra := len(all) - len(ordered) - btoi(root != nil); extra > 0 {
		r.add(LevelWarn, "Zincirle ilgisi olmayan %d sertifika yok sayıldı", extra)
	}
	given := append(append([]*x509.Certificate{}, certs...), chain...)
	if !prefixOrder(given, ordered) {
		r.add(LevelWarn, "Zincir sırası düzeltildi: sertifika → ara sertifikalar")
	}
	if roots == nil {
		roots, _ = x509.SystemCertPool()
	}
	inter := x509.NewCertPool()
	for _, c := range ordered[1:] {
		inter.AddCert(c)
	}
	// Dates are reported above; check the chain at a moment the leaf is valid.
	at := now
	if at.Before(leaf.NotBefore) || at.After(leaf.NotAfter) {
		at = leaf.NotBefore.Add(leaf.NotAfter.Sub(leaf.NotBefore) / 2)
	}
	if _, err := leaf.Verify(x509.VerifyOptions{Roots: roots, Intermediates: inter, CurrentTime: at, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}); err != nil {
		top := ordered[len(ordered)-1]
		r.add(LevelErr, "Zincir eksik veya güvenilir değil: %q sertifikasını imzalayan %q bulunamadı ya da güvenilir bir kök değil. CA bundle / ara sertifikaları ekleyin. (%v)",
			top.Subject.CommonName, top.Issuer.CommonName, err)
	} else {
		names := make([]string, 0, len(ordered)-1)
		for _, c := range ordered[1:] {
			names = append(names, c.Subject.CommonName)
		}
		if len(names) == 0 {
			r.add(LevelOK, "Zincir doğrulandı (ara sertifika gerekmiyor)")
		} else {
			r.add(LevelOK, "Zincir doğrulandı: %s", strings.Join(names, " → "))
		}
	}
	for _, c := range ordered[1:] {
		if at.After(c.NotAfter) {
			r.add(LevelErr, "Ara sertifikanın süresi dolmuş: %s", c.Subject.CommonName)
		}
	}

	r.FullChain = EncodeCerts(ordered)
	r.KeyPEM, _ = MarshalKey(key)
	r.OK = true
	for _, c := range r.Checks {
		if c.Level == LevelErr {
			r.OK = false
		}
	}
	return r
}

func btoi(b bool) int {
	if b {
		return 1
	}
	return 0
}

func dedupe(cs []*x509.Certificate) []*x509.Certificate {
	var out []*x509.Certificate
	for _, c := range cs {
		dup := false
		for _, o := range out {
			if c.Equal(o) {
				dup = true
				break
			}
		}
		if !dup {
			out = append(out, c)
		}
	}
	return out
}

// prefixOrder reports whether the user's input already listed want in order
// at the start (roots/extra certs at the end are fine).
func prefixOrder(given, want []*x509.Certificate) bool {
	given = dedupe(given)
	if len(given) < len(want) {
		return false
	}
	for i := range want {
		if !given[i].Equal(want[i]) {
			return false
		}
	}
	return true
}

// KeyMatches reports whether keyPEM belongs to the leaf of certPEM.
func KeyMatches(certPEM, keyPEM string) bool {
	certs, err := ParseCerts(certPEM)
	if err != nil || len(certs) == 0 {
		return false
	}
	k, err := ParseKey(keyPEM)
	if err != nil {
		return false
	}
	return samePublicKey(certs[0].PublicKey, k.Public())
}

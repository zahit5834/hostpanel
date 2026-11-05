// Package logs implements the Log Center: activity log, masking and file tailing.
package logs

import (
	"log/slog"
	"regexp"
	"strings"
)

// Masked replaces any secret value in logs and stored params.
const Masked = "***"

// sensitiveKey matches field names whose values must never be logged.
var sensitiveKey = regexp.MustCompile(`(?i)(pass(word|wd)?|pwd|secret|token|api[_-]?key|private|credential|connection[_-]?string|sa_password|totp|recovery|cookie|session|authorization|key$|^key)`)

// IsSensitiveKey reports whether a field name denotes a secret.
func IsSensitiveKey(k string) bool { return sensitiveKey.MatchString(k) }

// MaskMap returns a deep copy of m with sensitive values replaced.
func MaskMap(m map[string]any) map[string]any {
	if m == nil {
		return nil
	}
	out := make(map[string]any, len(m))
	for k, v := range m {
		if IsSensitiveKey(k) {
			out[k] = Masked
			continue
		}
		switch t := v.(type) {
		case map[string]any:
			out[k] = MaskMap(t)
		case map[string]string:
			mm := make(map[string]any, len(t))
			for kk, vv := range t {
				mm[kk] = vv
			}
			out[k] = MaskMap(mm)
		default:
			out[k] = v
		}
	}
	return out
}

// MaskArgs hides secrets in a command argument list. It masks:
//   - literal values listed in secrets
//   - "--password=x" / "KEY=VALUE" forms with a sensitive name
//   - the value following a sensitive flag ("--password x")
func MaskArgs(args []string, secrets []string) []string {
	out := make([]string, len(args))
	maskNext := false
	for i, a := range args {
		switch {
		case maskNext:
			out[i] = Masked
			maskNext = false
			continue
		case strings.HasPrefix(a, "-") && !strings.Contains(a, "=") && IsSensitiveKey(strings.TrimLeft(a, "-")):
			out[i] = a
			maskNext = true
			continue
		}
		if k, _, ok := strings.Cut(a, "="); ok && IsSensitiveKey(strings.TrimLeft(k, "-")) {
			out[i] = k + "=" + Masked
			continue
		}
		out[i] = MaskString(a, secrets)
	}
	return out
}

// MaskString replaces every occurrence of each non-empty secret in s.
func MaskString(s string, secrets []string) string {
	for _, sec := range secrets {
		if len(sec) >= 4 { // very short strings would mangle normal text
			s = strings.ReplaceAll(s, sec, Masked)
		}
	}
	return s
}

// SlogReplaceAttr masks sensitive attributes in every slog record.
func SlogReplaceAttr(_ []string, a slog.Attr) slog.Attr {
	if IsSensitiveKey(a.Key) && a.Value.Kind() != slog.KindGroup {
		return slog.String(a.Key, Masked)
	}
	return a
}

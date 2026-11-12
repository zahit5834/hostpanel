package notify

import (
	"html"
	"strings"
	"unicode"
	"unicode/utf8"
)

// Message layout shared by Telegram (HTML) and e-mail (plain text). Producers
// keep writing plain "Title" + "Text"; the layout makes it readable:
//   - a blank line between title and body,
//   - one sentence per line,
//   - "Label: value" lines get a bold label (Telegram),
//   - a short line ending in ":" is a section header,
//   - navigation hints ("… → …") go to their own paragraph with 👉.

type lineKind int

const (
	lineText lineKind = iota
	lineBlank
	lineLabel  // label + ": " + rest
	lineHeader // "Section:"
	lineHint   // "Sunucu → Genel …"
)

type bodyLine struct {
	kind   lineKind
	bullet bool   // "• " list item
	label  string // lineLabel
	text   string
}

// layout splits the body into typed lines.
func layout(text string) []bodyLine {
	var out []bodyLine
	var hints []bodyLine
	for _, raw := range strings.Split(strings.ReplaceAll(text, "\r\n", "\n"), "\n") {
		raw = strings.TrimRight(raw, " \t")
		if strings.TrimSpace(raw) == "" {
			if len(out) > 0 && out[len(out)-1].kind != lineBlank {
				out = append(out, bodyLine{kind: lineBlank})
			}
			continue
		}
		if item, ok := strings.CutPrefix(raw, "• "); ok {
			if label, rest, ok := labelOf(item); ok && rest != "" {
				out = append(out, bodyLine{kind: lineLabel, bullet: true, label: label, text: rest})
			} else {
				out = append(out, bodyLine{kind: lineText, bullet: true, text: item})
			}
			continue
		}
		for _, s := range sentences(raw) {
			switch label, rest, ok := labelOf(s); {
			case ok && rest == "":
				out = append(out, bodyLine{kind: lineHeader, text: label + ":"})
			case ok:
				out = append(out, bodyLine{kind: lineLabel, label: label, text: rest})
			case strings.Contains(s, " → "):
				hints = append(hints, bodyLine{kind: lineHint, text: s})
			default:
				out = append(out, bodyLine{kind: lineText, text: s})
			}
		}
	}
	for len(out) > 0 && out[len(out)-1].kind == lineBlank {
		out = out[:len(out)-1]
	}
	if len(hints) > 0 {
		if len(out) > 0 {
			out = append(out, bodyLine{kind: lineBlank})
		}
		out = append(out, hints...)
	}
	return out
}

// sentences splits "A. B." into "A." and "B." at ". " followed by an upper
// case letter (indented and bullet lines stay whole).
func sentences(line string) []string {
	if strings.HasPrefix(line, " ") || strings.HasPrefix(line, "-") {
		return []string{line}
	}
	var out []string
	for {
		cut := -1
		for i := 0; i+2 < len(line); i++ {
			if line[i] != '.' || line[i+1] != ' ' {
				continue
			}
			r, _ := utf8.DecodeRuneInString(line[i+2:])
			if unicode.IsUpper(r) {
				cut = i + 1
				break
			}
		}
		if cut < 0 {
			return append(out, line)
		}
		out = append(out, line[:cut])
		line = strings.TrimLeft(line[cut:], " ")
	}
}

// labelOf recognises "Label: rest" with a short plain label (words, digits,
// parentheses) — not error texts such as `Get "http://…": dial tcp …`.
func labelOf(s string) (label, rest string, ok bool) {
	i := strings.Index(s, ":")
	if i <= 0 || (i+1 < len(s) && s[i+1] != ' ') {
		return "", "", false
	}
	label = s[:i]
	if utf8.RuneCountInString(label) > 32 {
		return "", "", false
	}
	for _, r := range label {
		if !(unicode.IsLetter(r) || unicode.IsDigit(r) || strings.ContainsRune(" ()'/-", r)) {
			return "", "", false
		}
	}
	return label, strings.TrimSpace(s[i+1:]), true
}

// telegramHTML renders an event for parse_mode=HTML; every piece of text is
// escaped, so producer strings cannot inject markup.
func telegramHTML(e Event) string {
	var b strings.Builder
	if e.Title != "" {
		b.WriteString(icon(e.Title) + "<b>" + html.EscapeString(e.Title) + "</b>")
		if e.Text != "" {
			b.WriteString("\n\n")
		}
	}
	for i, l := range layout(e.Text) {
		if i > 0 {
			b.WriteByte('\n')
		}
		if l.bullet {
			b.WriteString("• ")
		}
		switch l.kind {
		case lineLabel:
			b.WriteString("<b>" + html.EscapeString(l.label) + ":</b> " + html.EscapeString(l.text))
		case lineHeader:
			b.WriteString("<b>" + html.EscapeString(l.text) + "</b>")
		case lineHint:
			b.WriteString("👉 <i>" + html.EscapeString(l.text) + "</i>")
		case lineText:
			b.WriteString(html.EscapeString(l.text))
		}
	}
	return b.String()
}

// telegramPlain is the fallback when Telegram rejects the HTML.
func telegramPlain(e Event) string {
	if e.Title == "" {
		return plainBody(e.Text)
	}
	return icon(e.Title) + message(e)
}

// icon prefixes 🖥 unless the title already starts with its own emoji (🔴, ⚠️).
func icon(title string) string {
	r, _ := utf8.DecodeRuneInString(title)
	if unicode.IsLetter(r) || unicode.IsDigit(r) {
		return "🖥 "
	}
	return ""
}

// message is the plain-text form (e-mail body, Telegram fallback).
func message(e Event) string {
	body := plainBody(e.Text)
	if body == "" {
		return e.Title
	}
	if e.Title == "" {
		return body
	}
	return e.Title + "\n\n" + body
}

func plainBody(text string) string {
	var b strings.Builder
	for i, l := range layout(text) {
		if i > 0 {
			b.WriteByte('\n')
		}
		if l.bullet {
			b.WriteString("• ")
		}
		switch l.kind {
		case lineLabel:
			b.WriteString(l.label + ": " + l.text)
		case lineHeader, lineText, lineHint:
			b.WriteString(l.text)
		}
	}
	return b.String()
}

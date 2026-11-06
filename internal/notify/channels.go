package notify

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"mime"
	"net"
	"net/http"
	"net/mail"
	"net/smtp"
	"net/url"
	"strconv"
	"strings"
	"time"
)

func message(e Event) string {
	if e.Text == "" {
		return e.Title
	}
	return e.Title + "\n" + e.Text
}

// telegram calls sendMessage. The token is part of the URL, so transport
// errors are reported without it.
func (s *Service) telegram(ctx context.Context, c Config, e Event) error {
	form := url.Values{"chat_id": {c.TelegramChat}, "text": {"🖥 " + message(e)}, "disable_web_page_preview": {"true"}}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, s.TelegramAPI+"/bot"+c.TelegramToken+"/sendMessage",
		strings.NewReader(form.Encode()))
	if err != nil {
		return errors.New("istek oluşturulamadı")
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	res, err := s.Client.Do(req)
	if err != nil {
		var ue *url.Error
		if errors.As(err, &ue) {
			err = ue.Err
		}
		return fmt.Errorf("bağlanılamadı: %s", strings.ReplaceAll(err.Error(), c.TelegramToken, "***"))
	}
	defer res.Body.Close()
	var out struct {
		OK          bool   `json:"ok"`
		Description string `json:"description"`
	}
	json.NewDecoder(io.LimitReader(res.Body, 64<<10)).Decode(&out)
	if !out.OK {
		if out.Description == "" {
			out.Description = res.Status
		}
		return fmt.Errorf("API hatası: %s", out.Description)
	}
	return nil
}

// buildMail renders an RFC 5322 message. Addresses were validated on save;
// the subject is single-line and Q-encoded.
func buildMail(c Config, e Event, now time.Time) []byte {
	subject := strings.NewReplacer("\r", " ", "\n", " ").Replace("[HostPanel] " + e.Title)
	var b strings.Builder
	fmt.Fprintf(&b, "From: %s\r\n", c.SMTPFrom)
	fmt.Fprintf(&b, "To: %s\r\n", c.SMTPTo)
	fmt.Fprintf(&b, "Subject: %s\r\n", mime.QEncoding.Encode("utf-8", subject))
	fmt.Fprintf(&b, "Date: %s\r\n", now.Format(time.RFC1123Z))
	b.WriteString("MIME-Version: 1.0\r\nContent-Type: text/plain; charset=utf-8\r\nContent-Transfer-Encoding: 8bit\r\n\r\n")
	body := strings.ReplaceAll(message(e), "\r\n", "\n")
	for _, line := range strings.Split(body, "\n") {
		if strings.HasPrefix(line, ".") {
			line = "." + line
		}
		b.WriteString(line + "\r\n")
	}
	return []byte(b.String())
}

// sendMail delivers over SMTP: port 465 uses implicit TLS, others require
// STARTTLS (credentials never travel in clear text).
func (s *Service) sendMail(ctx context.Context, c Config, e Event) error {
	addr := net.JoinHostPort(c.SMTPHost, strconv.Itoa(c.SMTPPort))
	if s.SMTPAddr != "" {
		addr = s.SMTPAddr
	}
	d := net.Dialer{}
	conn, err := d.DialContext(ctx, "tcp", addr)
	if err != nil {
		return fmt.Errorf("SMTP sunucusuna bağlanılamadı: %w", err)
	}
	if dl, ok := ctx.Deadline(); ok {
		conn.SetDeadline(dl)
	}
	tlsConf := &tls.Config{ServerName: c.SMTPHost, MinVersion: tls.VersionTLS12, RootCAs: s.RootCAs}
	if c.SMTPPort == 465 {
		conn = tls.Client(conn, tlsConf)
	}
	cl, err := smtp.NewClient(conn, c.SMTPHost)
	if err != nil {
		conn.Close()
		return fmt.Errorf("SMTP: %w", err)
	}
	defer cl.Close()
	if c.SMTPPort != 465 {
		if ok, _ := cl.Extension("STARTTLS"); !ok {
			return errors.New("SMTP sunucusu STARTTLS desteklemiyor")
		}
		if err := cl.StartTLS(tlsConf); err != nil {
			return fmt.Errorf("STARTTLS: %w", err)
		}
	}
	if c.SMTPUser != "" {
		if err := cl.Auth(smtp.PlainAuth("", c.SMTPUser, c.SMTPPass, c.SMTPHost)); err != nil {
			return fmt.Errorf("SMTP kimlik doğrulama: %w", err)
		}
	}
	from, _ := mail.ParseAddress(c.SMTPFrom)
	to, _ := mail.ParseAddress(c.SMTPTo)
	if from == nil || to == nil {
		return errors.New("geçersiz e-posta adresi")
	}
	if err := cl.Mail(from.Address); err != nil {
		return err
	}
	if err := cl.Rcpt(to.Address); err != nil {
		return err
	}
	w, err := cl.Data()
	if err != nil {
		return err
	}
	if _, err := w.Write(buildMail(c, e, time.Now())); err != nil {
		return err
	}
	if err := w.Close(); err != nil {
		return err
	}
	return cl.Quit()
}

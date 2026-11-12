package mail

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/zahit5834/hostpanel/internal/store"
)

// Outgoing mail limits (Rspamd ratelimit per authenticated mailbox).
const (
	DefaultRatePerHour = 200
	MinRatePerHour     = 10
	MaxRatePerHour     = 10000
	DefaultQueueAlert  = 50
	MaxQueueAlert      = 100000
	// heavyWindow is the look-back of the unusual sending alarm (the
	// monitor's periodic hooks run every 10 minutes).
	heavyWindow = 10
)

// CheckRate validates a sending limit (0 = none).
func CheckRate(n int) error {
	if n != 0 && (n < MinRatePerHour || n > MaxRatePerHour) {
		return fmt.Errorf("saatlik sınır 0 (sınırsız) ya da %d–%d arasında olmalı", MinRatePerHour, MaxRatePerHour)
	}
	return nil
}

// Sender is one authenticated mailbox and the messages it submitted.
type Sender struct {
	Address string
	Count   int
}

// ParseSentStats parses `hp-mail.sh sent-stats`: "<addr> <n>" lines, most
// active first.
func ParseSentStats(out string) []Sender {
	var ss []Sender
	for _, line := range strings.Split(out, "\n") {
		f := strings.Fields(line)
		if len(f) != 2 || !ValidAddress(f[0]) {
			continue
		}
		if n, err := strconv.Atoi(f[1]); err == nil && n > 0 {
			ss = append(ss, Sender{Address: f[0], Count: n})
		}
	}
	sort.Slice(ss, func(i, j int) bool {
		if ss[i].Count != ss[j].Count {
			return ss[i].Count > ss[j].Count
		}
		return ss[i].Address < ss[j].Address
	})
	return ss
}

// mailbox validates addr and returns the server and the mailbox (s.mu held).
func (s *Service) mailbox(ctx context.Context, addr string) (Server, Mailbox, error) {
	if err := s.ownAddress(ctx, addr); err != nil {
		return Server{}, Mailbox{}, err
	}
	srv, err := s.server(ctx)
	if err != nil {
		return srv, Mailbox{}, err
	}
	l, err := s.Listing(ctx)
	if err != nil {
		return srv, Mailbox{}, err
	}
	m, ok := l.Mailbox(addr)
	if !ok {
		return srv, m, errors.New("posta kutusu bulunamadı")
	}
	return srv, m, nil
}

func onOff(on bool) string {
	if on {
		return "on"
	}
	return "off"
}

// SetSuspended turns IMAP and SMTP login of a mailbox off (mail keeps
// arriving, nothing is deleted) or back on.
func (s *Service) SetSuspended(ctx context.Context, addr string, on bool) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, _, err := s.mailbox(ctx, addr); err != nil {
		return err
	}
	if _, err := s.helper(ctx, nil, nil, nil, time.Minute, "account-suspend", addr, onOff(on)); err != nil {
		return err
	}
	if s.Fake != nil {
		s.Fake.setFlag(addr, true, on)
	}
	return nil
}

// SetSendBlocked refuses (or allows again) the submissions of a mailbox;
// IMAP and incoming mail are not affected.
func (s *Service) SetSendBlocked(ctx context.Context, addr string, on bool) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, _, err := s.mailbox(ctx, addr); err != nil {
		return err
	}
	if _, err := s.helper(ctx, nil, nil, nil, time.Minute, "send-block", addr, onOff(on)); err != nil {
		return err
	}
	if s.Fake != nil {
		s.Fake.setFlag(addr, false, on)
	}
	return nil
}

// PurgeQueue deletes the queued messages of one sender and returns how many.
func (s *Service) PurgeQueue(ctx context.Context, addr string) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, _, err := s.mailbox(ctx, addr); err != nil {
		return 0, err
	}
	if _, err := s.runningServer(ctx); err != nil {
		return 0, err
	}
	res, err := s.helper(ctx, nil, nil, nil, 2*time.Minute, "queue-purge", addr)
	if err != nil {
		return 0, err
	}
	n, _ := strconv.Atoi(parseKV(res.Stdout, "deleted"))
	return max(n, 0), nil
}

// SetCatchAll sends mail for unknown addresses of a domain to one mailbox
// of the same customer ("" turns it off).
func (s *Service) SetCatchAll(ctx context.Context, domainID int64, target string) error {
	d, err := s.Store.Domain(ctx, domainID)
	if err != nil {
		return errors.New("alan adı bulunamadı")
	}
	target = NormalizeAddress(target)
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, err := s.server(ctx); err != nil {
		return err
	}
	arg := "-"
	if target != "" {
		if !ValidAddress(target) {
			return errors.New("geçersiz hedef")
		}
		td, err := s.Store.DomainByName(ctx, DomainOf(target))
		if err != nil || td.CustomerID != d.CustomerID {
			return errors.New("hedef, aynı müşterinin bir posta kutusu olmalı")
		}
		l, err := s.Listing(ctx)
		if err != nil {
			return err
		}
		if !l.HasMailbox(target) {
			return errors.New("hedef bir posta kutusu olmalı (yönlendirme ya da dış adres olamaz)")
		}
		arg = target
	}
	if _, err := s.helper(ctx, nil, nil, nil, time.Minute, "catchall", d.Name, arg); err != nil {
		return err
	}
	if s.Fake != nil {
		s.Fake.setCatchAll(d.Name, target)
	}
	return nil
}

// SetLimits stores the sending limit (written to Rspamd) and the queue alarm.
func (s *Service) SetLimits(ctx context.Context, ratePerHour, queueAlert int) error {
	if err := CheckRate(ratePerHour); err != nil {
		return err
	}
	if queueAlert < 0 || queueAlert > MaxQueueAlert {
		return fmt.Errorf("kuyruk uyarısı 0 (kapalı) – %d arasında olmalı", MaxQueueAlert)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	srv, err := s.server(ctx)
	if err != nil {
		return err
	}
	if srv.Status == StatusInstalling || srv.Status == StatusError {
		return errors.New("posta sunucusu kurulumu tamamlanmadı")
	}
	if ratePerHour != srv.RatePerHour {
		if _, err := s.helper(ctx, nil, nil, nil, time.Minute, "ratelimit", strconv.Itoa(ratePerHour)); err != nil {
			return err
		}
	}
	return s.Store.SetLimits(ctx, srv.ID, ratePerHour, queueAlert)
}

// applyRate writes the stored limit again (after a restore or a panel
// update: the files may hold another value or none).
func (s *Service) applyRate(ctx context.Context, w io.Writer, srv Server) error {
	_, err := s.helper(ctx, w, nil, nil, time.Minute, "ratelimit", strconv.Itoa(srv.RatePerHour))
	return err
}

// opsRev is the revision of the Rspamd overrides hp-mail.sh writes (1: send
// limits and block lists, Faz 13).
const (
	opsRev        = "1"
	settingOpsRev = "mail_ops_rev"
)

// EnsureOps writes the Rspamd overrides once for servers installed before
// they existed (the panel update runs the previous hp-update.sh).
func (s *Service) EnsureOps(ctx context.Context) {
	if store.GetSetting(ctx, s.DB, settingOpsRev, "") == opsRev {
		return
	}
	srv, err := s.Store.Server(ctx)
	if err != nil || srv.Status == StatusInstalling || srv.Status == StatusError {
		return
	}
	if err := s.applyRate(ctx, nil, srv); err != nil {
		s.Log.Warn("mail rspamd overrides failed", "err", err)
		return
	}
	store.SetSetting(ctx, s.DB, settingOpsRev, opsRev)
	s.Log.Info("mail rspamd overrides written", "rate_per_hour", srv.RatePerHour)
}

// SentStats returns the submissions per mailbox of the last minutes.
func (s *Service) SentStats(ctx context.Context, minutes int) ([]Sender, error) {
	if minutes < 1 || minutes > 1440 {
		return nil, errors.New("geçersiz süre")
	}
	if s.Fake != nil {
		return s.Fake.sentStats(), nil
	}
	if _, err := s.runningServer(ctx); err != nil {
		return nil, err
	}
	res, err := s.helper(ctx, nil, nil, nil, time.Minute, "sent-stats", strconv.Itoa(minutes))
	if err != nil {
		return nil, err
	}
	return ParseSentStats(res.Stdout), nil
}

// Alarm is a notification raised by Watch.
type Alarm struct {
	Key, Title, Text string
}

const settingWatchState = "mail_watch_state"

type watchState struct {
	QueueAlerted bool `json:"queue_alerted,omitempty"`
}

// heavyThreshold is the 10-minute count that counts as unusual: half the
// hourly limit (100 when there is none).
func heavyThreshold(rate int) int {
	if rate <= 0 {
		return 100
	}
	return max(rate/2, 5)
}

// Watch checks the queue and the senders of the last 10 minutes (monitor's
// periodic hook; only while the server is meant to run). A queue alarm is
// raised once until the queue drops below the threshold again; unusual
// senders are deduplicated per mailbox by the notifier (one per hour).
func (s *Service) Watch(ctx context.Context) []Alarm {
	srv, err := s.Store.Server(ctx)
	if err != nil || srv.Status != StatusRunning {
		return nil
	}
	var st watchState
	json.Unmarshal([]byte(store.GetSetting(ctx, s.DB, settingWatchState, "{}")), &st)
	var out []Alarm
	if srv.QueueAlert > 0 {
		if n, err := s.Queue(ctx); err == nil {
			switch {
			case n >= srv.QueueAlert && !st.QueueAlerted:
				st.QueueAlerted = true
				out = append(out, Alarm{Key: "mail.queue", Title: "Posta kuyruğu birikiyor",
					Text: fmt.Sprintf("Kuyrukta %d ileti bekliyor (eşik %d). Bir hesap ele geçirilmiş ya da alıcı sunucular reddediyor olabilir: E-posta → Teslim edilebilirlik.", n, srv.QueueAlert)})
			case n < srv.QueueAlert && st.QueueAlerted:
				st.QueueAlerted = false
			}
		}
	}
	if senders, err := s.SentStats(ctx, heavyWindow); err == nil {
		limit := heavyThreshold(srv.RatePerHour)
		for _, x := range senders {
			if x.Count < limit {
				break
			}
			out = append(out, Alarm{Key: "mail.heavy:" + x.Address, Title: "Olağan dışı posta gönderimi: " + x.Address,
				Text: fmt.Sprintf("%s son %d dakikada %d ileti gönderdi (saatlik sınır %s). Hesap ele geçirilmiş olabilir: E-posta → alan adı → Erişim → Gönderimi durdur.",
					x.Address, heavyWindow, x.Count, rateText(srv.RatePerHour))})
		}
	}
	b, _ := json.Marshal(st)
	store.SetSetting(ctx, s.DB, settingWatchState, string(b))
	return out
}

func rateText(n int) string {
	if n == 0 {
		return "yok"
	}
	return strconv.Itoa(n)
}

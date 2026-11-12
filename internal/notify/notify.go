// Package notify sends admin notifications over Telegram and e-mail (SMTP).
// Other packages get a Send func injected; every delivery is recorded in the
// activity log.
package notify

import (
	"context"
	"crypto/x509"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"net/mail"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/zahit5834/hostpanel/internal/crypto"
	"github.com/zahit5834/hostpanel/internal/logs"
	"github.com/zahit5834/hostpanel/internal/store"
)

// Event kinds (each can be switched on/off in Ayarlar → Bildirimler).
const (
	KindSiteStatus  = "site.status" // site.down / site.up
	KindRestarting  = "site.restarting"
	KindSSLExpiring = "ssl.expiring"
	KindBackup      = "backup.failed"
	KindDisk        = "disk.high"
	KindLoginFailed = "login.failed"
	KindLoginNewIP  = "login.newip"
	KindCron        = "cron.failed"
	KindUpdate      = "panel.update"
	KindSecurity    = "security" // SSH/UFW/fail2ban changes, script integrity, audit findings
	KindSystem      = "system"   // reboot, OOM, memory, OS updates
	KindInfra       = "infra"    // nginx/docker/named/fail2ban, DB and mail containers, certbot timer down/up
	KindDomain      = "domain.expiring"
	KindVerify      = "backup.verify" // weekly restore drill result
	KindSummary     = "summary"       // daily/weekly digest (sent only when scheduled)
	KindTest        = "test"
)

// Kinds lists the switchable kinds with their Turkish labels, in display order.
var Kinds = []struct{ ID, Label string }{
	{KindSiteStatus, "Site çöktü / tekrar açıldı"},
	{KindRestarting, "Site sürekli yeniden başlıyor"},
	{KindSSLExpiring, "SSL sertifikası bitiyor"},
	{KindBackup, "Yedek başarısız"},
	{KindDisk, "Disk %85 üzeri"},
	{KindCron, "Site cron görevi başarısız"},
	{KindUpdate, "Panel, container ve .NET/Node güncellemeleri (yeni sürüm / sonuç)"},
	{KindInfra, "Altyapı: nginx, Docker, DNS, fail2ban, veritabanı ve posta container'ları düştü / düzeldi"},
	{KindDomain, "Alan adının kayıt süresi doluyor (30/15/7 gün)"},
	{KindVerify, "Yedek doğrulama sonucu (haftalık kurtarma provası)"},
	{KindSummary, "Günlük / haftalık özet (Ayarlar → Bildirimler'de zamanlanınca)"},
	{KindSecurity, "Güvenlik: SSH/UFW/fail2ban değişiklikleri, script bütünlüğü, denetim bulguları"},
	{KindSystem, "Sunucu: yeniden başlatma, bellek yetersizliği (OOM), sistem güncellemeleri"},
	{KindLoginFailed, "Başarısız panel girişi"},
	{KindLoginNewIP, "Yeni IP'den panel girişi"},
}

// DefaultKinds are enabled until the admin changes the selection.
var DefaultKinds = []string{KindSiteStatus, KindRestarting, KindSSLExpiring, KindBackup, KindDisk, KindCron, KindUpdate, KindLoginNewIP,
	KindSecurity, KindSystem, KindInfra, KindDomain, KindVerify, KindSummary}

// legacyKnown are the kinds that existed before setKnown was stored (Faz 11):
// a saved selection that predates a default kind gets it switched on.
var legacyKnown = []string{KindSiteStatus, KindRestarting, KindSSLExpiring, KindBackup, KindDisk, KindCron, KindUpdate,
	KindLoginFailed, KindLoginNewIP}

// Event is one notification.
type Event struct {
	Kind  string
	Key   string // dedupe key (default Kind); same key is sent at most once per Window
	Title string
	Text  string
	// NoDedupe sends even if the same key went out recently (state changes like down/up).
	NoDedupe bool
}

// Window is the dedupe window.
const Window = time.Hour

// Settings keys.
const (
	setTGEnabled  = "notify_telegram_enabled"
	setTGToken    = "notify_telegram_token_sealed"
	setTGChat     = "notify_telegram_chat"
	setSMEnabled  = "notify_smtp_enabled"
	setSMHost     = "notify_smtp_host"
	setSMPort     = "notify_smtp_port"
	setSMUser     = "notify_smtp_user"
	setSMPass     = "notify_smtp_pass_sealed"
	setSMFrom     = "notify_smtp_from"
	setSMTo       = "notify_smtp_to"
	setKinds      = "notify_kinds"
	setKnown      = "notify_kinds_known" // kinds that existed when the selection was saved
	setKnownIPs   = "notify_known_ips"
	maxKnownIPs   = 20
	sendTimeout   = 15 * time.Second
	queueCapacity = 32
)

// Config is the notification settings (secrets opened).
type Config struct {
	TelegramOn    bool
	TelegramToken string
	TelegramChat  string
	SMTPOn        bool
	SMTPHost      string
	SMTPPort      int
	SMTPUser      string
	SMTPPass      string
	SMTPFrom      string
	SMTPTo        string
	Kinds         []string
	Commands      bool // Telegram commands are answered
}

// Enabled reports whether events of kind are sent.
func (c Config) Enabled(kind string) bool { return kind == KindTest || slices.Contains(c.Kinds, kind) }

// Service queues and delivers notifications.
type Service struct {
	DB       *sql.DB
	Box      *crypto.Box
	Activity *logs.Activity
	Log      *slog.Logger
	// Client and TelegramAPI are overridable in tests.
	Client      *http.Client
	TelegramAPI string
	RootCAs     *x509.CertPool // SMTP TLS roots (nil = system)
	// SMTPAddr overrides host:port for dialing (tests); TLS still verifies SMTPHost.
	SMTPAddr string

	once    sync.Once
	queue   chan Event
	botWake chan struct{}
	mu      sync.Mutex
	last    map[string]time.Time
}

func (s *Service) init() {
	s.once.Do(func() {
		s.queue = make(chan Event, queueCapacity)
		s.botWake = make(chan struct{}, 1)
		s.last = map[string]time.Time{}
		if s.Client == nil {
			s.Client = &http.Client{Timeout: sendTimeout}
		}
		if s.TelegramAPI == "" {
			s.TelegramAPI = "https://api.telegram.org"
		}
	})
}

func (s *Service) get(ctx context.Context, k, def string) string {
	return store.GetSetting(ctx, s.DB, k, def)
}

// Load reads the settings.
func (s *Service) Load(ctx context.Context) Config {
	c := Config{
		TelegramOn: s.get(ctx, setTGEnabled, "") == "1", TelegramChat: s.get(ctx, setTGChat, ""),
		SMTPOn: s.get(ctx, setSMEnabled, "") == "1", SMTPHost: s.get(ctx, setSMHost, ""), SMTPUser: s.get(ctx, setSMUser, ""),
		SMTPFrom: s.get(ctx, setSMFrom, ""), SMTPTo: s.get(ctx, setSMTo, ""),
		Commands: s.get(ctx, setTGCommands, "") == "1",
	}
	c.SMTPPort, _ = strconv.Atoi(s.get(ctx, setSMPort, "587"))
	if v := s.get(ctx, setTGToken, ""); v != "" {
		c.TelegramToken, _ = s.Box.OpenString(v)
	}
	if v := s.get(ctx, setSMPass, ""); v != "" {
		c.SMTPPass, _ = s.Box.OpenString(v)
	}
	if raw := s.get(ctx, setKinds, ""); raw != "" {
		json.Unmarshal([]byte(raw), &c.Kinds)
		known := legacyKnown
		if kr := s.get(ctx, setKnown, ""); kr != "" {
			known = nil
			json.Unmarshal([]byte(kr), &known)
		}
		for _, k := range DefaultKinds {
			if !slices.Contains(known, k) && !slices.Contains(c.Kinds, k) {
				c.Kinds = append(c.Kinds, k) // added after the admin's last save
			}
		}
	} else {
		c.Kinds = DefaultKinds
	}
	return c
}

var (
	tokenRe = regexp.MustCompile(`^[0-9]{5,20}:[A-Za-z0-9_-]{30,64}$`)
	chatRe  = regexp.MustCompile(`^(-?[0-9]{1,20}|@[A-Za-z][A-Za-z0-9_]{4,31})$`)
	hostRe  = regexp.MustCompile(`^[A-Za-z0-9]([A-Za-z0-9.-]{0,251}[A-Za-z0-9])?$`)
)

// Input is the settings form. Empty secrets keep the stored ones.
type Input struct {
	TelegramOn    bool
	TelegramToken string
	TelegramChat  string
	SMTPOn        bool
	SMTPHost      string
	SMTPPort      int
	SMTPUser      string
	SMTPPass      string
	SMTPFrom      string
	SMTPTo        string
	Kinds         []string
	Commands      bool // answer Telegram commands (I5)
}

// Save validates and stores the settings.
func (s *Service) Save(ctx context.Context, in Input) error {
	cur := s.Load(ctx)
	in.TelegramToken, in.TelegramChat = strings.TrimSpace(in.TelegramToken), strings.TrimSpace(in.TelegramChat)
	in.SMTPHost, in.SMTPUser = strings.TrimSpace(in.SMTPHost), strings.TrimSpace(in.SMTPUser)
	in.SMTPFrom, in.SMTPTo = strings.TrimSpace(in.SMTPFrom), strings.TrimSpace(in.SMTPTo)
	token := in.TelegramToken
	if token == "" {
		token = cur.TelegramToken
	}
	if in.TelegramToken != "" && !tokenRe.MatchString(in.TelegramToken) {
		return errors.New("geçersiz Telegram bot token'ı (BotFather'ın verdiği 123456:ABC… biçimi)")
	}
	if in.TelegramChat != "" && !chatRe.MatchString(in.TelegramChat) {
		return errors.New("geçersiz Telegram chat ID")
	}
	if in.TelegramOn && (token == "" || in.TelegramChat == "") {
		return errors.New("bildirim için Telegram bot token'ı ve chat ID gerekli")
	}
	if in.Commands {
		if !in.TelegramOn {
			return errors.New("komutlar için Telegram kanalı etkin olmalı")
		}
		if _, err := strconv.ParseInt(in.TelegramChat, 10, 64); err != nil {
			return errors.New("komutlar için sayısal bir Telegram chat ID (botla özel sohbetiniz) gerekir; @kanal adı olmaz")
		}
	}
	if in.SMTPHost != "" && !hostRe.MatchString(in.SMTPHost) {
		return errors.New("geçersiz SMTP sunucusu")
	}
	if in.SMTPPort == 0 {
		in.SMTPPort = 587
	}
	if in.SMTPPort < 1 || in.SMTPPort > 65535 {
		return errors.New("geçersiz SMTP portu")
	}
	if strings.ContainsAny(in.SMTPUser, "\r\n") || len(in.SMTPUser) > 200 || len(in.SMTPPass) > 200 {
		return errors.New("geçersiz SMTP kullanıcı adı/şifresi")
	}
	for _, a := range []string{in.SMTPFrom, in.SMTPTo} {
		if a != "" {
			if _, err := mail.ParseAddress(a); err != nil || strings.ContainsAny(a, "\r\n") {
				return fmt.Errorf("geçersiz e-posta adresi: %s", a)
			}
		}
	}
	if in.SMTPOn && (in.SMTPHost == "" || in.SMTPFrom == "" || in.SMTPTo == "") {
		return errors.New("e-posta için SMTP sunucusu, gönderen ve alıcı gerekli")
	}
	var kinds []string
	for _, k := range Kinds {
		if slices.Contains(in.Kinds, k.ID) {
			kinds = append(kinds, k.ID)
		}
	}
	if kinds == nil {
		kinds = []string{}
	}
	kj, _ := json.Marshal(kinds)
	all := make([]string, len(Kinds))
	for i, k := range Kinds {
		all[i] = k.ID
	}
	known, _ := json.Marshal(all)
	vals := map[string]string{
		setTGEnabled: b01(in.TelegramOn), setTGChat: in.TelegramChat,
		setSMEnabled: b01(in.SMTPOn), setSMHost: in.SMTPHost, setSMPort: strconv.Itoa(in.SMTPPort), setSMUser: in.SMTPUser,
		setSMFrom: in.SMTPFrom, setSMTo: in.SMTPTo, setKinds: string(kj), setKnown: string(known),
		setTGCommands: b01(in.Commands),
	}
	if in.TelegramToken != "" {
		v, err := s.Box.SealString(in.TelegramToken)
		if err != nil {
			return err
		}
		vals[setTGToken] = v
	}
	if in.SMTPPass != "" {
		v, err := s.Box.SealString(in.SMTPPass)
		if err != nil {
			return err
		}
		vals[setSMPass] = v
	}
	for k, v := range vals {
		if err := store.SetSetting(ctx, s.DB, k, v); err != nil {
			return err
		}
	}
	s.WakeBot()
	return nil
}

func b01(b bool) string {
	if b {
		return "1"
	}
	return "0"
}

// Run delivers queued notifications until ctx is cancelled.
func (s *Service) Run(ctx context.Context) {
	s.init()
	for {
		select {
		case <-ctx.Done():
			return
		case e := <-s.queue:
			s.deliver(ctx, s.Load(ctx), e)
		}
	}
}

// Send queues e if its kind is enabled and it was not sent within Window.
// It never blocks; a full queue drops the event (logged).
func (s *Service) Send(ctx context.Context, e Event) {
	if s == nil {
		return
	}
	s.init()
	c := s.Load(ctx)
	if !c.Enabled(e.Kind) || (!c.TelegramOn && !c.SMTPOn) {
		return
	}
	if e.Key == "" {
		e.Key = e.Kind
	}
	s.mu.Lock()
	if t, ok := s.last[e.Key]; ok && !e.NoDedupe && time.Since(t) < Window {
		s.mu.Unlock()
		return
	}
	s.last[e.Key] = time.Now()
	for k, t := range s.last { // keep the map small
		if time.Since(t) > Window {
			delete(s.last, k)
		}
	}
	s.mu.Unlock()
	select {
	case s.queue <- e:
	default:
		s.Log.Warn("notification queue full, dropped", "kind", e.Kind)
	}
}

// Test sends a test message synchronously to every configured channel.
func (s *Service) Test(ctx context.Context) error {
	s.init()
	c := s.Load(ctx)
	if !c.TelegramOn && !c.SMTPOn {
		return errors.New("etkin bildirim kanalı yok")
	}
	return s.deliver(ctx, c, Event{Kind: KindTest, Title: "HostPanel test bildirimi", Text: "Bildirimler çalışıyor."})
}

func (s *Service) deliver(ctx context.Context, c Config, e Event) error {
	var errs []error
	try := func(channel string, send func(context.Context) error) {
		sctx, cancel := context.WithTimeout(ctx, sendTimeout)
		err := send(sctx)
		cancel()
		entry := logs.Entry{Action: "notify.sent", TargetType: "notify", TargetID: channel,
			Summary: "Bildirim (" + channel + "): " + e.Title, Status: logs.StatusSuccess}
		if err != nil {
			entry.Action, entry.Status, entry.Error = "notify.failed", logs.StatusFailed, err.Error()
			errs = append(errs, fmt.Errorf("%s: %w", channel, err))
		}
		// Recorded with a background actor: notifications are system events.
		s.Activity.Record(context.WithoutCancel(ctx), entry, map[string]any{"kind": e.Kind})
	}
	if c.TelegramOn {
		try("telegram", func(ctx context.Context) error { return s.telegram(ctx, c, e) })
	}
	if c.SMTPOn {
		try("email", func(ctx context.Context) error { return s.sendMail(ctx, c, e) })
	}
	return errors.Join(errs...)
}

// --- login helpers ---

// NewIP records ip as known and reports whether it was new.
func (s *Service) NewIP(ctx context.Context, ip string) bool {
	if ip == "" {
		return false
	}
	var known []string
	json.Unmarshal([]byte(s.get(ctx, setKnownIPs, "[]")), &known)
	if slices.Contains(known, ip) {
		return false
	}
	first := len(known) == 0
	known = append([]string{ip}, known...)
	if len(known) > maxKnownIPs {
		known = known[:maxKnownIPs]
	}
	b, _ := json.Marshal(known)
	store.SetSetting(ctx, s.DB, setKnownIPs, string(b))
	return !first // the very first login is not "new"
}

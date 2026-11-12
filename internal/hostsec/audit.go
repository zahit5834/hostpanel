package hostsec

import (
	"fmt"
	"net/netip"
	"slices"
	"strconv"
	"strings"
	"time"
)

// Levels of an audit finding.
const (
	LevelOK   = "ok"
	LevelWarn = "warn"
	LevelBad  = "bad"
	LevelInfo = "info" // could not be checked (dry-run, not installed)
)

// Finding is one row of Güvenlik → denetim.
type Finding struct {
	ID     string
	Title  string
	Level  string
	Detail string
	Link   string // where to fix it
}

// Listener is one listening socket ("ss -ltnuH").
type Listener struct {
	Proto string // tcp|udp
	Addr  netip.Addr
	Port  int
}

// Public reports whether the socket accepts connections from other hosts.
func (l Listener) Public() bool { return !l.Addr.IsLoopback() }

// ParseSS reads "ss -ltnuH" (Netid State Recv-Q Send-Q Local:Port Peer:Port …).
func ParseSS(out string) []Listener {
	var res []Listener
	seen := map[string]bool{}
	for _, line := range strings.Split(out, "\n") {
		f := strings.Fields(line)
		if len(f) < 5 || (f[0] != "tcp" && f[0] != "udp") {
			continue
		}
		local := f[4]
		i := strings.LastIndexByte(local, ':')
		if i < 0 {
			continue
		}
		port, err := strconv.Atoi(local[i+1:])
		if err != nil {
			continue
		}
		host := strings.Trim(local[:i], "[]")
		if j := strings.IndexByte(host, '%'); j >= 0 {
			host = host[:j] // 127.0.0.53%lo
		}
		var a netip.Addr
		switch host {
		case "*", "0.0.0.0":
			a = netip.IPv4Unspecified()
		case "::":
			a = netip.IPv6Unspecified()
		default:
			if a, err = netip.ParseAddr(host); err != nil {
				continue
			}
		}
		key := f[0] + " " + a.String() + " " + strconv.Itoa(port)
		if seen[key] {
			continue
		}
		seen[key] = true
		res = append(res, Listener{Proto: f[0], Addr: a, Port: port})
	}
	return res
}

// PortInfo names an expected port.
type PortInfo struct {
	Proto string // tcp|udp|"" (both)
	Port  int
	Label string
}

// UnexpectedPorts returns the public listening ports that are not in expect,
// as "tcp/135" strings (sorted, one per proto+port).
func UnexpectedPorts(ls []Listener, expect []PortInfo) []string {
	var out []string
	for _, l := range ls {
		if !l.Public() {
			continue
		}
		ok := false
		for _, e := range expect {
			if e.Port == l.Port && (e.Proto == "" || e.Proto == l.Proto) {
				ok = true
				break
			}
		}
		if s := l.Proto + "/" + strconv.Itoa(l.Port); !ok && !slices.Contains(out, s) {
			out = append(out, s)
		}
	}
	slices.Sort(out)
	return out
}

// AuditInput is everything the rules look at; the web layer gathers it so
// this package stays free of the other services.
type AuditInput struct {
	Now    time.Time
	DryRun bool

	SSH    *SSHStatus // nil = could not be read
	SSHErr string

	UFWInstalled, UFWActive bool
	UFWErr                  string
	Listeners               []Listener
	ListenErr               string
	Expected                []PortInfo
	DockerPorts             []int // published by Docker (bypass UFW): mail 25/465/587/993

	F2B    *F2BStatus
	F2BErr string

	UnattendedOn    *bool // nil = unknown
	SecurityUpdates int
	RebootRequired  bool

	TOTP           bool
	Allowlist      bool
	LastExport     time.Time // zero = never
	RemoteBackups  bool      // Drive configured
	CryptOn        bool
	LastBackupOK   time.Time
	BackupsPlanned bool
	SSLSoon        []string // domains expiring within 15 days
	DBExternal     []string // "MSSQL (2 IP)", …

	Integrity        []IntegrityIssue
	IntegrityChecked bool
}

// Audit applies the rules. Order is the display order.
func Audit(in AuditInput) []Finding {
	var fs []Finding
	add := func(id, title, level, detail, link string) {
		fs = append(fs, Finding{ID: id, Title: title, Level: level, Detail: detail, Link: link})
	}

	// SSH
	switch {
	case in.SSH == nil:
		add("ssh", "SSH giriş ayarları", LevelInfo, "Okunamadı: "+in.SSHErr, "/server?tab=ssh")
	default:
		st := in.SSH
		if st.PasswordOff() {
			add("ssh.password", "SSH parola girişi", LevelOK, "Kapalı; yalnızca anahtarla girilebilir.", "/server?tab=ssh")
		} else {
			add("ssh.password", "SSH parola girişi", LevelBad,
				"Açık. İnternetteki botlar sürekli parola dener; anahtarla girişe geçip parolayı kapatın.", "/server?tab=ssh")
		}
		switch st.RootLogin {
		case "no":
			add("ssh.root", "root ile SSH girişi", LevelOK, "Kapalı.", "/server?tab=ssh")
		case "without-password", "prohibit-password", "forced-commands-only":
			add("ssh.root", "root ile SSH girişi", LevelOK, "Yalnızca anahtarla.", "/server?tab=ssh")
		default:
			add("ssh.root", "root ile SSH girişi", LevelBad, "Şifreyle de açık; en azından \"yalnızca anahtarla\" yapın.", "/server?tab=ssh")
		}
		if st.Pending {
			add("ssh.pending", "Onay bekleyen SSH değişikliği", LevelWarn, "Onaylanmazsa kendiliğinden geri alınır.", "/server?tab=ssh")
		}
	}

	// firewall
	switch {
	case in.UFWErr != "":
		add("ufw", "Güvenlik duvarı (UFW)", LevelInfo, "Okunamadı: "+in.UFWErr, "/server?tab=ufw")
	case !in.UFWInstalled:
		add("ufw", "Güvenlik duvarı (UFW)", LevelBad, "Kurulu değil.", "/server?tab=ufw")
	case !in.UFWActive:
		add("ufw", "Güvenlik duvarı (UFW)", LevelBad, "Etkin değil: tüm dinleyen portlar internete açık.", "/server?tab=ufw")
	default:
		add("ufw", "Güvenlik duvarı (UFW)", LevelOK, "Etkin.", "/server?tab=ufw")
	}
	if in.ListenErr != "" {
		add("ports", "Dışarıya açık portlar", LevelInfo, "Okunamadı: "+in.ListenErr, "/server?tab=ufw")
	} else {
		un := UnexpectedPorts(in.Listeners, in.Expected)
		var docker []string
		for _, p := range in.DockerPorts {
			docker = append(docker, strconv.Itoa(p))
		}
		note := ""
		if len(docker) > 0 {
			note = " Docker'ın yayınladığı portlar (" + strings.Join(docker, ", ") + ") UFW'yi atlar; bu bilinçli (posta)."
		}
		switch {
		case len(un) == 0:
			add("ports", "Dışarıya açık portlar", LevelOK, "Yalnızca beklenen servisler dinliyor."+note, "/server?tab=ufw")
		case in.UFWActive:
			add("ports", "Dışarıya açık portlar", LevelWarn, "Beklenmeyen dinleyen port: "+strings.Join(un, ", ")+
				". UFW etkin olduğu için izin kuralı yoksa dışarıdan erişilemez; yine de hangi servis olduğunu kontrol edin."+note, "/server?tab=ufw")
		default:
			add("ports", "Dışarıya açık portlar", LevelBad, "Beklenmeyen dinleyen port: "+strings.Join(un, ", ")+
				" ve UFW kapalı: bu portlar internete açık."+note, "/server?tab=ufw")
		}
	}

	// fail2ban
	switch {
	case in.F2B == nil:
		add("fail2ban", "fail2ban", LevelInfo, "Okunamadı: "+in.F2BErr, "/server?tab=fail2ban")
	case !in.F2B.Installed:
		add("fail2ban", "fail2ban", LevelBad, "Kurulu değil (install.sh kurar).", "/server?tab=fail2ban")
	case !in.F2B.Active:
		add("fail2ban", "fail2ban", LevelBad, "Çalışmıyor: kaba kuvvet denemeleri engellenmiyor.", "/server?tab=fail2ban")
	default:
		missing := []string{}
		for _, j := range []string{"sshd", "hostpanel"} {
			if in.F2B.Jail(j) == nil {
				missing = append(missing, j)
			}
		}
		if len(missing) > 0 {
			add("fail2ban", "fail2ban", LevelWarn, "Çalışıyor ama şu jail'ler kapalı: "+strings.Join(missing, ", ")+".", "/server?tab=fail2ban")
		} else {
			add("fail2ban", "fail2ban", LevelOK, fmt.Sprintf("Çalışıyor; şu an %d adres engelli.", in.F2B.TotalBanned()), "/server?tab=fail2ban")
		}
	}

	// updates
	switch {
	case in.UnattendedOn == nil:
		add("updates.auto", "Otomatik güvenlik güncellemeleri", LevelInfo, "Durum okunamadı.", "/server?tab=updates")
	case *in.UnattendedOn:
		add("updates.auto", "Otomatik güvenlik güncellemeleri", LevelOK, "Açık (unattended-upgrades).", "/server?tab=updates")
	default:
		add("updates.auto", "Otomatik güvenlik güncellemeleri", LevelWarn, "Kapalı; güvenlik yamalarını elle uygulamanız gerekir.", "/server?tab=updates")
	}
	if in.SecurityUpdates > 0 {
		add("updates.pending", "Bekleyen güvenlik güncellemesi", LevelWarn, fmt.Sprintf("%d paket.", in.SecurityUpdates), "/server?tab=updates")
	} else {
		add("updates.pending", "Bekleyen güvenlik güncellemesi", LevelOK, "Yok.", "/server?tab=updates")
	}
	if in.RebootRequired {
		add("reboot", "Yeniden başlatma", LevelWarn, "Güncellemelerin (çekirdek vb.) etkinleşmesi için yeniden başlatma gerekiyor.", "/server?tab=updates")
	}

	// panel
	if in.TOTP {
		add("panel.2fa", "Panel iki adımlı doğrulama", LevelOK, "Açık.", "/settings/security")
	} else {
		add("panel.2fa", "Panel iki adımlı doğrulama", LevelBad, "Kapalı: şifreyi ele geçiren panele girer.", "/settings/security")
	}
	if in.Allowlist {
		add("panel.allowlist", "Panel IP izin listesi", LevelOK, "Tanımlı.", "/settings/security")
	} else {
		add("panel.allowlist", "Panel IP izin listesi", LevelInfo, "Tanımlı değil (her IP giriş sayfasını görür; sabit IP'niz varsa önerilir).", "/settings/security")
	}
	switch {
	case in.LastExport.IsZero():
		add("panel.export", "Yapılandırma yedeği (master.key)", LevelWarn,
			"Hiç dışa aktarılmadı. Sunucu kaybolursa şifreli ayarlar ve Drive yedeklerindeki env değerleri açılamaz.", "/settings/transfer")
	case in.Now.Sub(in.LastExport) > 90*24*time.Hour:
		add("panel.export", "Yapılandırma yedeği (master.key)", LevelWarn,
			fmt.Sprintf("Son dışa aktarma %d gün önce.", int(in.Now.Sub(in.LastExport).Hours()/24)), "/settings/transfer")
	default:
		add("panel.export", "Yapılandırma yedeği (master.key)", LevelOK, "Son dışa aktarma: "+in.LastExport.Format("2006-01-02")+".", "/settings/transfer")
	}

	// backups
	switch {
	case !in.BackupsPlanned:
		add("backups", "Yedekler", LevelWarn, "Etkin yedek planı yok.", "/backups")
	case in.LastBackupOK.IsZero() || in.Now.Sub(in.LastBackupOK) > 48*time.Hour:
		add("backups", "Yedekler", LevelWarn, "Son 48 saatte başarılı yedek yok.", "/backups")
	default:
		add("backups", "Yedekler", LevelOK, "Son başarılı yedek: "+in.LastBackupOK.Format("2006-01-02 15:04")+".", "/backups")
	}
	if in.RemoteBackups {
		if in.CryptOn {
			add("backups.crypt", "Drive yedeklerinde şifreleme", LevelOK, "rclone crypt açık.", "/backups")
		} else {
			add("backups.crypt", "Drive yedeklerinde şifreleme", LevelWarn, "Kapalı: DB dökümleri ve dosyalar Drive'da düz duruyor.", "/backups")
		}
	}

	if len(in.SSLSoon) > 0 {
		add("ssl", "SSL sertifikaları", LevelWarn, "15 günden az kalan: "+strings.Join(in.SSLSoon, ", ")+".", "/ssl")
	} else {
		add("ssl", "SSL sertifikaları", LevelOK, "15 günden yakın bitiş yok.", "/ssl")
	}
	if len(in.DBExternal) > 0 {
		add("db.external", "Veritabanı dış erişimi", LevelWarn, "Açık: "+strings.Join(in.DBExternal, ", ")+". Gerekmiyorsa kapatın.", "/databases")
	}

	switch {
	case !in.IntegrityChecked:
		add("integrity", "Script bütünlüğü", LevelInfo, "Kontrol edilmedi.", "/security")
	case len(in.Integrity) == 0:
		add("integrity", "Script bütünlüğü", LevelOK, "Kurulu script'ler, şablonlar, sudoers ve servis dosyası bu sürümle aynı.", "/security")
	default:
		var parts []string
		for i, is := range in.Integrity {
			if i == 5 {
				parts = append(parts, fmt.Sprintf("… (+%d)", len(in.Integrity)-5))
				break
			}
			parts = append(parts, is.Path+" ("+is.Label()+")")
		}
		add("integrity", "Script bütünlüğü", LevelBad, "Sürümden farklı: "+strings.Join(parts, ", ")+
			". Panel dışında değiştirilmiş olabilir; aynı sürümle update.sh çalıştırmak düzeltir.", "/security")
	}
	return fs
}

// Score counts the findings per level.
func Score(fs []Finding) (ok, warn, bad int) {
	for _, f := range fs {
		switch f.Level {
		case LevelOK:
			ok++
		case LevelWarn:
			warn++
		case LevelBad:
			bad++
		}
	}
	return
}

// NewBad returns the IDs of bad findings that are not in prev (comma list).
func NewBad(fs []Finding, prev string) []Finding {
	old := strings.Split(prev, ",")
	var out []Finding
	for _, f := range fs {
		if f.Level == LevelBad && !slices.Contains(old, f.ID) {
			out = append(out, f)
		}
	}
	return out
}

// BadIDs is the comma list stored to compare with the next run.
func BadIDs(fs []Finding) string {
	var ids []string
	for _, f := range fs {
		if f.Level == LevelBad {
			ids = append(ids, f.ID)
		}
	}
	return strings.Join(ids, ",")
}

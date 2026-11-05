# HostPanel — Claude Code Geliştirme Promptu

> Bu dosyayı repo köküne `PROMPT.md` olarak koyup Claude Code'a "PROMPT.md dosyasını oku ve plan modunda Faz 0'dan başla" diyebilirsin.
> `HostPanel` / `hostpanel` adını istediğin isimle değiştir.

---

## 1. Görev

Tek bir yöneticinin (ben) kullanacağı, Ubuntu sunucuda müşteri web sitelerini barındırmak için **kendi kontrol panelimi** geliştirmeni istiyorum. cPanel/Plesk gibi çok kullanıcılı bir ürün değil; benim günlük işlerimi (site ekleme, SSL, yedekleme, veritabanı) birkaç tıklamaya indiren, sade ama sağlam bir panel olacak.

**En önemli tasarım hedefi: panel ultra hafif olmalı.** Sunucunun kaynakları müşteri sitelerine ve MSSQL'e ayrılmalı, panel neredeyse hiç kaynak tüketmemeli.

Panel doğrudan bu sunucuda geliştirilecek, ancak sonunda **başka bir temiz sunucuya GitHub'dan tek komutla kurulabilmeli**:

```bash
curl -fsSL https://raw.githubusercontent.com/<github-kullanici>/hostpanel/main/install.sh | sudo bash
```

Önce bu dokümanı baştan sona oku, sonra **plan modunda** mimariyi ve faz planını çıkar, bana onaylat, ardından faz faz ilerle.

---

## 2. Hedef ortam

- **OS:** Ubuntu 24.04 LTS (amd64; arm64 desteği de derlensin). install.sh başka sürümde çalıştırılırsa uyarı verip durmalı.
- **Barındırılacak siteler:** Çoğunluğu ASP.NET Core (.NET 10), bir kısmı Node.js. İleride PHP, statik HTML vb. eklenecek.
- **Veritabanı:** MSSQL (Docker üzerinde). Mimari, ileride PostgreSQL/MySQL eklenebilecek şekilde soyutlanmalı.
- **Kullanıcı:** Tek admin (ben). Müşterilerin panele erişimi yok.

---

## 3. Teknik kararlar

### 3.1 Dil: Go
Panel **Go** ile yazılacak (Go'nun güncel stabil sürümü).

Gerekçe:
- Tek, statik binary; runtime bağımlılığı yok.
- Boşta RAM kullanımı birkaç on MB seviyesinde.
- Panel aynı sunucuda geliştirileceği için derleme süresi ve derleme sırasındaki RAM tüketimi de önemli. Go saniyeler içinde, düşük bellekle derlenir; Rust'ın derleme yükü bu senaryoda sunucudaki sitelere zarar verebilir.

### 3.2 Kaynak bütçesi (zorunlu hedefler)
| Metrik | Hedef |
|---|---|
| Boşta RAM (RSS) | **< 30 MB** |
| Binary boyutu | **< 30 MB** (tüm statik dosyalar gömülü) |
| Boşta CPU | ~%0 (polling yok; gereksiz goroutine/timer yok) |
| Harici runtime | **Yok** (Node, .NET, Python gerekmez) |
| CGO | **Kapalı** (`CGO_ENABLED=0`) |

- systemd servisinde `MemoryMax=256M` ve `GOMEMLIMIT` ayarlansın.
- Her fazın sonunda boşta RAM ölçülüp rapora yazılsın. Hedef aşılırsa sebebini bul ve düzelt.

### 3.3 Teknoloji yığını
| Konu | Karar |
|---|---|
| HTTP | Standart kütüphane `net/http` (Go 1.22+ pattern routing). Ağır framework yok. |
| UI | Sunucu tarafı render: `html/template` + **HTMX** + çok az **Alpine.js**. SPA, React, Node build adımı **yok**. |
| CSS | Tek, küçük, elle yazılmış CSS dosyası veya hafif bir classless/minimal CSS kütüphanesi. Karanlık/aydınlık tema. |
| Statik dosyalar | `go:embed` ile binary'ye gömülü. HTMX/Alpine CDN'den değil, repoya dahil edilsin. |
| Panel veritabanı | **SQLite**, saf Go sürücüsü (`modernc.org/sqlite`, CGO gerektirmez). WAL modu. |
| Migration | Gömülü SQL migration dosyaları (küçük kendi runner'ın veya `goose`). |
| Gerçek zamanlı akış | **Server-Sent Events (SSE)** — canlı log ve iş ilerlemesi için. WebSocket gerekmez. |
| Zamanlanmış işler | `robfig/cron/v3` + SQLite'ta tutulan basit iş kuyruğu (job tablosu). |
| Loglama | Standart `log/slog` (JSON format, dosyaya + Log Merkezi'ne). |
| Şifre hash | argon2id (`golang.org/x/crypto`). |
| 2FA | TOTP (`pquerna/otp`), QR kod üretimi. |
| YAML | Bakımı süren bir YAML kütüphanesi (örn. `goccy/go-yaml`). |
| MSSQL | `microsoft/go-mssqldb` sürücüsü (login/DB işlemleri doğrudan SQL ile). |
| Reverse proxy | **Nginx** (her site için ayrı server block) |
| Süreç yönetimi | **systemd** (her .NET/Node sitesi için ayrı unit) |
| SSL | **certbot** (Let's Encrypt) + ücretli SSL için Go `crypto/x509` ile CSR üretimi ve doğrulama |
| Konteyner | **Docker Engine** (MSSQL için). Docker SDK yerine `docker` CLI helper script üzerinden çağrılsın (binary küçük kalsın). |
| Yedek aktarımı | **rclone** (Google Drive) |

**Bağımlılık kuralı:** Standart kütüphane ile yapılabilen bir şey için harici paket ekleme. Eklenen her bağımlılık CLAUDE.md'de gerekçesiyle listelensin.

Kod, fonksiyon/tip adları ve yorumlar **İngilizce**; UI metinleri **Türkçe**.

---

## 4. Mimari ve güvenlik ilkeleri (kritik)

### 4.1 Yetki ayrımı
- Panel **root olarak çalışmayacak**. `hostpanel` adında sistem kullanıcısıyla çalışacak.
- Root gerektiren işlemler (nginx config yazma, systemd unit oluşturma, kullanıcı açma, certbot, docker vb.) **`/opt/hostpanel/scripts/` altındaki küçük, tek amaçlı helper script'ler** üzerinden yapılacak.
- `/etc/sudoers.d/hostpanel` dosyasında **yalnızca bu script'lere** NOPASSWD izni verilecek. Genel `sudo bash` vb. kesinlikle yok.
- Her helper script kendi argümanlarını tekrar doğrulayacak (domain regex, path traversal kontrolü, izin verilen değer listeleri).
- Log okumak için sudo kullanılmayacak: `hostpanel` kullanıcısı `systemd-journal` ve `adm` gruplarına eklenecek (salt okunur log erişimi).

### 4.2 Komut çalıştırma
- Komutlar **asla `sh -c` ile veya string birleştirmeyle** çalıştırılmayacak. `exec.CommandContext(ctx, binary, args...)` ile argümanlar ayrı ayrı verilecek.
- Tüm komut çalıştırma tek bir `CommandRunner` arayüzünden geçsin: context timeout, stdout/stderr yakalama, exit code, Log Merkezi'ne kayıt.
- Kullanıcı girdileri (domain, kullanıcı adı, DB adı) whitelist regex ile doğrulanacak.

### 4.3 Atomik ve geri alınabilir işlemler
- Nginx config değişikliğinden sonra mutlaka `nginx -t`; başarısızsa eski config'e **otomatik geri dön**, sonra reload.
- Çok adımlı işlemler (site oluşturma vb.) bir adım başarısız olursa yapılanları geri alacak (basit compensation/rollback mantığı).
- Uzun süren işlemler (certbot, yedekleme, runtime kurulumu) arka plan job'ı olarak çalışsın, UI'da SSE ile canlı log ve ilerleme göstersin.

### 4.4 Gizli bilgiler
- DB şifreleri, rclone token'ı, SSL private key'leri, ortam değişkenleri **AES-256-GCM** ile şifrelenerek saklansın. Ana anahtar `/etc/hostpanel/master.key` dosyasında, izin `600`, sahibi `hostpanel`. Kurulumda üretilsin.
- Private key dosyaları diskte `600`, sahibi root.
- Hiçbir gizli bilgi log'a yazılmayacak; loglama katmanında bilinen hassas alanlar otomatik maskelensin.

### 4.5 Web güvenliği
- Session'lar SQLite'ta; cookie `HttpOnly`, `Secure`, `SameSite=Strict`.
- Tüm durum değiştiren isteklerde CSRF koruması.
- Güvenlik başlıkları: CSP (inline script yok), `X-Frame-Options: DENY`, `Referrer-Policy`.

### 4.6 Site izolasyonu
- Her site için ayrı Linux kullanıcısı: `site_<kısaad>` (login shell yok).
- Site dizini: `/var/www/sites/<domain>/` → izin `750`, sahibi site kullanıcısı, grup `www-data` (nginx statik dosya okuyabilsin).
- systemd unit'lerinde hardening: `NoNewPrivileges=true`, `PrivateTmp=true`, `ProtectSystem=strict`, `ProtectHome=true`, `ReadWritePaths=<site dizini>`, ayrıca site başına ayarlanabilir `MemoryMax` ve `CPUQuota`.

---

## 5. Dizin yapısı (sunucuda)

```
/opt/hostpanel/
  bin/hostpanel         # tek binary (UI, şablonlar, migration'lar gömülü)
  scripts/              # root yetkili helper script'ler
  templates/            # nginx / systemd şablonları (override edilebilir)
/etc/hostpanel/
  config.yaml
  master.key            # şifreleme anahtarı (600)
  runtimes/             # altyapı tanım dosyaları (*.yaml)
  ssl/<domain>/         # ücretli sertifikalar, CSR, key
/var/lib/hostpanel/
  hostpanel.db          # SQLite
/var/log/hostpanel/
  panel.log             # panelin kendi logu (JSON, logrotate'li)
  jobs/<job-id>.log     # arka plan işlerinin tam çıktıları
/var/www/sites/<domain>/
  releases/<timestamp>/ # deploy sürümleri
  current -> releases/<timestamp>
  shared/               # uploads, .env vb. kalıcı dosyalar
  logs/
/var/backups/hostpanel/<domain>/
/var/lib/hostpanel/mssql/   # MSSQL container volume
```

---

## 6. Özellikler

### 6.1 Kimlik doğrulama ve panel güvenliği
- Tek admin hesabı. İlk kurulumda install.sh rastgele güçlü bir şifre üretip ekrana bassın.
- Session tabanlı giriş + **TOTP 2FA** (Google Authenticator uyumlu, QR kod ile kurulum) + yedek kurtarma kodları.
- Giriş denemelerinde rate limiting; başarısız girişler Log Merkezi'ne ve ayrı bir dosyaya yazılsın, **fail2ban** jail'i eklensin.
- Ayarlardan isteğe bağlı **IP allowlist**.
- Panel kendi alt alan adında (örn. `panel.domain.com`) HTTPS ile yayınlansın; install sırasında domain verilmezse yalnızca `127.0.0.1:<port>` üzerinden dinlesin (SSH tunnel ile erişim).

### 6.2 Dashboard
- CPU, RAM, disk, uptime, load average (`/proc` üzerinden doğrudan okunsun, harici araç yok).
- Site listesi durumlarıyla (çalışıyor / durdu / hata), SSL bitiş tarihleri, son yedek durumu.
- Site başına RAM/CPU kullanımı (systemd cgroup verilerinden).
- Uyarı kartları: dolmak üzere olan disk, 15 günden az kalmış SSL, başarısız yedek, çöken site.
- **"Son İşlemler" kartı:** Log Merkezi'nden son 10 işlem (zaman, işlem, hedef, sonuç ikonu). Tıklayınca Log Merkezi'nde ilgili kayıt açılsın.
- Metrikler sayfa açıkken HTMX ile birkaç saniyede bir güncellensin; sayfa kapalıyken hiçbir toplama yapılmasın (geçmiş grafik istenmiyor, sadece anlık durum).

### 6.3 Müşteri yönetimi
- Müşteri kaydı: ad, firma, telefon, e-posta, notlar.
- Her müşterinin altında siteleri, veritabanları ve DB kullanıcısı listelensin.
- Müşteri oluşturulduğunda (isteğe bağlı) **otomatik MSSQL login** oluşturulsun (bkz. 6.7).
- Müşteri detayında o müşteriyle ilgili son işlemler (Log Merkezi filtresi).

### 6.4 Site yönetimi
**Site ekleme sihirbazı:**
1. Müşteri seç
2. Domain + alias'lar (`www` otomatik eklensin, www ↔ non-www yönlendirme seçeneği)
3. Altyapı seç (.NET / Node.js / Statik / ileride PHP) ve sürümü seç
4. Altyapıya özel ayarlar (.NET için başlangıç DLL'i, Node için başlangıç komutu vb.)
5. Kaynak limitleri (MemoryMax, CPUQuota) — varsayılan değerlerle
6. İsteğe bağlı: aynı anda veritabanı oluştur, Let's Encrypt SSL kur

Sihirbaz şunları yapar: Linux kullanıcısı, dizin yapısı, boş bir port ataması (127.0.0.1, 5000–5999 aralığı), systemd unit, nginx config, varsayılan "yakında" sayfası.

**Site işlemleri:** başlat, durdur, yeniden başlat, devre dışı bırak, sil.
- **Durdurulan** sitede nginx özel bir 503 bakım sayfası göstersin.
- **Silme:** domain adını yazarak onay; silmeden önce otomatik son yedek alınsın; Linux kullanıcısı, unit, nginx config, sertifika temizlensin (DB'yi silmek ayrı checkbox).
- **Bakım modu** aç/kapa (uygulama çalışırken bakım sayfası göster).

**Deploy:**
- **Zip yükleme:** yayınlanmış (`dotnet publish` / build edilmiş Node) çıktıyı zip olarak yükle → `releases/<timestamp>` içine aç → `current` symlink'ini değiştir → servisi yeniden başlat → health check. Yükleme stream edilsin, dosya belleğe alınmasın.
- **Git deploy (Faz 5):** repo URL + branch + deploy key; sunucuda build (.NET SDK / npm) seçeneği.
- **Rollback:** son 5 release tutulsun, tek tıkla önceki sürüme dön.
- `shared/` altındaki kalıcı dizinler (uploads vb.) her release'e symlink'lensin; hangi dizinlerin kalıcı olduğu site ayarından tanımlansın.

**Ortam değişkenleri editörü:** Site başına key/value; `ConnectionStrings__Default` vb. Şifreli saklanıp systemd `EnvironmentFile` (izin `600`) olarak yazılsın. Kaydedince "yeniden başlat" önerisi.

**Site logları:** Site detayında "Loglar" sekmesi — Log Merkezi'nin o siteye filtrelenmiş görünümü (uygulama journal'ı, nginx access/error, deploy ve SSL işlemleri).

**Nginx gelişmiş:** site başına özel nginx snippet alanı (doğrulamadan geçmeden kaydedilmesin), max upload boyutu, HTTPS zorunlu yönlendirme, gzip, HSTS seçenekleri.

**.NET siteleri için not:** Site detayında, uygulamanın nginx arkasında doğru çalışması için `UseForwardedHeaders` gerektiğini hatırlatan bilgi kutusu göster.

### 6.5 Genişletilebilir altyapı (runtime) sistemi
Altyapılar kod değişikliği gerektirmeden eklenebilmeli. Her altyapı `/etc/hostpanel/runtimes/<ad>.yaml` dosyasıyla tanımlansın:

```yaml
id: dotnet
displayName: ".NET"
type: proxy            # proxy | fastcgi | static
versions:
  list-command: "..."  # kurulu sürümleri listeler
  install-script: "install-dotnet.sh"   # scripts/runtimes/ altında
startCommand: "/usr/share/dotnet/dotnet {{entryPoint}}"
environment:
  ASPNETCORE_URLS: "http://127.0.0.1:{{port}}"
  ASPNETCORE_ENVIRONMENT: "Production"
systemdTemplate: "proxy-service.service.tpl"
nginxTemplate: "proxy.conf.tpl"
siteFields:
  - key: entryPoint
    label: "Başlangıç DLL'i"
    required: true
```

- Kodda bir `RuntimeProvider` arayüzü olsun; YAML tanımlarını okuyan genel bir implementasyon ilk sürüm için yeterli.
- Başlangıçta hazır gelsin: **.NET** (birden fazla runtime sürümü yan yana, `dotnet-install.sh` ile), **Node.js** (birden fazla sürüm `/opt/node/<sürüm>` altında), **Statik**.
- **PHP** (php-fpm, site başına ayrı pool, birden fazla PHP sürümü) Faz 5'te eklensin; mimari bunu şimdiden desteklemeli.
- Panelde "Altyapılar" sayfası: kurulu altyapılar ve sürümleri, yeni sürüm kurma/kaldırma (kullanan site varsa kaldırmaya izin verme).

### 6.6 SSL yönetimi
**Ücretsiz (Let's Encrypt):**
- certbot ile kurulum (webroot veya nginx yöntemi — hangisi daha temizse onu seç ve gerekçesini yaz).
- Kurmadan önce **DNS ön kontrolü:** domain ve alias'ların A/AAAA kayıtları bu sunucuyu gösteriyor mu? Göstermiyorsa uyar ve hangi kaydın yanlış olduğunu belirt.
- Otomatik yenileme (certbot timer) + yenileme sonrası nginx reload hook'u. Yenileme sonuçları Log Merkezi'ne düşsün.
- Wildcard (DNS-01) şimdilik kapsam dışı ama ileride Cloudflare API ile eklenebilecek şekilde tasarla.

**Ücretli SSL:**
1. **CSR oluşturma ekranı:** Domain (CN), SAN listesi, ülke (varsayılan TR), şehir, il, kuruluş, birim, e-posta; anahtar tipi **RSA 2048 / RSA 4096 / ECDSA P-256**. Private key sunucuda üretilsin (Go `crypto` paketleri) ve korumalı saklansın. CSR metni kopyalanabilir ve indirilebilir şekilde gösterilsin.
2. **Sertifika kurma ekranı:** Daha önce oluşturulan CSR'ı seç (veya harici private key yapıştır), **CRT** ve **CA Bundle / Intermediate** alanlarına yapıştır ya da dosya yükle.
3. Kurulumdan önce doğrulamalar:
   - Sertifika ile private key eşleşiyor mu (public key karşılaştırması)?
   - Sertifika domain'i kapsıyor mu (CN/SAN)?
   - Zincir eksiksiz ve doğru sırada mı?
   - Geçerlilik tarihleri.
4. Doğrulama geçerse fullchain oluşturulup nginx'e bağlansın.
- Tüm sertifikalar tek listede: tür (LE/ücretli), veren CA, bitiş tarihi, kalan gün. Ücretli sertifikalar için bitişe 30/15/7 gün kala bildirim.
- Sertifika + key'i zip olarak dışa aktarma (başka sunucuya taşımak için).

### 6.7 Veritabanı yönetimi (Docker)
**Kurulum:** "Veritabanı Sunucuları" sayfasından tek tıkla Docker kurulumu (yoksa) ve **MSSQL container** kurulumu.
- İmaj: Microsoft'un güncel stabil MSSQL Linux imajı (sürümü kurulum sırasında kontrol et ve sor).
- Container'a bellek limiti (`MSSQL_MEMORY_LIMIT_MB` + Docker memory limit), SA şifresi rastgele üretilip şifreli saklansın.
- Port varsayılan olarak **yalnızca 127.0.0.1**'e bağlansın. Dışarıdan erişim (SSMS ile bağlanmak için) ayrı bir ayar olsun ve sadece IP allowlist ile UFW üzerinden açılsın.
- Veri kalıcı volume'de; container yeniden oluşturulsa da veri kaybolmasın.
- Container durumu, kaynak kullanımı, başlat/durdur/yeniden başlat. Container logları Log Merkezi'nden görüntülenebilsin.

**Müşteri izolasyonu (kritik):**
- Her müşteri için bir SQL login (örn. `c_<müşterikısaad>`), rastgele güçlü şifre.
- Login'e `DENY VIEW ANY DATABASE` uygulansın.
- Panelden o müşteri için DB oluşturulduğunda, DB'nin sahibi `ALTER AUTHORIZATION ON DATABASE::[db] TO [login]` ile o login yapılsın. Böylece müşteri yalnızca kendi DB'lerini görür ve erişir, diğerlerini göremez.
- İzolasyonu doğrulayan bir **otomatik test** yaz: iki müşteri oluştur, birinin diğerinin DB'sini göremediğini ve erişemediğini kontrol et.
- Şifre sıfırlama, login'i devre dışı bırakma, DB silme (onaylı).
- Her DB için hazır **connection string** üret (tek tıkla kopyala, isterse doğrudan ilgili sitenin ortam değişkenine yaz).
- DB boyutlarını listele.

**Genişletilebilirlik:** `DatabaseProvider` arayüzü (CreateLogin, CreateDatabase, Backup, Restore, Drop, GetSize). İlk implementasyon MSSQL; PostgreSQL/MySQL sonradan eklenebilir.

### 6.8 Yedekleme
**Yedek içeriği (site başına seçilebilir):** site dosyaları (`current` + `shared`), ilişkili veritabanları, nginx config, SSL dosyaları, site ayarları (JSON).
- Dosyalar `tar.zst` ile sıkıştırılsın (sistemdeki `tar` + `zstd` kullanılsın; düşük öncelikte, `nice`/`ionice` ile çalışsın ki siteler yavaşlamasın).
- MSSQL için `BACKUP DATABASE` ile `.bak` al (container volume'üne yazıp oradan al).

**Zamanlama:**
- Yedekleme planları: günlük / haftalık / aylık / özel cron; saat seçimi.
- Plan kapsamı: tüm siteler, seçili siteler veya tek site.
- **Saklama politikası:** yerelde son N yedek, uzakta (Google Drive) son M yedek / X gün. Eskiler otomatik silinsin.
- Planlar arası ayrım: örn. "günlük yerel yedek, haftalık Drive'a gönder".

**rclone entegrasyonu:**
- "Yedekleme Ayarları" sayfasından **rclone kurulumu** (resmi kurulum betiği veya paket) ve sürüm gösterimi.
- **Google Drive bağlantısı:** Sunucuda tarayıcı olmadığı için iki yöntem sun:
  1. **OAuth token yapıştırma:** Panel, kendi bilgisayarımda çalıştıracağım `rclone authorize "drive"` komutunu göstersin; çıktıdaki token'ı panele yapıştırınca remote oluşturulsun.
  2. **Service Account JSON** yükleme (+ hedef klasör / shared drive ID).
- Hedef klasör yolu ayarı (örn. `HostPanel-Backups/<sunucu-adı>/<domain>/`).
- İsteğe bağlı **rclone crypt** ile şifreli yedek.
- "Bağlantıyı test et" butonu.
- Upload bant genişliği limiti ayarı (`--bwlimit`).

**Geri yükleme:**
- Yerel veya Drive'daki yedeği listele → seç → dosyalar ve/veya DB geri yüklensin. Geri yüklemeden önce mevcut durumun otomatik yedeği alınsın.
- Yedekten **farklı domain'e** geri yükleme (klonlama/staging için).

**Takip:** Her yedek işinin durumu, süresi, boyutu ve tam çıktısı Log Merkezi'nde. Başarısız yedekte bildirim.

### 6.9 Mevcut siteleri içe aktarma (taşıma için)
Sitelerimi eski sunucudan taşıyacağım; bunun için ayrı bir sihirbaz:
- Site dosyalarını zip olarak yükle (veya rclone/URL'den çek)
- `.bak` dosyasından MSSQL DB'si geri yükle → otomatik olarak müşterinin login'ine bağla
- Ortam değişkenlerini/connection string'i toplu yapıştır
- Mevcut ücretli sertifikayı (crt + key + ca) içe aktar
- "DNS henüz bu sunucuyu göstermiyor" durumunu destekle: siteyi hazırla, test için hosts dosyası talimatı göster, DNS değişince SSL kur.

### 6.10 Zamanlanmış görevler (site cron'ları)
- Site başına cron görevi tanımlama (site kullanıcısı olarak çalışsın); her çalışmanın sonucu ve çıktısı Log Merkezi'ne düşsün.

### 6.11 İzleme ve bildirimler
- Site başına **uptime/health check** (URL + beklenen status kodu, aralık). Tekrarlayan çökmeleri tespit et.
- Bildirim kanalları: **Telegram bot** (öncelikli) ve **e-posta (SMTP)**.
- Bildirim olayları: site down/up, SSL bitiyor, yedek başarısız, disk %85 üzeri, servis sürekli yeniden başlıyor, panel girişinde başarısız deneme/yeni IP'den giriş.
- Gönderilen her bildirim Log Merkezi'nde de görünsün.

### 6.12 Sunucu yönetimi
- **UFW** kuralları görüntüleme/ekleme/silme (22, 80, 443 ve panel portu silinemez korumalı).
- Servis durumları: nginx, docker, fail2ban, hostpanel.
- Bekleyen güvenlik güncellemeleri sayısı (sadece gösterim; güncellemeyi ben SSH ile yaparım).
- Disk kullanımı dağılımı (sitelere, yedeklere, docker'a göre).

### 6.13 Log Merkezi
Panelin ayrı bir ana menü öğesi. Üç sekmeden oluşur:

**1. İşlem Geçmişi (Activity Log)**
- Panelde yapılan **her işlem** kaydedilsin: zaman, kaynak IP, işlem tipi (site.create, ssl.install, db.create, backup.run, login.success, login.failed, settings.update vb.), hedef (site/müşteri/DB), sonuç (başarılı / başarısız / devam ediyor), süre, kısa açıklama.
- Zamanlanmış/otomatik işler de (yedek, SSL yenileme, health check olayları, cron'lar) "sistem" kaynağıyla kaydedilsin; böylece benim yaptıklarımla otomatik olanlar ayırt edilebilsin.
- Zaman çizelgesi görünümü; başarısız işlemler kırmızı vurgulu.
- Bir kayda tıklayınca detay paneli: işlemin parametreleri (gizli alanlar maskeli), çalıştırılan adımlar, ilgili job'ın tam çıktısı, hata mesajı.
- "Değişiklik" içeren işlemlerde (nginx config, ortam değişkeni, ayarlar) **önce/sonra farkı (diff)** gösterilsin.

**2. İş Logları (Job Logs)**
- Arka plan işlerinin (deploy, SSL kurulumu, yedekleme, runtime kurulumu, DB işlemleri) listesi: durum, başlangıç, süre.
- Çalışan bir işin çıktısı **SSE ile canlı** akışla izlenebilsin; biten işlerin tam çıktısı `/var/log/hostpanel/jobs/` dosyasından okunsun.
- Başarısız bir işi "yeniden dene" butonu (güvenliyse).

**3. Sistem Logları**
- Kaynak seçici: panelin kendi logu, site uygulama logları (journald), nginx access/error (site bazlı veya genel), certbot, rclone, Docker/MSSQL container, fail2ban, SSH/auth girişleri (`auth.log`).
- **Canlı takip (tail -f)** modu SSE ile; durdur/devam et.
- Filtreler: kaynak, site, seviye (info/warn/error), tarih aralığı, serbest metin arama.
- Son N satır seçimi (100/500/1000), görüntülenen sonucu dosya olarak indirme.
- Büyük log dosyaları **asla tamamen belleğe alınmasın**; dosya sonundan geriye doğru okuma ve sayfalama ile çalışılsın (RAM bütçesi için kritik).

**Genel:**
- Dashboard'daki "Son İşlemler" kartı, site/müşteri detaylarındaki log sekmeleri bu modülün filtrelenmiş görünümleri olsun (tek bir log altyapısı, birden fazla görünüm).
- **Saklama:** İşlem geçmişi varsayılan 180 gün, job logları 30 gün (ayarlardan değiştirilebilir); eski kayıtlar günlük bir temizlik işiyle silinsin. Panelin kendi log dosyası için logrotate kuralı.
- Hızlı filtreleme için SQLite'ta uygun indeksler (zaman, işlem tipi, hedef, sonuç).

### 6.14 Panel ayarları ve güncelleme
- Genel ayarlar: sunucu adı, varsayılan kaynak limitleri, bildirim ayarları, yedekleme varsayılanları, log saklama süreleri.
- **Panelin kendini güncellemesi:** GitHub Releases'te yeni sürüm var mı kontrol et; "Güncelle" ile yeni binary'yi indir, checksum doğrula, mevcut binary'yi yedekle, değiştir, yeniden başlat, health check başarısızsa **otomatik geri dön**. DB migration'ları açılışta otomatik uygulansın. Güncelleme işlemi Log Merkezi'ne kaydedilsin.
- **Panel yapılandırma yedeği:** panel DB'si + `/etc/hostpanel` dışa aktarılıp başka sunucuda içe aktarılabilsin.

---

## 7. Kurulum ve dağıtım

### 7.1 Repo yapısı
```
/cmd/hostpanel/            # main paketi
/internal/
  auth/                    # session, 2FA, rate limit
  web/                     # handler'lar, middleware, şablonlar, statik dosyalar (embed)
  sites/  runtimes/  ssl/  databases/  backups/  monitor/  logs/  jobs/  system/
  exec/                    # CommandRunner
  store/                   # SQLite erişimi + migration'lar (embed)
  crypto/                  # AES-GCM gizli bilgi şifreleme
/deploy/scripts/           # root helper script'ler
/deploy/templates/         # nginx, systemd şablonları
/deploy/runtimes/          # varsayılan runtime yaml'ları
/install.sh
/update.sh
/uninstall.sh
/Makefile                  # build, test, lint, run-dev
/.github/workflows/release.yml
CLAUDE.md
README.md
```

### 7.2 GitHub Actions
- Her push'ta: `go vet`, `staticcheck`, testler.
- Tag push (`v*`) olduğunda: `CGO_ENABLED=0 go build -trimpath -ldflags "-s -w -X main.version=<tag>"` ile **linux/amd64 ve linux/arm64** binary'leri → `deploy/` klasörüyle birlikte `hostpanel-<version>-linux-<arch>.tar.gz` → SHA256 checksum dosyası → GitHub Release'e ekle.
- Sunucuda Go kurulu olması gerekmesin.

### 7.3 install.sh
- Root kontrolü, Ubuntu 24.04 kontrolü, mimari tespiti (amd64/arm64).
- **Idempotent** olsun: ikinci kez çalıştırılırsa bozmadan devam etsin.
- Parametreler (opsiyonel, interaktif sorabilir de):
  `--domain panel.ornek.com --email admin@ornek.com --port 8443 --version latest`
- Yaptıkları:
  1. Paketler: nginx, certbot, python3-certbot-nginx, ufw, fail2ban, zstd, curl, jq, unzip, openssl
  2. `hostpanel` kullanıcısı (`systemd-journal` ve `adm` gruplarında), dizinler, izinler
  3. Son release'i indir, **checksum doğrula**, `/opt/hostpanel` altına aç
  4. `master.key` üret
  5. sudoers dosyası (`visudo -c` ile doğrula)
  6. systemd servisi (`hostpanel.service`, `MemoryMax`, hardening ayarlarıyla)
  7. UFW: 22, 80, 443 (+ panel portu) — SSH portunu kapatmadığından emin ol
  8. fail2ban jail (SSH + panel girişi)
  9. logrotate kuralı
  10. Domain verildiyse panel için nginx + Let's Encrypt
  11. Admin şifresi üret, kurulum sonunda ekrana panel adresi + kullanıcı adı + şifre bas
- Docker, MSSQL, .NET runtime'ları, Node, rclone **install sırasında kurulmasın**; panelden ihtiyaç oldukça kurulsun.
- `update.sh`: panelin "güncelle" butonuyla aynı mantık (CLI'dan).
- `uninstall.sh`: paneli kaldırır ama **siteleri, DB'leri ve yedekleri silmez** (ayrı onay olmadan).

---

## 8. Geliştirme ortamı notu

- Geliştirmeyi sunucuda yapıyorum. Sunucuya Go toolchain'i kur; `make run-dev` ile panel geliştirme modunda (şablonlar diskten okunur, hot reload için `air` gibi hafif bir araç opsiyonel) çalışsın.
- `CommandRunner` için bir **dry-run modu** ekle: sistem komutlarını çalıştırmak yerine Log Merkezi'ne "[DRY-RUN]" etiketiyle yazsın. Böylece UI ve akışlar sistemi değiştirmeden test edilebilir.
- Root script'lerin testleri için ayrı bir test domain'i/test kullanıcıları kullan; işi bitince temizle.
- install.sh'yi her büyük fazdan sonra **temiz bir Ubuntu 24.04 VM'de** baştan test et.

---

## 9. Faz planı

Her fazın sonunda: build temiz, testler geçiyor, boşta RAM ölçümü yapıldı, kısa bir özet + manuel test adımları bana raporlanır, commit atılır. Bir sonraki faza onayım olmadan geçme.

- **Faz 0 — İskelet:** Go modülü ve dizin yapısı, CLAUDE.md, Makefile, HTTP sunucusu + şablon/layout sistemi (HTMX + Alpine gömülü), SQLite + migration'lar, auth + 2FA + CSRF, `CommandRunner` (dry-run dahil), AES-GCM gizli bilgi katmanı, **Log Merkezi altyapısı** (activity log, job sistemi, SSE akışı), sudoers + helper script altyapısı.
- **Faz 1 — Site çekirdeği:** Müşteri yönetimi, runtime YAML sistemi, .NET + Node + Statik runtime'ları, site ekleme sihirbazı, başlat/durdur/restart/sil, nginx + systemd şablonları, zip deploy + rollback, ortam değişkenleri, site log sekmesi.
- **Faz 2 — SSL:** Let's Encrypt (DNS ön kontrolüyle), CSR oluşturma, ücretli sertifika kurma + doğrulamalar, sertifika listesi ve bitiş takibi.
- **Faz 3 — Veritabanı:** Docker + MSSQL kurulumu, müşteri login'leri, DB oluşturma, izolasyon testi, connection string üretimi.
- **Faz 4 — Yedekleme:** Yerel yedek, planlar ve saklama, rclone kurulumu + Google Drive bağlantısı, uzak yedek, geri yükleme, içe aktarma sihirbazı.
- **Faz 5 — İzleme ve ekler:** Dashboard metrikleri, Log Merkezi sistem logları sekmesinin tüm kaynakları, health check, Telegram/e-posta bildirimleri, UFW yönetimi, site cron'ları, git deploy, PHP runtime.
- **Faz 6 — Dağıtım:** install/update/uninstall script'leri, GitHub Actions release, panelin kendini güncellemesi, yapılandırma dışa/içe aktarma, README.

---

## 10. Çalışma kuralları

- Önce `CLAUDE.md` oluştur: mimari özet, dizin yapısı, kod kuralları, bağımlılık listesi (gerekçeleriyle), sık kullanılan komutlar. Her fazda güncel tut.
- Bir şeyden emin değilsen (paket sürümü, imaj etiketi, kütüphane uyumluluğu) **tahmin etme**; kontrol et veya bana sor.
- Sistemde geri alınması zor bir işlem yapmadan önce (paket kaldırma, UFW değişikliği, mevcut nginx config'e dokunma) bana sor.
- SSH erişimimi kesebilecek hiçbir değişikliği (UFW, sshd_config, fail2ban) test etmeden uygulama.
- Kod basit ve okunabilir olsun; idiomatic Go yaz, gereksiz soyutlama ve over-engineering yapma. Tek admin için bir panel, kurumsal ürün değil.
- Goroutine sızıntısı olmasın: her arka plan işi ve SSE bağlantısı context ile iptal edilebilir olsun.
- Güvenlikle ilgili her kararı (sudoers, izinler, izolasyon) kısaca gerekçelendir.

---

## 11. Kabul kriterleri (bitmiş sayılması için)

- [ ] Temiz bir Ubuntu 24.04 sunucuda tek komutla kurulum, sonunda panel adresi ve giriş bilgileri ekranda.
- [ ] Panel boşta **< 30 MB RAM** kullanıyor; tek binary, harici runtime yok.
- [ ] .NET 10 ve Node.js site ekleme → zip deploy → SSL → HTTPS ile erişim, panelden 5 dakikanın altında.
- [ ] Ücretli SSL: CSR üret → CRT + CA yapıştır → doğrula → kur akışı uçtan uca çalışıyor.
- [ ] İki farklı müşterinin MSSQL login'i birbirinin DB'sini göremiyor ve erişemiyor (otomatik test).
- [ ] Zamanlanmış yedek Google Drive'a gidiyor, saklama politikası eskileri siliyor, Drive'dan geri yükleme çalışıyor.
- [ ] Log Merkezi'nde her işlem (manuel ve otomatik) görünüyor; çalışan işler ve sistem logları canlı izlenebiliyor; büyük log dosyaları RAM'i şişirmiyor.
- [ ] Panel süreci root değil; root işlemleri yalnızca whitelist'teki script'lerle yapılıyor.
- [ ] Hatalı nginx config'i hiçbir zaman canlıya alınmıyor (otomatik geri dönüş).
- [ ] Panel kendini GitHub Releases'ten güncelleyebiliyor ve başarısızlıkta geri dönüyor.

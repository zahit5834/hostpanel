# HostPanel — Geliştirici Notları (CLAUDE.md)

Tek admin için, Ubuntu 24.04 üzerinde müşteri sitelerini (ASP.NET Core, Node.js, statik; ileride PHP) barındıran **ultra hafif** kontrol paneli. Tam gereksinimler: `PROMPT.md`. Bu dosya mimariyi, kuralları ve faz durumunu özetler; her fazda güncellenir.

## Kaynak bütçesi (zorunlu)
| Metrik | Hedef | Son ölçüm |
|---|---|---|
| Boşta RSS | < 30 MB | **24.5 MB** (Faz 2, dry-run: giriş + DNS kontrolü + LE + CSR (RSA) + sayfalar, 60 sn boşta; RssAnon 9.7 MB, RssFile 14.8 MB). Faz 1: 24.0 MB, Faz 0: 18.8 MB |
| Binary | < 30 MB | **16.7 MB** amd64 / 15.7 MB arm64 (stripped, her şey gömülü) |
| Boşta CPU | ~%0 | %0.0 (polling yok; tek timer: günlük bakım) |
| CGO | kapalı | `CGO_ENABLED=0`, statik ELF |

Not: argon2id girişte geçici olarak ~19 MiB ayırır (VmHWM ~35 MB); `auth.argonKey` hemen ardından `debug.FreeOSMemory()` çağırır, aksi halde boşta RSS ~56 MB kalıyordu.

## Komutlar
Go `~/.local/go` altında: `export PATH="$HOME/.local/go/bin:$HOME/go/bin:$PATH"` (`~/.profile`'da).

| Komut | Açıklama |
|---|---|
| `make run-dev` | Dev modu: `./data/` altında DB/log/key, `127.0.0.1:8080`, dry-run, şablonlar diskten okunur. İlk açılışta admin şifresi stderr'e basılır. |
| `make test` | Go testleri + `deploy/scripts/test_lib.sh` |
| `make lint` | `go vet`, `staticcheck`, sudoers↔script eşleşme kontrolü, (varsa) shellcheck |
| `make build` / `build-arm64` | `bin/hostpanel-linux-<arch>` |
| `make measure` | Çalışan panelin RSS/CPU değerleri |
| `hostpanel admin reset-password` | Admin şifresini sıfırlar, yenisini basar (tüm oturumları kapatır) |
| `hostpanel admin disable-2fa` | 2FA kurtarma |

Dev erişimi: `ssh -L 8080:127.0.0.1:8080 ubuntu@sunucu` → `http://127.0.0.1:8080`.

## Dizin yapısı
```
cmd/hostpanel/        main: serve + admin alt komutları, günlük bakım (retention), graceful shutdown
internal/config/      YAML config, Defaults() (prod) / DevDefaults()
internal/store/       SQLite (modernc, WAL) + gömülü migration runner (migrations/NNN_*.sql)
internal/crypto/      AES-256-GCM Box, master.key yükleme/üretme (600 değilse reddeder)
internal/exec/        CommandRunner: Real, DryRun, Helper("hp-x.sh", args...) → sudo -n
internal/logs/        Activity log (Record/Begin/Finish/Query), maskeleme, TailLines (geriye okuma)
internal/jobs/        Job kuyruğu + worker, job log dosyaları, Broker (SSE pub/sub)
internal/auth/        argon2id, oturumlar, TOTP, kurtarma kodları, rate limit
internal/system/      /proc + statfs metrikleri
internal/customers/   müşteri CRUD (arama Go'da: Türkçe büyük/küçük harf)
internal/runtimes/    runtime YAML tanımları (Provider arayüzü), kurulu sürüm tespiti, resmi sürüm listeleri (1 sa cache)
internal/sites/       site iş mantığı: doğrulama, port, nginx render+doğrulama, saga, create/deploy/ops/env/settings/delete job'ları
internal/ssl/         anahtar/CSR üretimi, sertifika doğrulama (key/ad/zincir/tarih), DNS+HTTP ön kontrol, LE/ücretli/yenile/kaldır job'ları, dışa aktarma, günlük bakım
internal/web/         server, middleware, handler'lar, templates/ (layout + pages + partials), static/
deploy/scripts/       root helper script'leri (hp-*.sh) + lib.sh (doğrulayıcılar) + test_lib.sh; runtimes/<id>.sh kurulum alt script'leri
deploy/runtimes/      dotnet.yaml, node.yaml, static.yaml (prod: /opt/hostpanel/runtimes)
deploy/templates/     nginx/*.conf.tpl (Go text/template), systemd/*.service.tpl (root script doldurur), pages/ (yakında/503/devre dışı)
deploy/sudoers/       /etc/sudoers.d/hostpanel (script'ler tek tek listelenir)
deploy/systemd/       hostpanel.service
deploy/config.example.yaml
```
Sunucu düzeni: `PROMPT.md` §5 (`/opt/hostpanel`, `/etc/hostpanel`, `/var/lib/hostpanel`, `/var/log/hostpanel`, `/var/www/sites`).

## Mimari özet
- **İstek zinciri:** recoverer → securityHeaders (CSP) → withClientIP → withAllowlist → withSession (+CSRF) → mux → `requireAuth`.
- **Tek log altyapısı:** `activity_log` (her işlem; `source=user|system`, maskeli params, diff, job_id) + `jobs` + `/var/log/hostpanel/jobs/<id>.log`. Dashboard "Son İşlemler", ileride site/müşteri log sekmeleri bunun filtreleridir (`logs.Filter`).
- **Actor:** web katmanı `logs.WithActor(ctx, {user, ip})` koyar; job'lar base ctx'ten türediği için otomatik `system` olur.
- **Job'lar:** `Manager.Register(kind, Handler)` → `Submit(Spec)`. Handler `*jobs.Log`'a yazar (io.Writer; `exec.Cmd.Output` olarak verilebilir), `Progress(p)` çağırır, ctx iptaline uyar. Açılışta yarım kalan işler `failed` yapılır.
  - **Kural:** job params maskeli saklanır → handler'lara asla gizli bilgi param olarak verilmez; handler gizliyi kendisi (DB'den, id ile) yükler. Bu sayede "yeniden dene" güvenlidir.
- **SSE:** önce dosyadan replay, sonra broker; event id = satır no (Last-Event-ID ile tekrarsız yeniden bağlanma). Yavaş abone düşürülür, bağlantı r.Context() ile kapanır; `sse-close="done"`.
- **Siteler:** her site = `site_<short>` Linux kullanıcısı + `/var/www/sites/<domain>/{releases,shared,current→releases/X}` (2750 site_x:www-data) + (proxy ise) `hp-site-<short>.service` + `/etc/nginx/sites-*/hp-<domain>.conf` + `/etc/hostpanel/env/<domain>.env`. Port 5000–5999 (DB + `/proc/net/tcp`). Durum makinesi: provisioning → awaiting_deploy → running/stopped/maintenance/disabled/error; nginx modu duruma göre (`sites.ModeFor`).
- **Create/Delete saga:** adım + telafi (`saga.go`); create'te hata → yapılanlar ters sırayla geri alınır + DB satırı silinir. Delete önce arşivler (`/var/backups/hostpanel/<domain>/`), sonra adımlar best-effort.
- **Deploy:** upload stream → `uploads/upload-*.zip` → job: extract (site kullanıcısı olarak) → activate (atomik symlink) → restart → health check (30 sn, <500) → başarısızsa önceki sürüme otomatik dönüş → prune (son 5). Rollback aynı yolu kullanır.
- **SSL:** `sites.Service.CertFor` (ssl paketi enjekte eder; sites → ssl bağımlılığı yok) aktif sertifikayı nginx verisine koyar. Aktivasyon: `Store.Activate` (eski → replaced) → `ApplyNginx`; nginx reddederse `Store.Revert` (helper zaten eski dosyayı geri yüklemiştir). LE yolu `/etc/letsencrypt/live/<domain>/` (`--cert-name <domain>`), ücretli `/etc/hostpanel/ssl/<domain>/<cert-id>/` (her kurulum ayrı dizin → başarısız kurulum çalışanı ezmez). Yenileme: sistemin `certbot.timer`'ı + deploy hook (nginx reload + `ssl-renewals.log`); günlük bakım (`ssl.Service.Maintain`) logu activity'ye işler, LE bitişlerini tazeler, `certbot.service` hatasını ve 30/15/7 gün (LE: 15/7) eşiklerini bir kez raporlar. DNS-01/wildcard için genişleme noktası: `challenge` sütunu + `hp-ssl.sh issue` method whitelist'i.
- **Runtime ekleme:** `deploy/runtimes/<id>.yaml` (+ gerekiyorsa `deploy/scripts/runtimes/<id>.sh` ve `hp-site-unit.sh` exec allowlist'i). `type: proxy|static` (fastcgi = PHP, Faz 5).
- **Root işlemleri:** yalnızca `exec.Helper(cfg.ScriptsDir, "hp-<x>.sh", args...)`. Yeni helper: `deploy/scripts/hp-x.sh` (`source lib.sh`, `require_root`, tüm argümanları `validate_*` ile doğrula) + `deploy/sudoers/hostpanel` listesine ekle (`make check-sudoers`).

## Kod kuralları
- Kod/tip/yorum **İngilizce**, UI metinleri **Türkçe**.
- Komutlar **asla** `sh -c` / string birleştirme ile çalışmaz; `exec.Cmd{Name, Args}` (API'de shell yolu yok).
- Kullanıcı girdisi whitelist regex ile doğrulanır (Go'da ve helper script'te tekrar).
- Template'lerde inline `<script>`, `style=""`, `on*=` yok (CSP). Alpine **CSP build**: bileşenler `static/app.js` içinde `Alpine.data(...)` ile kayıtlı; template'te sadece isim/metot referansı.
- HTMX fragment'ları: sayfa şablonu `{{define "content"}}` + adlandırılmış bloklar; handler `isHX(r)` ise blok adını render eder. Bloklar her zaman `Page` alır (`.Data`).
- Uzun işler job'dır; HTTP handler'ı bekletmez.
- Her arka plan goroutine'i ctx ile iptal edilebilir; timer/ticker yalnızca ihtiyaç anında (SSE heartbeat bağlantıya bağlı).
- Standart kütüphane ile yapılabilen şey için bağımlılık eklenmez; eklenen her bağımlılık aşağıya gerekçesiyle yazılır.

## Bağımlılıklar
| Paket | Sürüm | Gerekçe |
|---|---|---|
| `modernc.org/sqlite` | v1.61.1 | Saf Go SQLite (CGO yok). |
| `golang.org/x/crypto` | v0.58.0 | argon2id. |
| `github.com/pquerna/otp` | v1.5.0 | TOTP + QR (dolaylı: `boombuler/barcode`). |
| `github.com/goccy/go-yaml` | v1.19.2 | config.yaml (ileride runtime YAML'ları). |
| htmx | 2.0.11 | `static/htmx.min.js`, gömülü. |
| htmx-ext-sse | 2.2.4 | `static/sse.js`, canlı job logları. |
| Alpine.js CSP build | 3.17.5 | `static/alpine-csp.min.js`; normal build `unsafe-eval` ister. |

Planlanan (ilgili fazda eklenecek): `robfig/cron/v3` (Faz 4 yedek planları), `microsoft/go-mssqldb` (Faz 3).

## Güvenlik kararları
- **Panel root değil:** `hostpanel` kullanıcısı; root işler sadece sudoers'ta tam yoluyla listelenen `hp-*.sh` script'leri. Wildcard yok (sudoers `*` argümanları ve dizine sonradan düşen dosyaları da eşler). `scripts/` root:root, panel yazamaz.
- **systemd:** `NoNewPrivileges` ve `ProtectSystem=strict` **bilinçli olarak yok** — sudo ile başlayan helper'lar servisin sandbox'ını miras alır; bu ayarlar sudo'yu (setuid) ve /etc yazımını engeller. Yetki sınırı sudoers whitelist'idir. `MemoryMax=256M`, `GOMEMLIMIT=48MiB`.
- **Oturum:** token'ın yalnızca SHA-256'sı DB'de; cookie `HttpOnly; SameSite=Strict; Secure` (yalnızca SSH-tunnel/dev'de `secure_cookies: false`). 12 sa kayan + 7 gün mutlak süre. 2FA aşamasında ayrı `mfa` oturumu (5 dk) ve geçişte token yenilenir (fixation).
- **CSRF:** oturuma bağlı token (form `_csrf` veya `X-CSRF-Token`) + Fetch-Metadata/Origin kontrolü; login öncesi formlar origin kontrolü + SameSite ile korunur.
- **CSP:** `script-src 'self'; style-src 'self'; img-src 'self' data:` (data: yalnızca 2FA QR için), `frame-ancestors 'none'`.
- **argon2id:** m=19 MiB, t=2, p=1 (OWASP minimumu; RAM bütçesi). Kullanıcı adı yanlışsa da hash çalışır (timing).
- **Rate limit:** IP başına 15 dk'da 5 başarısız deneme (DB'den sayılır, bellek durumu yok). Başarısız girişler `auth.log`'a fail2ban formatında: `<RFC3339> hostpanel: login failed ip=<IP> reason=<r>`.
- **TOTP:** ±1 adım tolerans, aynı adımın tekrar kullanımı reddedilir. **Kurtarma kodları:** 50 bit rastgele, master key'den türetilmiş anahtarla HMAC-SHA256 (DB tek başına sızarsa işe yaramaz; argon2'ye göre hızlı).
- **IP allowlist:** mevcut IP'yi dışlayan liste kaydedilmez; loopback (SSH tüneli) her zaman izinli.
- **X-Real-IP** yalnızca `trust_proxy: true` ve bağlantı 127.0.0.1'den geliyorsa kabul edilir.
- **Gizli bilgiler:** AES-256-GCM (`crypto.Box`), master key 600. Log/params maskeleme: `logs.IsSensitiveKey` (password, secret, token, key, connection string…) + `Cmd.Secrets` literal maskesi.
- **systemd unit'ini root script üretir** (`hp-site-unit.sh`): panel yalnızca doğrulanmış argümanlar verir; argv[0] allowlist (`/usr/share/dotnet/dotnet`, `/opt/node/vX.Y.Z/bin/node`), diğer argv `^[A-Za-z0-9._/@:=,+-]+$`, `..` yok. Panel ele geçirilse bile root'a serbest unit içeriği yazdıramaz. Site unit'leri sıkı: `NoNewPrivileges`, `ProtectSystem=strict`, `ReadWritePaths=<site dizini>`, `MemoryMax`, `CPUQuota`.
- **nginx config'ini panel üretir ama root script içerik doğrular** (`validate_nginx_conf`, Go'da `sites.ValidateConf` ile aynı kural; ifade bazlı `;{}` ayrıştırma): `include`/`load_module`/`*_temp_path`/perl/lua/js yasak, `*_log` yalnızca `/var/log/nginx/hp-<domain>.(access|error).log` (root master'a keyfi dosya açtırılamaz). Yaz → `nginx -t` → hata ise eski dosya geri yüklenir.
- **Zip site kullanıcısı olarak açılır** (`runuser`): zip-slip/symlink en fazla o kullanıcının yetkisinde kalır.
- **Env dosyası** root:root 600; değerler `env_line` ile tırnaklanır (tek tırnak, ya da `\ " $` kaçışlı çift tırnak). DB'de AES-GCM; activity diff'inde yalnızca anahtar adları. Runtime'ın kendi değişkenleri (ASPNETCORE_URLS, PORT…) kullanıcınınkileri ezer ve kullanıcı tarafından girilemez.
- **Upload:** multipart gövde `_csrf` için parse edilmez → `X-CSRF-Token` başlığı zorunlu; 1 GiB sınır, PK imzası kontrolü, okuma süresi 1 sa'e uzatılır (yalnızca bu istekte).
- **Let's Encrypt:** webroot yöntemi — nginx config'lerini yalnızca panel şablonları yazar; `--nginx` eklentisi config'i kendisi değiştirip geri alma mantığını ve diff'leri bozar. Staging ↔ prod geçişinde `--force-renewal` (prod→staging `--break-my-certs`).
- **Sertifika dosya yolu kuralı:** dosya alan tüm `*ssl_*` direktifleri (`ssl_certificate(_key)`, `ssl_trusted_certificate`, `ssl_dhparam`, `ssl_password_file`, `proxy_ssl_*`…) yalnızca o domainin LE lineage'ını veya `/etc/hostpanel/ssl/<domain>/` dizinini gösterebilir (`..`/`$` yok); `ssl_conf_command` yasak; snippet'te ssl dosya direktifleri tamamen yasak. Go + bash aynı kural (`testdata_nginx_bad.txt`). Root master'a başka sitenin/sistemin dosyası okutulamaz.
- **Ücretli sertifika key'leri:** Go'da üretilir (RSA 2048/4096, ECDSA P-256), DB'de AES-GCM; kurulumda stdin ile `hp-ssl.sh install-custom`'a gider, script `openssl` ile key↔cert eşleşmesini ve süreyi tekrar kontrol eder; dosya 600 root, dizin 700. Parolalı key reddedilir. Sayfalara key geri basılmaz. Dışa aktarma POST + CSRF + `ssl.export` activity kaydı; LE key'i `export-key` stdout'undan okunur (exec.Real stdout'u loglamaz).
- **DNS ön kontrolü:** A/AAAA ↔ sunucu IP'leri (arayüzler + Ayarlar → Genel'de elle girilen genel IP'ler) + HTTP probe: her site config'inde `location = /.well-known/hostpanel-probe { return 200 "<server_id>"; }` (rastgele, `settings.server_id`). HTTP probe belirleyicidir (CDN/NAT arkasında DNS yanıltıcı); AAAA var ama sunucuda IPv6 yoksa engel olarak raporlanır.
- **TLS profili:** Mozilla intermediate, TLS 1.2/1.3; nginx 1.24 (Ubuntu 24.04) `http2 on;` bilmez → `listen 443 ssl http2`. `force_https`: 80 portu yalnızca ACME + probe + 301. HSTS, `add_header` kullanan location'larda tekrarlanır (nginx kalıtım kuralı).

## Log rotasyonu
`panel.log` ve `auth.log` append modunda açık tutulur → logrotate kuralı `copytruncate` kullanmalı (Faz 6 install.sh).

## Faz durumu
- [x] **Faz 0 — İskelet** (2026-11-05): modül/dizinler, config, SQLite+migration, auth+2FA+CSRF+rate limit+allowlist, CommandRunner (+dry-run), AES-GCM, Log Merkezi (işlem geçmişi, iş logları + SSE, sistem logları: panel/auth), helper script + sudoers altyapısı, systemd unit.
- [x] **Faz 1 — Site çekirdeği** (2026-11-05): müşteriler, runtime YAML sistemi (.NET/Node/statik + sürüm kur/kaldır), site sihirbazı, başlat/durdur/restart/bakım/devre dışı/sil, nginx + systemd şablonları, zip deploy + otomatik geri dönüş + rollback, ortam değişkenleri (şifreli), site ayarları (nginx diff), site log sekmesi (işlem geçmişi/journal/nginx).
- [x] **Faz 2 — SSL** (2026-11-05): Let's Encrypt (DNS+HTTP ön kontrolü, staging seçeneği, otomatik yenileme + Log Merkezi), CSR oluşturma (RSA/ECDSA), ücretli sertifika doğrulama (key eşleşmesi, CN/SAN, zincir sırası/eksikliği, tarihler) + kurulum, sertifika listesi + bitiş takibi (dashboard kartı, site listesi sütunu, eşik uyarıları), dışa aktarma (zip), force HTTPS/HSTS, certbot log kaynağı.
- [ ] Faz 3 — Veritabanı
- [ ] Faz 4 — Yedekleme
- [ ] Faz 5 — İzleme ve ekler
- [ ] Faz 6 — Dağıtım

## Bekleyen manuel testler (kullanıcı sonra yapacak)
Faz 0:
- [ ] `sudo apt install -y make shellcheck`, ardından `make lint test`
- [ ] `sudo visudo -cf deploy/sudoers/hostpanel`
- [ ] `sudo deploy/scripts/hp-selftest.sh ping` (gerçek sudo zinciri)
- [ ] Tarayıcı (SSH tüneli `-L 8080:127.0.0.1:8080`): giriş → 2FA kur (QR) → çıkış/giriş TOTP ve kurtarma kodu → öz test işi canlı akış + iptal → İşlem Geçmişi kayıtları → tema ve mobil menü

Faz 1 (sunucuda nginx/dotnet/node yok; dry-run ile geliştirildi):
- [ ] `sudo apt install -y nginx unzip zstd`; script'ler/şablonlar `/opt/hostpanel/{scripts,templates,runtimes}` altına root:root kopyalanmalı (Faz 6 install.sh; şimdilik elle). `hostpanel-maps.conf` ilk site kurulumunda `/etc/nginx/conf.d/`'ye otomatik konur; hata sayfaları `/opt/hostpanel/templates/pages/`'den sunulur (www-data okuyabilmeli). `/var/www/letsencrypt` Faz 2'de.
- [ ] `sudo visudo -cf deploy/sudoers/hostpanel` (10 script)
- [ ] `config.yaml`'da `dry_run: false` ile panel → Altyapılar: .NET 10 ve Node 24 kur (sha512/sha256 doğrulaması job logunda)
- [ ] .NET 10 site: sihirbaz → `dotnet publish` zip'i yükle → health check → `curl -H 'Host: <domain>' http://127.0.0.1/`; `UseForwardedHeaders` bilgi kutusu
- [ ] Node site (entryPoint `server.js`) + statik site (SPA açık/kapalı)
- [ ] Bozuk sürüm yükle (açılışta çöken) → otomatik geri dönüş; elle rollback; 6+ deploy sonrası yalnızca 5 sürüm kalmalı
- [ ] Durdur → 503 sayfası; bakım modu; devre dışı; tekrar etkinleştir
- [ ] Env değerleri `$`, `"`, `'`, boşluk içersin → uygulamada aynen okunmalı; `/etc/hostpanel/env/*.env` 600 root
- [ ] Ayarlar → özel snippet'e bilerek geçerli ama nginx'in reddedeceği direktif (örn. `proxy_read_timeout abc;`) → `nginx -t` hatası, eski config geri yüklenmeli, site çalışmaya devam etmeli
- [ ] Kalıcı dizin (`wwwroot/uploads`) deploy'lar arasında korunuyor mu
- [ ] Site sil → `/var/backups/hostpanel/<domain>/pre-delete-*.tar.zst` oluştu, kullanıcı/dizin/unit/nginx temizlendi
- [ ] Panel kullanıcısı `adm` + `systemd-journal` gruplarında olmalı (nginx/journal log sekmesi; Faz 6 install.sh)

Faz 2:
- [ ] `sudo apt install -y certbot`; `systemctl list-timers certbot.timer` aktif mi
- [ ] `sudo visudo -cf deploy/sudoers/hostpanel` (11 script)
- [ ] Gerçek domain (A kaydı 185.48.180.32): site SSL sekmesi → ön kontrol "hazır" → önce **test sertifikası (staging)** → sonra gerçek sertifika (staging→prod zorla yenileme job logunda)
- [ ] Yanlış A kaydı / AAAA kaydı olan bir adla ön kontrol mesajları; Cloudflare proxy'li adda "CDN/proxy" notu
- [ ] HTTPS: `curl -I https://<domain>`, HTTP→HTTPS 301, HSTS başlığı, www→apex yönlendirmesi 443'te; SSL Labs notu (A beklenir)
- [ ] `sudo certbot renew --dry-run` → deploy hook çalıştı mı (`/var/log/hostpanel/ssl-renewals.log`); ertesi günlük bakımda İşlem Geçmişi'nde `ssl.renew` (system)
- [ ] Panelden "Yenile" / "Zorla yenile"
- [ ] Ücretli: CSR oluştur → sağlayıcıdan (veya `openssl` ile kendi test CA'n) CRT + CA bundle → Doğrula (yanlış sıra, eksik ara, yanlış key denemeleri) → Kur → `/etc/hostpanel/ssl/<domain>/<id>/` 700/600
- [ ] Dışa aktar zip'i: `openssl x509 -noout -modulus` ↔ `openssl rsa -noout -modulus` eşleşmesi
- [ ] SSL'i kaldır → site HTTP'ye döner, dosyalar silinir; site silmede LE lineage + custom dizin temizlenir
- [ ] Sistem Logları → certbot kaynağı (journal)

## Açık konular
- Modül yolu geçici `hostpanel`; GitHub kullanıcı adı gelince `github.com/<ad>/hostpanel` (Faz 6). `deploy/systemd/hostpanel.service` içindeki `OWNER` da.
- Sunucuda `make` ve `shellcheck` yok (`sudo apt install make shellcheck`).
- Dry-run'da kurulu runtime yoksa resmi listedeki sürümler "kurulu" sayılır (geliştirme kolaylığı); bu yüzden dev'de Altyapılar sayfasında "Kur" düğmesi görünmez.
- Mevcut sitelerin nginx config'leri probe location'ını ancak yeniden render edildiğinde alır (Gelişmiş → "nginx yapılandırmasını yeniden uygula"); dev dışında site yok, Faz 6 update script'i hepsini yeniden uygulayacak.
- SSL bitiş bildirimleri şimdilik activity kaydı (`ssl.expiring`) + dashboard kartı; Telegram/e-posta Faz 5'te bu olaya bağlanacak.
- Panelin kendi HTTPS'i (panel.domain) Faz 6 install.sh.

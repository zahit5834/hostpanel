# HostPanel — Geliştirici Notları (CLAUDE.md)

Tek admin için, Ubuntu 24.04 üzerinde müşteri sitelerini (ASP.NET Core, Node.js, statik; ileride PHP) barındıran **ultra hafif** kontrol paneli. Tam gereksinimler: `PROMPT.md`. Bu dosya mimariyi, kuralları ve faz durumunu özetler; her fazda güncellenir.

## Kaynak bütçesi (zorunlu)
| Metrik | Hedef | Son ölçüm |
|---|---|---|
| Boşta RSS | < 30 MB | **18.8 MB** (Faz 0, giriş + iş sonrası 60 sn boşta; RssAnon 5.3 MB, RssFile 13.5 MB) |
| Binary | < 30 MB | **15 MB** amd64 / 14 MB arm64 (stripped, her şey gömülü) |
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
internal/web/         server, middleware, handler'lar, templates/ (layout + pages + partials), static/
deploy/scripts/       root helper script'leri (hp-*.sh) + lib.sh (doğrulayıcılar) + test_lib.sh
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
- **Let's Encrypt (Faz 2):** webroot yöntemi — nginx config'lerini yalnızca panel şablonları yazar; `--nginx` eklentisi config'i kendisi değiştirip geri alma mantığını bozar.

## Log rotasyonu
`panel.log` ve `auth.log` append modunda açık tutulur → logrotate kuralı `copytruncate` kullanmalı (Faz 6 install.sh).

## Faz durumu
- [x] **Faz 0 — İskelet** (2026-11-05): modül/dizinler, config, SQLite+migration, auth+2FA+CSRF+rate limit+allowlist, CommandRunner (+dry-run), AES-GCM, Log Merkezi (işlem geçmişi, iş logları + SSE, sistem logları: panel/auth), helper script + sudoers altyapısı, systemd unit.
- [ ] Faz 1 — Site çekirdeği
- [ ] Faz 2 — SSL
- [ ] Faz 3 — Veritabanı
- [ ] Faz 4 — Yedekleme
- [ ] Faz 5 — İzleme ve ekler
- [ ] Faz 6 — Dağıtım

## Açık konular
- Modül yolu geçici `hostpanel`; GitHub kullanıcı adı gelince `github.com/<ad>/hostpanel` (Faz 6). `deploy/systemd/hostpanel.service` içindeki `OWNER` da.
- Sunucuda `make` ve `shellcheck` yok (`sudo apt install make shellcheck`).

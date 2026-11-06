# HostPanel — Geliştirici Notları (CLAUDE.md)

Tek admin için, Ubuntu 24.04 üzerinde müşteri sitelerini (ASP.NET Core, Node.js, statik, PHP 8.3) barındıran **ultra hafif** kontrol paneli. Tam gereksinimler: `PROMPT.md`. Bu dosya mimariyi, kuralları ve faz durumunu özetler; her fazda güncellenir.

## Kaynak bütçesi (zorunlu)
| Metrik | Hedef | Son ölçüm |
|---|---|---|
| Boşta RSS | < 30 MB | **28.9 MB** (Faz 5b, stripped binary, dry-run: giriş + dashboard/metrik poll + siteler/altyapılar/Cron Çalışmaları/sunucu/sistem logları/yedekler + cron ve deploy sekmeleri; 60 sn sonra 29.8 MB, 2.5 dk sonra 28.9 MB; RssAnon 11.6 MB, RssFile 17.4 MB; 30 sn'de 0 CPU tick — **pay daralıyor**, bkz. Açık konular). Faz 5a: 26.3 MB (dry-run: giriş + dashboard/metrik poll + Sunucu sayfası (apt-check, du) + bildirim ayarı + tüm log kaynakları + iki canlı tail, 60 sn boşta; RssAnon 10.3 MB, RssFile 16.0 MB; 30 sn'de 0 CPU tick). Faz 4: 25.2, Faz 3: 23.4, Faz 2: 24.5, Faz 1: 24.0, Faz 0: 18.8 MB |
| Binary | < 30 MB | **19.4 MB** amd64 / 18.2 MB arm64 (10⁶ bayt; stripped, her şey gömülü; Faz 5a: 19.3 / 18.0, Faz 4: 19.0 / 17.8, Faz 3: 18.7 / 17.6, Faz 2: 16.7 / 15.7 — go-mssqldb +1.9 MB) |
| Boşta CPU | ~%0 | %0.0 (polling yok; timer'lar: günlük bakım, yedek zamanlayıcısı, cron zamanlayıcısı (en yakın cron / 6 sa), izleme döngüsü (en yakın health check vadesi / 10 dk disk kontrolü); CPU% ve site RAM/CPU yalnızca dashboard açıkken poll farkıyla) |
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
internal/system/      /proc + statfs metrikleri, /proc/stat CPU farkı, cgroup (site RAM/CPU), UFW çıktı ayrıştırma + kural doğrulama
internal/customers/   müşteri CRUD (arama Go'da: Türkçe büyük/küçük harf)
internal/runtimes/    runtime YAML tanımları (Provider arayüzü), kurulu sürüm tespiti, resmi sürüm listeleri (1 sa cache)
internal/sites/       site iş mantığı: doğrulama, port, nginx render+doğrulama, saga, create/deploy/ops/env/settings/delete job'ları
internal/databases/   DatabaseProvider arayüzü, MSSQL (go-mssqldb) + FakeServer (dry-run), login/DB/container servisi + job'ları, izolasyon testi, BackupTo/RestoreFrom
internal/backups/     yedek planları/kayıtları (store), cron (schedule), saklama (retention, saf fonksiyon), config.json, rclone/Drive ayarları (remote), job'lar (service), zamanlayıcı (scheduler)
internal/ssl/         anahtar/CSR üretimi, sertifika doğrulama (key/ad/zincir/tarih), DNS+HTTP ön kontrol, LE/ücretli/yenile/kaldır job'ları, dışa aktarma, günlük bakım
internal/schedule/    5 alanlı cron ifadesi (robfig parser), NextRun, Türkçe açıklama — yedek planları ve site cron'ları ortak
internal/crons/       site cron'ları: store (site_crons, cron_runs), servis (çalıştırma, semafor, hata/düzelme), tek-timer zamanlayıcı
internal/monitor/     site health check'leri (health_checks tablosu, durum makinesi, NRestarts ile çökme döngüsü), disk eşiği; tek timer
internal/notify/      Telegram + SMTP bildirimleri (ayarlar, kuyruk, dedupe, bilinen IP listesi)
internal/web/         server, middleware, handler'lar, templates/ (layout + pages + partials), static/
deploy/scripts/       root helper script'leri (hp-*.sh) + lib.sh (doğrulayıcılar) + test_lib.sh; runtimes/<id>.sh kurulum alt script'leri
deploy/runtimes/      dotnet.yaml, node.yaml, php.yaml, static.yaml (prod: /opt/hostpanel/runtimes)
deploy/templates/     nginx/*.conf.tpl (Go text/template; fastcgi.conf.tpl = PHP), systemd/*.service.tpl (php-fpm.service.tpl) (root script doldurur), pages/ (yakında/503/devre dışı)
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
- **Veritabanı (MSSQL):** tek container `hostpanel-mssql` (`mcr.microsoft.com/mssql/server:2025-CU10-ubuntu-24.04`, sabit etiket), `--network host`, `MSSQL_IP_ADDRESS=127.0.0.1` (dış erişimde 0.0.0.0), veri `/var/lib/hostpanel/mssql` (→ `/var/opt/mssql`, uid 10001), `MSSQL_MEMORY_LIMIT_MB` + docker `--memory` (+256 MB) + `max server memory` (−512 MB). Docker yalnızca `hp-mssql.sh` üzerinden. Panel her işlemde bağlantı açıp kapatır (boşta soket yok). Müşteri başına login `c_<slug>`; DB'ler `ALTER AUTHORIZATION` ile o login'e ait, `RECOVERY SIMPLE`. Job'lar: `db.docker.install`, `db.server.install` (pull → run → hazır bekle (3 dk) → sa rotasyonu → max memory), `db.server.recreate` (önce UFW, sonra rm+run; veri korunur), `db.create` (+ site env'e connection string), `db.drop` (önce `BACKUP … COPY_ONLY` → `mssql/backup/pre-drop-*.bak`), `db.isolation-test`. Site silme: `sites.Service.DeleteHook` ("DB'leri de sil" → yedekli drop; yoksa `site_id` NULL olur). Müşteri silme login'i sunucudan da düşürür (DB varsa reddedilir). Şifre sıfırlamada env'e yazılmış connection string'ler güncellenir (site yeniden başlatılmalı). Dry-run'da `databases.FakeServer` (aynı görünürlük kuralları, SQL'i `[DRY-RUN SQL]` olarak loglar).
- **Yedekleme:** yedek = `/var/backups/hostpanel/<domain>/<ad>/` (root 0700; ad `YYYYMMDD-HHMMSS-<4 hex>`): `files.tar.zst` (aktif sürüm → `release/` + `shared/`), `db-<db>.bak` (panel `BACKUP … COPY_ONLY` ile `mssql/backup/hpbk-<ad>-<db>.bak`'a yazar, script taşır), `config.json` (her zaman; "ayarlar" bileşeni seçilmezse yalnızca runtime/DB listesi — env değerleri master.key ile AES-GCM **mühürlü** kalır), `nginx.conf` (bilgi), `ssl.tar.zst` (felaket kurtarma; geri yüklemede otomatik kurulmaz), `SHA256SUMS`, `manifest.json`. Uzak: rclone alias `hp:` → (crypt varsa) `hpcrypt:` → `hpdrive:<kök>`; yol `hp:<sunucu>/<domain>/<ad>/`, satırda `remote_server` saklanır. Job'lar: `backup.rclone.install`, `backup.remote.test`, `backup.remote.scan` (Drive'daki yedekleri kayda alır → sunucu yeniden kurulumu), `backup.run`, `backup.plan` (site başına yedek → upload → saklama; bir site hata verse de devam, sonuçta `backup.failed` activity + bildirim), `backup.upload`, `backup.delete`, `backup.restore`, `backup.import-db`. **Saklama** (`Prune`): plan+site başına yerelde son N, Drive'da son M ve/veya X günden eskiler; Drive'daki en yeni kopya asla silinmez; yalnızca-Drive planında Drive'a ulaşmamış kopya yerelde kalır; elle/geri-yükleme-öncesi yedekler budanmaz. **Zamanlayıcı:** tek goroutine + tek timer (en yakın `next_run_at`, en fazla 6 sa uyku), plan değişince `Reschedule()`; panel kapalıyken kaçırılan çalışma bir kez yapılır; çalışan plan tekrar başlatılmaz. **Geri yükleme:** (gerekirse indir + sha256) → `verify` → config.json → aynı runtime şartı → **hedefin otomatik yedeği** (`pre-restore`, alınamazsa durur) → ayarlar+env (`UpdateSettings`/`SaveEnv`; başka master.key → anlaşılır hata) → DB'ler (`stage-db` → `RestoreFrom` → `unstage`) → dosyalar (`Sites.RestoreRelease` = deploy yolu: aktivasyon, restart, health check, otomatik geri dönüş). **Klon** (başka site): hedefin domain/alias'ı kalır; DB'ler hedefin DB'lerine sırayla, fazlası `DBBase(hedef)` adıyla hedef müşterinin login'ine; env'deki connection string hedefe göre yeniden yazılır. **Taşıma sekmesi:** zip (deploy), `.bak` yükleme (`import-*.bak` → `stage-upload` → `RestoreFrom`; geçerliliği `RESTORE FILELISTONLY` sınar), dotenv yapıştırma (birleştirir), SSL kurulum bağlantısı, hosts satırı. Dry-run'da `read-config` diske bakamaz → kaynak sitenin güncel ayarları kullanılır.
- **İzleme (Faz 5a):** `monitor.Service.Run` tek goroutine + tek timer (en yakın `last_checked+interval`, en fazla 10 dk); satırlar `RunDue`/`CheckNow`'da tembel oluşur (site create hook'u yok). Yalnızca `running` + etkin siteler kontrol edilir; durdurulan sitenin durumu `unknown`a döner (bildirim yok). Kontrol: proxy → `127.0.0.1:<port><path>`, statik → nginx'e 127.0.0.1:80 (Host) / `force_https` ise 443 (SNI, normal doğrulama); yönlendirme takip edilmez, 10 sn; beklenen kod 0 = <500. 2 ardışık hata → `site.down`, 1 başarı → `site.up` (activity + bildirim, dedupe yok). Proxy sitelerde `systemctl show -p NRestarts`: 15 dk'da ≥3 otomatik restart → `site.restarting` (saatte bir). Aynı döngü 10 dk'da bir disk %85 eşiğini kontrol eder (`disk.high`/`disk.ok`, durum değişiminde). Dry-run'da kontrol 200 döner. `RunDue` ve `CheckNow` `runMu` ile sıralı.
- **Dashboard:** CPU% = iki poll arasındaki `/proc/stat` farkı, site RAM/CPU = `/sys/fs/cgroup/system.slice/hp-site-<x>.service/{memory.current,cpu.stat}` farkı (`Server.metrics`, mutex; arka planda örnekleme yok, 5 sn'lik HTMX poll yalnızca sayfa açıkken). Uyarı kartı: disk ≥%85, site `error`/health down/sık restart, SSL <15 gün, son 24 sa başarısız yedek. Site tablosu: durum, sağlık, RAM, CPU, SSL günü, son yedek (`backups.Store.LatestBySite`).
- **Bildirimler:** `notify.Service.Send(ctx, Event{Kind, Key, …})` engellemez (tampon 32, dolarsa düşer + log); olay türü kapalıysa ya da kanal yoksa düşer; aynı `Key` 1 sa içinde bir kez (`NoDedupe`: site down/up). Tek gönderici goroutine (`Run`), her gönderim 15 sn, `notify.sent`/`notify.failed` activity (kanal + kind; gizli bilgi yok). Kancalar `Notify func` alanı ile enjekte: ssl (`ssl.expiring`), backups (`backup.failed`), monitor, web/auth (başarısız giriş — IP başına saatte bir, varsayılan kapalı; yeni IP'den başarılı giriş — son 20 IP `notify_known_ips`'te, ilk giriş "yeni" sayılmaz). Ayarlar → Bildirimler: kanallar, olay seçimi, "Test bildirimi gönder" (senkron).
- **Log Merkezi → Sistem Logları:** kaynaklar panel, panel girişleri, site journal'ı (site seçici), nginx erişim/hata (site bazlı veya genel), certbot (journal), SSL yenileme kayıtları, rclone, Docker (journal), MSSQL container (helper), fail2ban, auth.log. Filtreler: seviye, metin, tarih aralığı (`datetime-local`; journal'da `--since/--until`, dosyalarda `logs.LineTime` ile satır zamanı — RFC3339/panel JSON/nginx/rclone/fail2ban/syslog; zamansız satır öncekinin kararını izler). Filtre varken dosya baştan taranır (`logs.ScanLines`, son N eşleşme halka tamponda, RAM sabit), yoksa `TailLines`. **Canlı takip:** `GET /logs/system/stream` SSE; dosyada bağlantıya bağlı 1 sn ticker (boyut küçülürse/inode değişirse baştan), journal'da `journalctl -f -n 0` (istek ctx'i ile ölür); satırlar HTML-escape, metin/seviye filtresi canlıda da uygulanır; "Durdur" SSE elemanını kaldırır.
- **Sunucu sayfası (`/server`):** servis durumları (tek `systemctl is-active` çağrısı), güvenlik güncellemeleri (`/usr/lib/update-notifier/apt-check` stderr `toplam;güvenlik`, yetkisiz, 1 sa cache, tembel yükleme), disk dağılımı (`hp-server.sh disk-usage`, root `du -sb` nice/ionice, 10 dk cache, aynı anda tek du), UFW (aşağıda). Dry-run'da UFW örnek kurallar gösterir.
- **Site cron'ları (Faz 5b):** `site_crons` (zamanlama `internal/schedule`, komut tek satır ≤1000 bayt, zaman aşımı 60–3600 sn) + `cron_runs` (çıktının son 16 KB'ı). `crons.Service.Run` tek goroutine + tek timer (en yakın `next_run_at`, en fazla 6 sa); kaçırılan çalışma telafi edilmez (1 dk'dan geç kalan atlanır, sonraki zaman hesaplanır). Job kuyruğu kullanılmaz (dakikalık cron günde 1440 job üretirdi): her çalışma kendi goroutine'inde, en fazla 4 eşzamanlı (semafor); önceki çalışma sürüyorsa `skipped` kaydı (bellekte + sabit unit adı `hp-cron-<short>-<id>` systemd'de ikincisini başlatmaz). Yalnızca `running`/`maintenance` ve gerçek sürümü olan siteler. `hp-site-cron.sh run` → `run_as_site`. activity'ye yalnızca kaydet/sil/elle çalıştır + `site.cron.failed`/`site.cron.recovered` (system) düşer; bildirim `cron.failed` (cron başına saatte bir). Saklama günlük bakımda: cron başına son 100 ve 30 gün. Log Merkezi → "Cron Çalışmaları" (site/durum/tarih). Site silmede `hp-site-cron.sh stop-all` (cron + build unit'leri). Kapanışta çalışan cron'lar beklenir (`cronDone`).
- **Kullanıcı komutu çalıştırma (`lib.sh run_as_site`):** cron ve build komutları site kullanıcısıyla `systemd-run --wait --pipe --collect --expand-environment=no --uid/--gid=site_x` geçici unit'inde `/bin/bash -c "<komut>"` (komut panelden stdin ile gelir, root tarafında kabuk yorumlaması yok — bash site kullanıcısı olarak çalışır). Sandbox site unit'iyle aynı: `NoNewPrivileges`, `ProtectSystem=strict`, `ProtectHome`, `PrivateTmp`, `PrivateDevices`, `ReadWritePaths=<site dizini>`, `RestrictSUIDSGID`, `RuntimeMaxSec`, `MemoryMax`, `CPUQuota`, `TasksMax=256`, `HOME=<site>/.home`, PATH'te runtime, site env dosyası `EnvironmentFile`. Site kullanıcısı zaten kendi kodunu çalıştırabildiğinden yeni yetki doğmaz.
- **Git deploy (Faz 5b):** `site_git` (repo, branch, build komutu, çıktı dizini, build zaman aşımı, public key, son commit). Yalnızca panelden tetiklenir (webhook yok); job `site.deploy` (`params.git=true`): `hp-site-git.sh fetch` (URL stdin; bare önbellek `<site>/.git-cache`, `fetch --depth 50`, `git archive | tar` → `<site>/build/<release>`, hepsi site kullanıcısıyla; `commit=`/`subject=` basar) → `build` (`run_as_site`, unit `hp-build-<short>`, bellek `max(site, 1024 MB)`, CPU `max(site, %100)`; boş komut = atla) → `release` (çıktı → `releases/<release>`, `finalize_release` = zip deploy ile aynı kalıcı dizin/izin kodu) → mevcut goLive (aktivasyon, restart, health check, otomatik geri dönüş, prune). Hata → `clean`. Sürümde `source` (zip/git/backup) + commit. Ön değerler: .NET `dotnet publish -c Release -o hp-publish` (çıktı `hp-publish`), Node `npm ci && npm run build --if-present`, PHP composer (composer.json varsa). .NET build için aynı major'da SDK gerekir (`runtimes.HasSDKFor`; Altyapılar → .NET → SDK'lar: `dotnet.sh install-sdk <X.Y>` kanalın en yeni SDK'sı, SHA-512). Submodule yok.
- **PHP 8.3 (`type: fastcgi`, Faz 5b):** yalnızca Ubuntu deposundaki 8.3 (`runtimes/php.sh`: apt `php8.3-fpm/cli` + yaygın eklentiler + `php8.3-sybase` (pdo_dblib/MSSQL) + composer; ardından dağıtımın `php8.3-fpm.service`'i `disable --now`, config'e dokunulmaz). Her PHP sitesi kendi php-fpm master'ı: `hp-site-<short>.service` (`php-fpm8.3 --nodaemonize --fpm-config=/etc/hostpanel/php/<domain>.conf`, `Type=notify`, `User=site_x`, `ExecReload` USR2) → proxy sitelerle aynı sandbox, cgroup metrikleri, NRestarts, başlat/durdur, journal. `HasUnit()` = proxy|fastcgi (eski `Type == proxy` kontrolleri). Pool config'ini root üretir (`hp-php-pool.sh install <domain> <short> <memMB> <children> <uploadMB>`): `listen=<site>/run/php.sock` 0660 (site dizini setgid www-data → soket grubu www-data; nginx bağlanır, diğer siteler bağlanamaz), `pm=ondemand` (boşta worker yok, master ~10 MB), `clear_env=no` (env unit'in EnvironmentFile'ından), `open_basedir=<site>/:/tmp/:/usr/share/php/`, `memory_limit`, upload = sitenin max upload'u, `expose_php=off`, `error_log=syslog` (journal; unit'te PrivateDevices yok → `/dev/log`). Ayarlarda alanlar/max upload değişirse pool yeniden yazılır + restart. Health check: restart sonrası unit aktif kalmalı (HTTP kontrolü monitörde nginx üzerinden). nginx `fastcgi.conf.tpl`: `root current/<docroot>`, front controller `try_files … /index.php?$query_string`, nokta dosyaları ve kalıcı dizinlerde `.php` yasak, `fastcgi_param`'lar satır satır (`include fastcgi_params` yok), `SCRIPT_FILENAME`/`DOCUMENT_ROOT` = `$realpath_root` (symlink geçişinde OPcache eski sürümü sunmaz).
- **Yedek config.json'da cron + git:** cron'lar ve git ayarları (deploy key hariç) yazılır; aynı siteye geri yüklemede eksik cron'lar (ada göre) geri gelir, klonda **devre dışı** kopyalanır; git ayarları hedefte yoksa kaydedilir, SSH repo ise yeni deploy key üretilir ve job loguna basılır (repo'ya eklenmeli).
- **Runtime ekleme:** `deploy/runtimes/<id>.yaml` (+ gerekiyorsa `deploy/scripts/runtimes/<id>.sh` ve `hp-site-unit.sh` exec allowlist'i). `type: proxy|static|fastcgi`.
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
| `github.com/microsoft/go-mssqldb` | v1.11.2 | MSSQL sürücüsü (saf Go, Microsoft'un resmi sürücüsü). Yalnızca kök paket kullanılır (`NewConnector`); Azure AD alt paketleri import edilmez → binary'ye girmez. Dolaylı: `golang-sql/civil`, `golang-sql/sqlexp`, `shopspring/decimal`, `golang.org/x/text`. Binary +~1.9 MB. |

| `github.com/robfig/cron/v3` | v3.0.1 | Yedek planlarının cron ifadesini ayrıştırıp bir sonraki zamanı hesaplamak (ay sonu/haftanın günü/DST kuralları elle yazılmaz). Yalnızca parser (`Minute|Hour|Dom|Month|Dow`, `@`/`TZ=` reddedilir) + `Next`; kütüphanenin kendi zamanlayıcısı kullanılmaz (panel tek timer ile uyur). Bağımlılığı yok. |
| rclone | v1.75.2 | Panel binary'sine girmez: `hp-backup.sh rclone-install` resmi zip'i indirir, SHA-256'yı (amd64/arm64 script'te sabit, downloads.rclone.org SHA256SUMS'tan) doğrular, `/usr/local/bin/rclone`. apt'teki 1.60 eski. |

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
- **MSSQL ağ/UFW:** Docker `-p` ile yayınlanan portlar DOCKER iptables zincirinden geçer ve **UFW'yi atlar** → container `--network host`; SQL Server host'ta dinler, UFW kuralları normal işler. Varsayılan yalnızca 127.0.0.1. Dış erişim: IP/CIDR listesi zorunlu (`/0` yasak), `hp-mssql.sh firewall` yalnızca `ufw allow proto tcp from <ip> to any port 1433 comment hostpanel-mssql` ekler (eskileri yorumdan bulup siler); **UFW etkin değilse reddeder**, panel UFW'yi asla kendisi açmaz (SSH kesilme riski). Kurallar container'a dokunulmadan önce uygulanır.
- **Docker grubu yok:** panel kullanıcısı `docker` grubuna eklenmez (root eşdeğeri); her docker işi `hp-mssql.sh` alt komut whitelist'i ile. İmaj regex'i yalnızca `mcr.microsoft.com/mssql/server:20(22|25)-…`, MSSQL_PID `Express|Developer|ürün anahtarı`.
- **sa şifresi:** rastgele (24 karakter `[A-Za-z0-9]`, ~138 bit), AES-GCM; container'a argv değil stdin → `/run` altında 600 `--env-file` (çalıştırınca silinir). İlk şifre `docker inspect`'te kaldığı için hazır olur olmaz `ALTER LOGIN sa` ile değiştirilir; `sa_pending_sealed` sütunu rotasyonu çökme-güvenli yapar (bağlantı başarısızsa bekleyen şifre denenir ve terfi ettirilir). Recreate'te mevcut şifre verilir (imaj env'i mevcut veriye uygulasa da uygulamasa da tutarlı) ve ardından yine rotasyon yapılır.
- **SQL enjeksiyonu:** DDL parametre almadığından ifadeler T-SQL içinde `QUOTENAME(@name)` / `QUOTENAME(@pw, N'''')` ile kurulup `EXEC(@sql)` edilir; değerler sürücüye parametre (sp_executesql) olarak gider, Go'da string birleştirme yok (`TestSQLUsesParameters` SQL metninde kullanıcı verisi olmadığını doğrular). Adlar `^[a-z][a-z0-9_]{1,62}$` + sistem adları yasak; yedek yolu yalnızca `/var/opt/mssql/backup/<ad>.bak`.
- **Müşteri izolasyonu:** login `CHECK_POLICY=ON`, varsayılan DB master, `DENY VIEW ANY DATABASE` → yalnızca sahibi olduğu DB'leri görür; yeni DB'lerde guest kapalı olduğu için başkasınınkine `USE`/3 parçalı ad/doğrudan bağlantı ile giremez. `CreateDatabase` başka sahibe ait mevcut bir DB'yi devralmayı reddeder. `IsolationTest` (iki geçici `hpiso_*` login+DB, her iki yönde: görünürlük, katalog okuma, doğrudan bağlantı, tablo yazma, sysadmin değil, yanlış şifre) hem panelden job hem `go test` (env ile gerçek sunucuya).
- **Bağlantı bilgisi** yalnızca POST + CSRF ile gösterilir, `db.reveal` activity kaydı düşer. Connection string'de şifre kaçış gerektirmez (alfanumerik).
- **Yedekler root'a ait:** `/var/backups/hostpanel` 0700 root; panel kullanıcısı yedek dosyalarını okuyamaz (DB dökümleri, env, SSL key'leri). rclone yalnızca root helper içinde, `/etc/hostpanel/rclone.conf` 600 (+ SA için `rclone-sa.json` 600) → Drive token'ı panel ele geçirilse bile okunamaz. Token/SA/crypt şifreleri stdin ile gider (argv'de yok, `Secrets` maskesi), script JSON'un tek satır ve kontrol karaktersiz olduğunu, client id/secret ve crypt anahtarının regex'ini yeniden doğrular. Crypt şifreleri `rclone obscure -` (stdin) ile config'e yazılır.
- **rclone crypt:** isteğe bağlı, varsayılan açık; password + salt (32 karakter rastgele) bir kez üretilir, DB'de AES-GCM, bağlantı yeniden yapılandırılınca korunur; "anahtarları göster" POST + CSRF + `backup.crypt.reveal` activity. Kaybolursa Drive'daki yedekler açılamaz (UI uyarır). Crypt kapalıyken de env değerleri master.key mühürlü olduğundan Drive'da düz metin gizli bilgi yalnızca DB dökümü/dosyalar/SSL'dir.
- **Geri yüklemede dosyalar site kullanıcısıyla açılır:** root arşivi açar, `tar` `runuser -u site_x` ile çalışır (`--no-same-owner --no-same-permissions`); kalıcı dizin symlink'leri hedef site için yeniden kurulur. İndirilen yedekte yalnızca beklenen dosya adları (`validate_backup_file`), dizin/symlink yok, `SHA256SUMS` satır biçimi doğrulanır, sonra `sha256sum -c`.
- **Restore SQL:** metinde yalnızca `@db/@path/@owner/@lN/@pN`; dosyalar `/var/opt/mssql/data/<db>.mdf|_N.ndf|_log.ldf` (FILESTREAM/full-text reddedilir). Sonrasında owner login'inin dbo olmayan kullanıcısı düşürülür, `REVOKE CONNECT FROM guest`, `TRUSTWORTHY OFF`, `RECOVERY SIMPLE` → başka yerden gelen .bak müşteri izolasyonunu bozamaz.
- **Root'un yazdığı loglar panel dizininde değil:** `/var/log/hostpanel` panel kullanıcısına ait; root oraya yazsaydı panel bir symlink koyup root'a keyfi dosyaya ekleme/chgrp yaptırabilirdi. Bu yüzden `ssl-renewals.log` (certbot deploy hook) ve `rclone.log` (`hp-backup.sh`, rclone stderr'i `tee -a` ile hem job loguna hem dosyaya) `/var/log/hostpanel-root/` altında (dizin root:hostpanel 0750, dosyalar 0640; `root_log_file` symlink'i reddeder, hook da `[ -L ]` kontrol eder). Config: `root_log_dir`.
- **UFW:** panel UFW'yi **asla açıp kapatmaz**; `hp-server.sh ufw-add/ufw-delete` UFW etkin değilse reddeder. Ekleme: `allow|deny`, port/aralık (aralıkta tcp/udp zorunlu), kaynak `any`/IP/CIDR (`/0` yasak), yorum `hostpanel`; korumalı portlara (22, 80, 443, `sshd -T` portu, config `listen` portu) deny eklenemez. Silme: script kuralı numarasıyla **yeniden okur**, panelin gördüğü satırın sha256 önekiyle karşılaştırır (liste değiştiyse silmez), `hostpanel-mssql` yorumlu, profil (OpenSSH/Nginx…)/"Anywhere" ve korumalı portu kapsayan kuralları silmez. Go (`system.ParseUFW`/`UFWRuleInput.Validate`) aynı kuralla düğmeyi gizler ve girdiyi önceden reddeder. Her değişiklik activity'de önce/sonra `ufw status` diff'i ile.
- **Bildirim gizlileri:** Telegram token'ı ve SMTP şifresi AES-GCM (settings), sayfaya geri basılmaz (boş alan = mevcut korunur); token URL'de olduğu için taşıma hataları token'sız raporlanır. SMTP yalnızca TLS: 465 doğrudan TLS, diğer portlarda STARTTLS zorunlu (sunucu sunmazsa gönderilmez → şifre asla açık metin gitmez), sertifika doğrulanır. Konu/adres başlıkları CRLF'siz (adresler `mail.ParseAddress`), gövdede dot-stuffing.
- **Yetkisiz okumalar:** cgroup dosyaları, `/proc/stat`, `apt-check`, journal (`systemd-journal` grubu), `/var/log/{auth.log,fail2ban.log,nginx/*}` (`adm` grubu, Faz 6 install.sh) → root helper gerekmez; yalnızca `du` (yedek/MSSQL dizinleri root 0700) ve UFW `hp-server.sh` üzerinden.
- **Deploy key root'ta:** `hp-site-git.sh keygen` → `/etc/hostpanel/git/<domain>/id_ed25519` (root 0600), panel yalnızca public key'i görür (rclone.conf deseni). Fetch sırasında key ve known_hosts site kullanıcısına ait geçici kopya olarak `/run/hostpanel-git/<short>/` (dizin root:site_x 0750) altına konur, trap ile silinir; git `runuser` ile site kullanıcısı olarak, sabit `GIT_SSH_COMMAND` (`IdentitiesOnly`, `BatchMode`, `StrictHostKeyChecking=accept-new`), `GIT_TERMINAL_PROMPT=0`, `protocol.allow=never` + yalnızca https/ssh, `core.hooksPath=/dev/null`, `timeout 600`. Repo URL: `git@host:yol`, `ssh://[user@]host[:port]/yol` veya kimlik bilgisiz `https://` (Go + bash aynı regex, `-` ile başlayamaz); branch git ref kuralı; çıktı dizini göreli, `..`/symlink yok.
- **Host anahtarı TOFU:** ilk bağlantıda kabul, site başına root'a ait `known_hosts`'a geri yazılır (yalnızca geçerli `host tip base64` satırları, 64 KB); değişirse fetch reddedilir. Panelde parmak izi + "Host anahtarını sıfırla".
- **PHP soketi/nginx:** `fastcgi_pass` yalnızca `unix:/var/www/sites/<o domain>/run/php.sock` (Go `ValidateConf` + bash `validate_nginx_conf`, `testdata_nginx_bad.txt`); snippet'te `fastcgi_pass`/`fastcgi_param` yasak; `include` yasağı korunur. `hp-site-unit.sh` php-fpm için argümanları domain'den kendisi kurar ve config dosyasının var olmasını ister.
- **TLS profili:** Mozilla intermediate, TLS 1.2/1.3; nginx 1.24 (Ubuntu 24.04) `http2 on;` bilmez → `listen 443 ssl http2`. `force_https`: 80 portu yalnızca ACME + probe + 301. HSTS, `add_header` kullanan location'larda tekrarlanır (nginx kalıtım kuralı).

## Log rotasyonu
`panel.log` ve `auth.log` append modunda açık tutulur → logrotate kuralı `copytruncate` kullanmalı (Faz 6 install.sh).

## Faz durumu
- [x] **Faz 0 — İskelet** (2026-11-05): modül/dizinler, config, SQLite+migration, auth+2FA+CSRF+rate limit+allowlist, CommandRunner (+dry-run), AES-GCM, Log Merkezi (işlem geçmişi, iş logları + SSE, sistem logları: panel/auth), helper script + sudoers altyapısı, systemd unit.
- [x] **Faz 1 — Site çekirdeği** (2026-11-05): müşteriler, runtime YAML sistemi (.NET/Node/statik + sürüm kur/kaldır), site sihirbazı, başlat/durdur/restart/bakım/devre dışı/sil, nginx + systemd şablonları, zip deploy + otomatik geri dönüş + rollback, ortam değişkenleri (şifreli), site ayarları (nginx diff), site log sekmesi (işlem geçmişi/journal/nginx).
- [x] **Faz 2 — SSL** (2026-11-05): Let's Encrypt (DNS+HTTP ön kontrolü, staging seçeneği, otomatik yenileme + Log Merkezi), CSR oluşturma (RSA/ECDSA), ücretli sertifika doğrulama (key eşleşmesi, CN/SAN, zincir sırası/eksikliği, tarihler) + kurulum, sertifika listesi + bitiş takibi (dashboard kartı, site listesi sütunu, eşik uyarıları), dışa aktarma (zip), force HTTPS/HSTS, certbot log kaynağı.
- [x] **Faz 3 — Veritabanı** (2026-11-05): Docker (docker.io) + MSSQL 2025 container kurulumu (Express/Developer/ürün anahtarı, bellek sınırı, sa rotasyonu), durum/CPU/RAM + başlat/durdur/yeniden başlat, container logları Log Merkezi'nde, dış erişim (IP allowlist + UFW, host network), müşteri login'leri (oluştur/şifre sıfırla/devre dışı/sil), DB oluştur (sahiplik) / yedekli sil / boyutlar, connection string (.NET/Node) + site env'e yazma, izolasyon testi (job + env ile go test), müşteri formu/detayı, site sihirbazı ve site silme entegrasyonu.
- [x] **Faz 4 — Yedekleme** (2026-11-05): yerel + Google Drive (rclone v1.75.2, OAuth token ya da service account + Shared Drive, isteğe bağlı crypt), bileşen seçimi (dosyalar/DB/ayarlar/SSL), elle yedek (+Drive'a gönder), planlar (günlük/haftalık/aylık/cron, kapsam, hedef, saklama N/M/X gün), tek-timer zamanlayıcı, Drive taraması, geri yükleme (aynı site / klon; otomatik ön yedek, deploy yolu ile otomatik geri dönüş), MSSQL `Restore`, taşıma sihirbazı (Mevcut siteyi taşı → Taşıma sekmesi: zip, .bak, dotenv, SSL, hosts satırı).
- [x] **Faz 5a — İzleme ve bildirimler** (2026-11-06): dashboard CPU% + site başına RAM/CPU (cgroup) + site tablosu (durum/sağlık/SSL/son yedek) + uyarı kartları, site health check'leri (ayar kartı, şimdi kontrol et) + çökme döngüsü tespiti + disk eşiği, Telegram/SMTP bildirimleri (olay seçimi, dedupe, test, yeni IP / başarısız giriş), Log Merkezi'nde tüm sistem log kaynakları + tarih aralığı + canlı takip (SSE), Sunucu sayfası (servisler, güvenlik güncellemeleri, disk dağılımı, UFW kural ekle/sil + korumalar), root log dizini düzeltmesi.
- [x] **Faz 5b — Site cron'ları, git deploy, PHP 8.3** (2026-11-06): site cron'ları (Cron sekmesi, hazır zamanlamalar, şimdi çalıştır, çakışmada atla, zaman aşımı, Log Merkezi "Cron Çalışmaları", `cron.failed` bildirimi, saklama), ortak `internal/schedule`, git deploy (SSH deploy key root'ta / açık https, TOFU host key, sunucuda site kullanıcısıyla build, sürüm kaynağı + commit), .NET SDK kur/kaldır, PHP 8.3 (apt, site başına php-fpm unit'i + root üretimli pool, fastcgi nginx şablonu + doğrulayıcı kuralı), yedek config.json'da cron/git.
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

Faz 3 (sunucuda Docker yok; FakeServer ile dry-run geliştirildi):
- [ ] `sudo visudo -cf deploy/sudoers/hostpanel` (12 script); `hp-mssql.sh` `/opt/hostpanel/scripts/`'e root:root kopyalanmalı
- [ ] Panelden "Docker'ı kur" (`docker.io`) → ardından **SSH'ın hâlâ açık olduğunu** ve `sudo iptables -S INPUT`'un değişmediğini kontrol et (Docker yalnızca FORWARD/NAT zincirlerine dokunur)
- [ ] "MSSQL'i kur" (Express, 2048 MB) → job logunda pull/run, "SQL Server hazır", "sa şifresi yenilendi"; `ss -ltnp | grep 1433` yalnızca `127.0.0.1:1433`; `free -m` ile RAM (~2 GB ayrılır, sunucu 3.9 GB)
- [ ] `sudo docker inspect hostpanel-mssql | grep MSSQL_SA_PASSWORD` → buradaki şifreyle `sqlcmd`/SSMS girişi **reddedilmeli**
- [ ] Gerçek izolasyon testi: panelden "İzolasyon testini çalıştır" + `HOSTPANEL_TEST_MSSQL='<sa>' go test ./internal/databases -run IsolationMSSQL -v` (sa şifresi: panel DB'sinde şifreli; test için geçici bir sysadmin login'i de kullanılabilir)
- [ ] Müşteri + DB oluştur → .NET sitesi env'deki `ConnectionStrings__DefaultConnection` ile bağlanabiliyor mu (yeniden başlatma sonrası); Node sitesi `DATABASE_URL` (`mssql` paketi) ile
- [ ] Şifre sıfırla → site env güncellendi mi, yeniden başlatınca bağlanıyor mu; login devre dışı → bağlantı reddi
- [ ] DB sil → `/var/lib/hostpanel/mssql/backup/pre-drop-*.bak` oluştu mu
- [ ] Bellek değişikliği (recreate) sonrası `MSSQL_MEMORY_LIMIT_MB` ve veri korunuyor mu; `SELECT value_in_use FROM sys.configurations WHERE name='max server memory (MB)'`
- [ ] Dış erişim: UFW **kapalıyken** reddedilmeli; UFW açıkken (SSH kuralı önceden var!) IP ekle → `ufw status` yalnızca 1433 kuralları, `ss -ltnp` 0.0.0.0:1433, SSMS ile izinli IP'den bağlantı, başka IP'den zaman aşımı; kapatınca kurallar silinmeli. **Not:** container recreate'te `MSSQL_IP_ADDRESS`'in mevcut veriye uygulandığı burada doğrulanacak.
- [ ] Log Merkezi → Sistem Logları → MSSQL container

Faz 4 (sunucuda rclone/Docker yok; dry-run ile geliştirildi):
- [ ] `sudo visudo -cf deploy/sudoers/hostpanel` (13 script); `hp-backup.sh` + güncel `lib.sh` `/opt/hostpanel/scripts/`'e root:root; `sudo apt install -y zstd unzip curl`
- [ ] Yedekler → Ayarlar → "rclone'u kur" → job logunda "SHA-256 doğrulandı", `rclone version` = v1.75.2
- [ ] Kendi bilgisayarında `rclone authorize "drive"` → token'ı yapıştır (crypt açık) → anahtarları parola yöneticisine kaydet → "Bağlantıyı test et"; `sudo ls -l /etc/hostpanel/rclone.conf` 600 root
- [ ] Site → Yedekler → tüm bileşenlerle "Şimdi yedekle" + Drive'a gönder → `sudo ls -l /var/backups/hostpanel/<domain>/<ad>/` (0600 dosyalar, `SHA256SUMS`), Drive'da klasör/dosya adları şifreli görünmeli
- [ ] Plan (her gün, birkaç dakika sonrası; hedef "Yerel + Drive", yerel 1, Drive 2) → zamanında çalıştı mı, iki-üç çalışmadan sonra eskiler yerelde ve Drive'da silindi mi; panel kapatılıp plan saati geçince açılınca bir kez çalışmalı
- [ ] Yerel kopyayı sil → yalnızca Drive'daki yedekten geri yükle (indirme + sha256) → site çalışıyor mu, DB verisi geri geldi mi, "geri yükleme öncesi" yedeği oluştu mu
- [ ] Bozuk sürüm içeren yedek (açılışta çöken) geri yükle → otomatik önceki sürüme dönüş
- [ ] Klon: yedeği aynı müşterinin başka .NET sitesine geri yükle → yeni DB (`<kısa_ad>`) o müşterinin login'ine ait, env connection string'i yeni DB'yi gösteriyor, site yeni DB ile çalışıyor
- [ ] Taşıma: SSMS'ten alınmış gerçek `.bak` yükle (sıkıştırılmış/çok dosyalı da) → `RESTORE FILELISTONLY` sonrası DB hazır, sahibi müşteri login'i, izolasyon testi hâlâ geçiyor; dotenv yapıştırma; hosts satırıyla test
- [ ] "Drive'ı tara": `/var/backups/hostpanel` + panel DB'si yokmuş gibi (yeni kurulum) aynı sunucu adıyla Drive'daki yedekler listeye geliyor mu (crypt anahtarları aynı girilmeli)
- [ ] Service account + Shared Drive ile bağlantı (Workspace hesabı varsa)
- [ ] Bant genişliği sınırı (`2M`) upload süresine yansıyor mu; yedek sırasında `nice`/`ionice` ile site yanıt süresi

Faz 5a (dry-run + gerçek sunucuda yetkisiz okumalar denendi: auth.log, journal, apt-check, cgroup):
- [ ] `sudo visudo -cf deploy/sudoers/hostpanel` (14 script); `hp-server.sh` + güncel `lib.sh`, `hp-ssl.sh`, `hp-backup.sh` `/opt/hostpanel/scripts/`'e root:root
- [ ] `sudo hp-ssl.sh setup` yeniden → `/var/log/hostpanel-root/` (root:hostpanel 0750) ve yeni deploy hook; `sudo certbot renew --dry-run` sonrası satır `/var/log/hostpanel-root/ssl-renewals.log`'da, Log Merkezi → "SSL yenileme kayıtları"nda görünmeli
- [ ] Drive'a yedek gönder → Log Merkezi → rclone kaynağında satırlar; job logunda ilerleme hâlâ görünüyor mu (tee)
- [ ] Telegram: @BotFather ile bot → token + chat ID → Kaydet → "Test bildirimi gönder" → mesaj geldi mi; İşlem Geçmişi'nde `notify.sent`
- [ ] SMTP (587 STARTTLS ve 465): test e-postası; Türkçe karakterli konu düzgün mü
- [ ] Bir siteyi çökert (ör. `sudo systemctl kill hp-site-<x>` değil — uygulamanın 500 dönmesi veya portu kapatması): 2 kontrol sonra "erişilemiyor" bildirimi, düzelince "tekrar erişilebilir"; dashboard uyarı kartı
- [ ] Açılışta çöken sürüm (Restart=on-failure döngüsü) → 15 dk içinde "sık sık yeniden başlıyor" bildirimi (saatte bir)
- [ ] Başka bir IP'den panele giriş (ör. farklı tünel çıkışı) → "yeni IP" bildirimi; ilk girişte gelmemeli
- [ ] Sunucu sayfası: disk dağılımı gerçek değerler (root du); servis durumları
- [ ] **UFW (önce SSH ile `sudo ufw allow OpenSSH` olduğundan emin ol; UFW'yi panel açmaz):** UFW kapalıyken sayfada talimat ve ekle/sil reddi; açtıktan sonra 8081/tcp kuralı ekle/sil, `sudo ufw status numbered`'da `# hostpanel`; OpenSSH/22/80/443/panel portu kuralları için "korumalı" ve script'e doğrudan `sudo hp-server.sh ufw-delete <no> <hash>` ile de silinemediğini doğrula; deny 22 reddi; SSH oturumu her adımda açık kalmalı
- [ ] Log Merkezi: nginx erişim/hata (site + genel), fail2ban (kuruluysa), Docker journal, site journal canlı takip (uygulama log basarken), tarih aralığı filtresi
- [ ] Not: sunucuya `185.48.180.8` ve `203.205.18.230`'dan SSH şifre denemeleri geliyor (auth.log) → parola girişini kapatıp yalnızca anahtar + fail2ban (Faz 6) önerilir

Faz 5b (sudo şifreli → dry-run; sunucuda git 2.43 ve systemd 255 `--pipe/--wait` doğrulandı):
- [ ] `sudo visudo -cf deploy/sudoers/hostpanel` (17 script); yeni `hp-site-cron.sh`, `hp-site-git.sh`, `hp-php-pool.sh`, `runtimes/php.sh` + güncel `lib.sh`, `hp-site-deploy.sh`, `hp-site-unit.sh`, `hp-runtime.sh`, `runtimes/{dotnet,node}.sh`, `templates/{nginx/fastcgi.conf.tpl,systemd/php-fpm.service.tpl}`, `runtimes/php.yaml` → `/opt/hostpanel/...` root:root
- [ ] Altyapılar → PHP "Kur" → job logunda apt; `systemctl is-enabled php8.3-fpm` = disabled, `php -v` 8.3.x
- [ ] PHP sitesi (docroot `public`) + `index.php` (`<?php phpinfo();`) zip'i → `curl -H 'Host: <domain>' http://127.0.0.1/`; `ls -l <site>/run/php.sock` → `site_x www-data srw-rw----`; başka site kullanıcısıyla sokete bağlanma reddedilmeli; `open_basedir` dışı `file_get_contents('/etc/passwd')` hata vermeli; `error_log()` satırı site journal'ında
- [ ] Laravel: composer'lı git deploy, `.env` yerine panel env'i, `storage` kalıcı dizin, cron `cd current && php artisan schedule:run`; dashboard'da PHP sitesinin RAM'i (boşta ~10 MB)
- [ ] `uploads/` altına `x.php` koy → 403; `.env` → 403/404
- [ ] Git (SSH): Deploy sekmesinde public key → GitHub → Deploy keys → "Git'ten deploy et" → job logunda host key kabulü, commit + başlık; `sudo ls -l /etc/hostpanel/git/<domain>/` 600 root; panel kullanıcısı key'i okuyamamalı; "Host anahtarını sıfırla" sonrası tekrar kabul
- [ ] Git (https, açık repo) + Node `npm ci && npm run build`; statik site çıktı dizini `dist`
- [ ] .NET: Altyapılar → SDK 10.0 kur (SHA-512) → `dotnet --list-sdks`; git deploy `dotnet publish` (~1 GB RAM; build sırasında site çalışmaya devam ediyor mu); SDK yokken anlaşılır hata
- [ ] Bozuk build (derleme hatası) → sürüm oluşmaz, `build/` temizlenir; build zaman aşımı
- [ ] Cron: `id; pwd; env | grep -c .` → site kullanıcısı, site dizini, env değişkenleri; `sleep 120` + 60 sn timeout → "Zaman aşımı"; dakikalık uzun cron → "Atlandı"; başarısız cron → bildirim (saatte bir), düzelince İşlem Geçmişi'nde `site.cron.recovered`
- [ ] Cron `touch /etc/x` / `/home/ubuntu` okuma → reddedilmeli (ProtectSystem/ProtectHome)
- [ ] Çalışan cron/build varken site sil → `systemctl list-units 'hp-cron-*' 'hp-build-*'` boş; `/etc/hostpanel/{git,php}/<domain>*` silindi
- [ ] Yedek → klon: cron'lar hedefte devre dışı, git ayarları geldi (SSH ise yeni key logda)

## Açık konular
- Modül yolu geçici `hostpanel`; GitHub kullanıcı adı gelince `github.com/<ad>/hostpanel` (Faz 6). `deploy/systemd/hostpanel.service` içindeki `OWNER` da.
- Sunucuda `make` ve `shellcheck` yok (`sudo apt install make shellcheck`).
- Dry-run'da kurulu runtime yoksa resmi listedeki sürümler "kurulu" sayılır (geliştirme kolaylığı); bu yüzden dev'de Altyapılar sayfasında "Kur" düğmesi görünmez.
- Mevcut sitelerin nginx config'leri probe location'ını ancak yeniden render edildiğinde alır (Gelişmiş → "nginx yapılandırmasını yeniden uygula"); dev dışında site yok, Faz 6 update script'i hepsini yeniden uygulayacak.
- Panelin kendi HTTPS'i (panel.domain) Faz 6 install.sh.
- MSSQL sürüm (edition) değişikliği şimdilik yalnızca kurulumda seçilir; sonradan ürün anahtarı girme (recreate + `MSSQL_PID`'in mevcut veriye etkisi doğrulanarak) ileride.
- `pre-drop-*.bak` (DB silme) ve `pre-delete-*.tar.zst` (site silme) dosyaları birikir; planların saklamasına dahil değiller (elle silinir); Faz 5a'da disk %85 uyarısı + Sunucu sayfasındaki dağılım bunları görünür kılar, otomatik temizlik yok.
- Taşımada URL'den zip çekme yok (zip yükleme yeterli görüldü). Restore'da SSL otomatik kurulmaz (`ssl.tar.zst` yalnızca arşiv).
- Yedek öncesi boş disk kontrolü yok; `tar`/`BACKUP` disk dolunca hata verir ve yarım yedek silinir (disk %85 uyarısı Faz 5a'da var).
- Aynı saniyede aynı siteye iki geri yükleme sürüm adı çakışmasına düşebilir (sürüm adı saniye çözünürlüklü; tek worker ile pratikte olmaz).
- Klonda DB eşlemesi sıraya göre (ada göre değil); hedefin birden fazla DB'si varsa kontrol edilmeli.
- `go test -race` sunucuda çalışmıyor (gcc yok, race CGO ister); paylaşılan durum mutex/atomic ile, gcc'li bir makinede `-race` koşulmalı.
- Canlı takibi durdurmak panel.log'a `journalctl … exit -1` WARN satırı düşürür (bağlantı kapanınca süreç öldürülür; zararsız).
- `/var/log/hostpanel-root/*.log` için logrotate kuralı Faz 6 install.sh (copytruncate gerekmez; dosyalar her yazımda açılır).
- Başarısız panel girişi bildirimi varsayılan kapalı (gürültü); fail2ban jail'i Faz 6.
- Git: submodule ve LFS yok; webhook yok (yalnızca panelden). Build ağ erişimli (npm/NuGet/composer).
- PHP: yalnızca 8.3 (Ubuntu deposu); `pdo_sqlsrv` yok (Microsoft deposu gerekir) — MSSQL için `pdo_dblib` (FreeTDS). PHP sitesine DB bağlantısı `DATABASE_URL` (URL biçimi) olarak yazılır.
- **RAM payı:** boşta RSS 28.9 MB (sınır 30). Faz 6 öncesi heap profili (pprof, geçici build) ve prod modunda (şablonlar gömülü, tek parse) ölçüm (`RssAnon` Faz 5a'da 10.3 → 11.6 MB) ile pay açılmalı; ölçüm dev modunda (şablonlar diskten) yapıldı.
- Cron'da kaçırılan çalışma telafi edilmez (bilinçli; cron semantiği); en fazla 4 eşzamanlı.
- İmaj güncelleme (yeni CU) için panelde düğme yok; ileride recreate yoluna "imaj" alanı eklenebilir (regex zaten 2022/2025 etiketlerine izin veriyor).

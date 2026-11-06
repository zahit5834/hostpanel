# HostPanel

Ubuntu 24.04 için tek yöneticili, ultra hafif hosting kontrol paneli: Go, tek statik binary (~19 MB), boşta < 30 MB RAM, boşta ~%0 CPU.

## Özellikler
- **Siteler:** ASP.NET Core, Node.js, PHP 8.3 (site başına php-fpm) ve statik/SPA. Her site kendi Linux kullanıcısı ve sıkı sandbox'lı systemd unit'iyle çalışır.
- **Deploy:** zip yükleme veya Git (SSH deploy key / açık https), sunucuda build. Health check başarısızsa önceki sürüme otomatik döner; tek tıkla rollback.
- **SSL:** Let's Encrypt (DNS + HTTP ön kontrolü, otomatik yenileme), CSR üretimi, ücretli sertifika doğrulama ve kurulumu, bitiş takibi.
- **MSSQL 2025 (Docker):** müşteri başına login, izole veritabanları, dış erişim için IP allowlist + UFW.
- **Yedekleme:** yerel + Google Drive (rclone, isteğe bağlı şifreleme). Planlar, saklama kuralları, geri yükleme/klon ve taşıma sihirbazı.
- **İzleme:** CPU/RAM/disk, site başına RAM/CPU, health check, çökme döngüsü tespiti, Telegram/e-posta bildirimleri.
- **Log Merkezi:** işlem geçmişi, iş logları (canlı), sistem logları (nginx, journal, certbot, fail2ban, auth.log…).
- **Site cron'ları,** Sunucu sayfası (servisler, güvenlik güncellemeleri, disk dağılımı, UFW).
- **Güvenlik:** 2FA (TOTP + kurtarma kodları), IP allowlist, fail2ban entegrasyonu.
- **Panel yönetimi:** panelden tek tıkla güncelleme (otomatik geri dönüşlü), yapılandırmayı dışa/içe aktarma.

## Gereksinimler
- Ubuntu 24.04 LTS, amd64 veya arm64
- root (sudo) erişimi
- Önerilen en az 2 GB RAM; MSSQL kullanılacaksa 4 GB
- Panel için alan adı isteğe bağlıdır. Verilmezse panel `https://<sunucu-ip>:8443` adresinde self-signed sertifikayla açılır.

## Kurulum
Tek komut (IP modu, self-signed sertifika):
```bash
curl -fsSL https://raw.githubusercontent.com/zahit5834/hostpanel/main/install.sh | sudo bash
```
Alan adıyla (Let's Encrypt). Önce A kaydını sunucuya yönlendirin:
```bash
curl -fsSL https://raw.githubusercontent.com/zahit5834/hostpanel/main/install.sh \
  | sudo bash -s -- --domain panel.ornek.com --email admin@ornek.com
```

| Parametre | Açıklama |
|---|---|
| `--domain AD` | Panelin alan adı; Let's Encrypt sertifikası alınır, alınamazsa self-signed'a düşer |
| `--email E` | Let's Encrypt hesap e-postası |
| `--port N` | Panelin HTTPS portu (varsayılan 8443; `443` yalnızca `--domain` ile) |
| `--version vX.Y.Z` | Belirli sürüm (varsayılan: en son sürüm) |
| `--tarball F --sums F` | GitHub yerine yerel paket + SHA256SUMS (çevrimdışı/test) |
| `--import F.hpcfg` | Başka sunucudan dışa aktarılmış panel yapılandırmasını içe al |
| `--no-firewall` | UFW'ye dokunma |
| `--yes` | Onay sorularını atla |

**Betiğin yaptıkları.** Betik tekrar çalıştırılabilir; mevcut ayarları, `master.key`'i ve admin şifresini korur.
- **Paketler:** nginx, certbot, ufw, fail2ban, zstd, git ve diğer temel araçlar.
- **Panel:** `hostpanel` sistem kullanıcısını oluşturur ve paneli `/opt/hostpanel`'e kurar.
- **sudoers:** yalnızca listelenen helper script'leri root yetkisiyle çalışabilir.
- **UFW:**
  - Önce SSH portlarını, ardından 80, 443 ve panel portunu açar.
  - SSH portu tespit edilemezse UFW'yi etkinleştirmez.
  - UFW kapalıysa açmadan önce onay ister.
- **fail2ban:** panel girişi ve SSH için jail kurar; kurulumu yapan IP muaf tutulur.
- **logrotate** kurallarını ekler.

Docker, MSSQL, .NET/Node/PHP ve rclone **kurulmaz**; bunları panelden ihtiyaç olduğunda kurarsınız.

## İlk giriş
1. Kurulumun sonunda ekrana panel adresi, kullanıcı adı (`admin`) ve şifre basılır. Self-signed modda sertifikanın SHA-256 parmak izi de basılır.
2. Self-signed modda tarayıcı uyarı verir. Parmak izini karşılaştırıp devam edin.
3. **Ayarlar → Güvenlik**'ten 2FA'yı açın ve kurtarma kodlarını saklayın. İsterseniz IP allowlist tanımlayın.
4. Şifreyi unutursanız `sudo -u hostpanel /opt/hostpanel/bin/hostpanel admin reset-password` çalıştırın. 2FA cihazı kaybolursa `admin disable-2fa` kullanın.

Paneli hiç dışarı açmadan SSH tüneliyle de kullanabilirsiniz:
```bash
ssh -L 8443:127.0.0.1:8443 kullanici@sunucu
```
Ardından `https://127.0.0.1:8443` adresini açın.

## Güncelleme
- **Panelden:** Ayarlar → Güncelleme → "vX.Y.Z sürümüne güncelle".
  - Panel her gün yeni sürümü kontrol eder ve bildirim gönderir.
  - Güncellemeyi root indirir ve SHA-256 ile doğrular. Ardından paneli durdurur ve veritabanının kopyasını alır.
  - Yeni sürüm kurulur ve health check yapılır. Başarısız olursa önceki sürüme **otomatik geri döner**.
  - Sonuç İşlem Geçmişi'ne ve Log Merkezi → "Panel güncelleme" kaynağına düşer.
- **Komut satırından:**
  ```bash
  sudo /opt/hostpanel/update.sh            # en son sürüm
  sudo /opt/hostpanel/update.sh v0.2.0     # belirli sürüm
  ```

## Kaldırma
```bash
sudo /opt/hostpanel/uninstall.sh
```
Varsayılan olarak yalnızca panel kaldırılır. Siteler çalışmaya devam eder; veritabanları, yedekler, panel ayarları ve UFW kuralları korunur. Bunları da silmek için ayrı bayraklar vardır; her biri ayrıca yazılı onay ister:

| Bayrak | Siler |
|---|---|
| `--delete-sites` | Tüm siteler: servisler, nginx config'leri, site kullanıcıları, `/var/www/sites` |
| `--delete-databases` | MSSQL container'ı ve tüm veritabanları |
| `--delete-backups` | Yerel yedekler (`/var/backups/hostpanel`); Drive'dakiler kalır |
| `--purge-config` | Panel veritabanı, config, `master.key`, loglar, `hostpanel` kullanıcısı |

## Sunucu taşıma
1. **Eski sunucu:** Ayarlar → Taşıma → parola (en az 12 karakter) ile `.hpcfg` dosyasını indirin.
   - Dosyada admin hesabı + 2FA, ayarlar, bildirimler, müşteriler, yedek planları, Drive ayarları ve crypt anahtarları, özel runtime tanımları ve `master.key` bulunur.
   - Dosya argon2id + AES-256-GCM ile şifrelenir.
   - Siteler, veritabanları, sertifikalar ve geçmiş dosyada yer almaz.
   - Drive token'ı ve git deploy key'leri yalnızca root'ta durduğu için dışa aktarılmaz.
2. **Yeni sunucu:** dosyayı kopyalayıp kurun:
   ```bash
   sudo bash install.sh --import hostpanel-config-….hpcfg
   ```
   Panel zaten kuruluysa:
   ```bash
   sudo systemctl stop hostpanel
   sudo /opt/hostpanel/bin/hostpanel admin import-config --file F.hpcfg
   sudo systemctl start hostpanel
   ```
3. **Yedekler → Ayarlar:**
   - rclone'u kurun ve Drive token'ını yeniden girin (crypt anahtarları dosyadan gelir).
   - "Drive'ı tara" ile yedekleri listeye alın.
4. MSSQL kullanılıyorsa sunucuyu kurun ve müşteri login'lerini yeniden oluşturun (müşteri detayı).
5. Siteleri oluşturup yedekten geri yükleyin. DNS'i yeni sunucuya çevirip SSL alın.

## Güvenlik özeti
- **Yetki sınırı:**
  - Panel root olarak çalışmaz; root işleri yalnızca sudoers'ta tek tek listelenmiş `hp-*.sh` script'leriyle yapılır.
  - Script'ler her argümanı yeniden doğrular. Komutlar asla kabuk üzerinden kurulmaz.
- **Panel arkada:** panel yalnızca `127.0.0.1:8090`'da dinler; dışarıya nginx (TLS 1.2/1.3) açar.
- **Gizli bilgiler:** AES-256-GCM ile saklanır (`master.key`, 0600) ve loglarda maskelenir.
- **Yalnızca root'ta duranlar:** Drive token'ı, git deploy key'leri ve yedek dosyaları. Panel ele geçirilse bile bunları okuyamaz.
- **Site izolasyonu:** her site ayrı kullanıcı ve sandbox'la çalışır. MSSQL'de müşteriler birbirinin veritabanını göremez.
- **Oturum güvenliği:** argon2id, 2FA, CSRF, sıkı CSP, giriş rate limit'i, fail2ban.

## Geliştirme
```bash
export PATH="$HOME/.local/go/bin:$HOME/go/bin:$PATH"
make run-dev        # http://127.0.0.1:8080, dry-run; admin şifresi ilk açılışta terminale basılır
make lint test
make build build-arm64
make dist VERSION=v0.1.0   # dist/: iki tarball + install.sh + SHA256SUMS
```
Mimari ve kurallar: [CLAUDE.md](CLAUDE.md). Gereksinimler: [PROMPT.md](PROMPT.md).

## Sürüm çıkarma
`v*.*.*` etiketi push edildiğinde GitHub Actions çalışır:
1. testleri koşar
2. amd64/arm64 paketlerini ve `SHA256SUMS`'u üretir
3. GitHub Release oluşturur

```bash
git tag v0.1.0 && git push origin main --tags
```

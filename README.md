# HostPanel

Ubuntu 24.04 için tek yöneticili, ultra hafif hosting kontrol paneli: Go, tek statik binary (~19 MB), boşta < 30 MB RAM, boşta ~%0 CPU.

## Özellikler
- **Siteler:** ASP.NET Core, Node.js, PHP 8.3 (site başına php-fpm) ve statik/SPA. Her site kendi Linux kullanıcısı ve sıkı sandbox'lı systemd unit'iyle çalışır. İsteğe bağlı olarak tüm alt alan adlarını karşılar (`*.alanadi.com`).
- **Deploy:** zip yükleme veya Git (SSH deploy key / açık https), sunucuda build. Health check başarısızsa önceki sürüme otomatik döner; tek tıkla rollback.
- **SSL:** Let's Encrypt (DNS + HTTP ön kontrolü, otomatik yenileme), panelin DNS sunucusuyla DNS doğrulaması ve wildcard (`*.alanadi.com`) sertifika, CSR üretimi, ücretli sertifika doğrulama ve kurulumu, bitiş takibi.
- **MSSQL 2025 (Docker):** müşteri başına login, izole veritabanları, dış erişim için IP allowlist + UFW.
- **PostgreSQL 18 (Docker):** müşteri başına rol, sahibine ait veritabanları, site env'ine connection string, `pg_dump -Fc` dökümüyle taşıma, yedek/geri yükleme, dış erişim için IP allowlist + UFW.
- **E-posta (docker-mailserver):** müşteri alan adları için posta kutuları, kota, yönlendirmeler, catch-all; DKIM/SPF/DMARC/MX kayıtları panelin DNS'ine otomatik; Let's Encrypt sertifikası, kuyruk, engellenen IP'ler, yedek/geri yükleme. İstemcilerin otomatik ayarı (Thunderbird, Outlook, iPhone/Mac profili), kutu başına saatlik gönderim sınırı, kutuyu askıya alma / gönderimini durdurma, kara liste (RBL) kontrolü, DMARC politikası ve raporları. Webmail yoktur.
- **Yedekleme:** yerel + Google Drive (rclone, isteğe bağlı şifreleme). Planlar, saklama kuralları, geri yükleme/klon ve taşıma sihirbazı. Haftalık yedek doğrulama (Drive'dan indirip sağlama, arşiv ve veritabanı kontrolü; hiçbir şey geri yüklenmez).
- **DNS (kendi nameserver'larınız):** BIND 9 (yalnızca yetkili sunucu), zone ve kayıt yönetimi (A, AAAA, CNAME, MX, TXT, SRV, CAA, NS), sitelerin A/AAAA kayıtları otomatik, yetki devri kontrolü, isteğe bağlı DNSSEC.
- **İzleme:** CPU/RAM/disk, site başına RAM/CPU, health check, çökme döngüsü tespiti, altyapı izleme (nginx, Docker, BIND, fail2ban, certbot, veritabanı ve posta container'ları), 30 günlük sunucu metrik grafikleri, dış heartbeat (healthchecks.io / Uptime Kuma), Telegram/e-posta bildirimleri, günlük/haftalık özet raporu, Telegram komutları (`/durum`, `/siteler`, `/disk`, `/yedekler`, 2FA kodlu `/yeniden_baslat`).
- **Alan adları:** sitelerin, zone'ların ve posta alan adlarının kayıt bitiş tarihleri (RDAP; `.tr` gibi RDAP'sız uzantılarda elle), 30/15/7 gün kala bildirim.
- **İstatistikler:** site bazlı günlük trafik (istek, ziyaretçi, bant genişliği, 4xx/5xx, bot, en çok açılan sayfalar; nginx loglarından) ve uptime geçmişi (günlük erişilebilirlik, ortalama yanıt süresi, kesinti kayıtları).
- **Container güncellemeleri:** MSSQL ve posta sunucusu imajları her gün kontrol edilir, yeni sürümde bildirim gelir; tek tıkla güncelleme (başarısız olursa eski sürüme otomatik dönüş).
- **Log Merkezi:** işlem geçmişi, iş logları (canlı), sistem logları (nginx, journal, certbot, fail2ban, auth.log…).
- **Site cron'ları; toplu işlemler** (seçili sitelerde yeniden başlatma, bakım modu, nginx yeniden uygulama, yedek).
- **.NET/Node yama güncellemeleri:** aynı ana sürümdeki yeni yama kurulur, siteler tek tek taşınır; health check geçmeyen site eski sürümde kalır.
- **Sunucu yönetimi:** servisleri yeniden yükleme/başlatma, `nginx -t`, sistem güncellemeleri (yalnızca güvenlik ya da tümü, otomatik güncellemeler, yeniden başlatılması gereken servisler), planlı yeniden başlatma + açılış raporu, bellek planı, swap, bellek yetersizliği (OOM) uyarısı, disk dağılımı, disk temizliği asistanı (eski arşivler, kullanılmayan Docker imajları, apt önbelleği, eski journal; müşteri e-postaları silinmez), UFW.
- **Güvenlik:** 2FA (TOTP + kurtarma kodları), IP allowlist, kritik işlemlerde yeniden doğrulama, açık oturumlar ve giriş geçmişi, SSH ayarları (parola/root girişi; onaylanmazsa 3 dakikada kendiliğinden geri alınır) ve yönetici anahtarları, fail2ban (engelliler, süreler, muaf IP'ler), güvenlik denetimi sayfası, kritik değişiklik bildirimleri, root script bütünlük kontrolü.
- **Panel yönetimi:** panelden tek tıkla güncelleme (otomatik geri dönüşlü), yapılandırmayı dışa/içe aktarma.

## Gereksinimler
- Ubuntu 24.04 LTS, amd64 veya arm64
- root (sudo) erişimi
- Önerilen en az 2 GB RAM; MSSQL kullanılacaksa 4 GB (PostgreSQL varsayılan olarak 2 GB ayırır, en az 512 MB; posta sunucusu 1 GB, virüs taramasıyla en az 2.5 GB)
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

Docker, MSSQL, PostgreSQL, .NET/Node/PHP ve rclone **kurulmaz**; bunları panelden ihtiyaç olduğunda kurarsınız.

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

## Panel adresi (panel.alanadiniz.com)
Kurulumda alan adı vermediyseniz ya da adı değiştirmek istiyorsanız: **Ayarlar → Genel → Panel adresi**.
1. Ön eki (varsayılan `panel`) yazın, listeden bir alan adı seçin. Liste paneldeki DNS zone'larından ve sitelerin alan adlarından oluşur.
2. "Panel adresini değiştir"e basın. Panel şunları kendisi yapar:
   - Zone paneldeyse A/AAAA kaydını ekler. Zone başka yerdeyse sayfadaki IP'lere A kaydını DNS sağlayıcınızda siz girersiniz.
   - Adın genel DNS'te bu sunucuya çözülmesini bekler (en fazla ~2 dk).
   - Let's Encrypt sertifikası alır, sonra nginx'i `https://panel.alanadiniz.com` (443) için yapılandırır. 80. port bu adrese yönlenir.
3. Eski `https://<sunucu-ip>:8443` adresi **yedek giriş** olarak açık kalır (self-signed). Yeni ad bozulursa buradan girebilirsiniz.

Notlar:
- Sertifika alınana kadar panel eski adresinden çalışmaya devam eder. Bir adım başarısız olursa adres değişmez, DNS kaydı geri alınır.
- Bir sitenin, posta sunucusunun ya da nameserver'ın adı seçilemez. Aynı adda elle girilmiş bir DNS kaydı varsa ad reddedilir.
- Oturum çerezleri adrese bağlıdır, yeni adreste bir kez yeniden giriş yapılır.
- "Alan adını kaldır" paneli yalnızca IP adresine döndürür ve sertifikayı siler.

## Kendi nameserver'larınız (DNS)
1. **DNS** sayfasında nameserver adlarını (ör. `ns1.alanadiniz.com`, `ns2.alanadiniz.com`), yönetici e-postasını ve sunucunun genel IP'lerini kaydedin.
2. "DNS sunucusunu kur": Ubuntu deposundan BIND 9 kurulur.
   - Yalnızca yetkili sunucu olarak çalışır: recursion ve zone transferi kapalı, yanıt hız sınırı (RRL) açık.
   - UFW etkinse 53/udp + 53/tcp açılır. SSH kurallarına dokunulmaz.
3. **Registrar'da glue kayıtları:** `alanadiniz.com`'un registrar'ında `ns1`/`ns2` için glue (child nameserver) kaydı açıp sunucu IP'sini girin. Tek sunucuda ikisi de aynı IP'yi gösterir. Bazı uzantıların registry'leri iki farklı IP isteyebilir; registrar'ınıza danışın.
4. **Zone'lar:** zone ekleyin ya da site sihirbazında "DNS zone'u oluştur"u işaretleyin.
   - Sitenin domain, www ve alias'ları için A/AAAA kayıtları otomatik üretilir; aynı ada elle kayıt girerseniz sizinki geçerli olur.
   - Domain'in nameserver'larını registrar'da `ns1`/`ns2` yapın. Zone sayfasındaki "Yetki devri" alanı yayıldığında yeşile döner (birkaç saat sürebilir).
5. **DNSSEC (isteğe bağlı):** zone ayarlarından açın; "DS kaydı"nı registrar'a girin. Kapatmadan önce DS'i registrar'dan kaldırın.
6. **Wildcard site ve sertifika:** site → Ayarlar → "Tüm alt alan adlarını da karşıla" (zone panelin DNS sunucusunda olmalı; `*` kaydı otomatik eklenir). Ardından SSL sekmesinde `*.alanadi.com`'u seçip "DNS (panelin DNS sunucusu)" yöntemiyle sertifika alın. certbot doğrulama kaydını (`_acme-challenge`) zone'a kendisi yazar ve siler; yenileme de aynı yolla otomatiktir. DNS doğrulaması CDN arkasındaki sitelerde de kullanılabilir. Kendi sitesi olan alt adlar, posta adı ve panel etkilenmez.

Sunucu kapalıyken bu domain'ler çözülmez. E-posta gibi kritik hizmetler için bunu göz önünde bulundurun.

## PostgreSQL
1. **Veritabanları → PostgreSQL:** Docker yoksa "Docker'ı kur", ardından bellek miktarını seçip "PostgreSQL'i kur".
   - İmaj `postgres:18.6-trixie`, container `hostpanel-postgres`, veri `/var/lib/hostpanel-db/postgres` (v0.8.0 öncesi kurulumlarda `/var/lib/hostpanel/postgres`; aşağıdaki nota bakın).
   - Yalnızca `127.0.0.1:5432`'de dinler. `postgres` süper kullanıcısının şifresi yoktur ve TCP'den bağlanamaz; yönetim işlerini root helper container içinden yapar.
2. **Müşteri rolü + veritabanı:** veritabanını oluştururken müşteriyi ve (isteğe bağlı) siteyi seçin. Rol (`c_<müşteri>`) gerekirse otomatik açılır. Bağlantı dizesi sitenin ortam değişkenine yazılır:
   - .NET (Npgsql): `ConnectionStrings__DefaultConnection` = `Host=127.0.0.1;Port=5432;Database=…;Username=…;Password=…`
   - Node / PHP: `DATABASE_URL` = `postgresql://rol:şifre@127.0.0.1:5432/db`
3. **Mevcut veritabanını taşıma:** eski sunucuda custom formatta döküm alın:
   ```bash
   pg_dump -Fc -d <veritabani> -f <veritabani>.dump
   ```
   Ardından site → Taşıma → "PostgreSQL dökümü yükle".
   - Döküm müşteri rolüyle, tek transaction'da geçici bir veritabanına açılır; başarılı olursa yerine konur.
   - Düz `.sql` dökümleri kabul edilmez: psql meta komutları (`\!`) container içinde komut çalıştırabilir.
   - Süper kullanıcı isteyen ("untrusted") uzantılar ve imajda olmayanlar (ör. `postgis`) yüklenemez; hata job logunda görünür. `pgcrypto`, `uuid-ossp`, `citext` gibi güvenilir uzantılar sorun çıkarmaz.
4. **Yedekler:** site yedeğinin "veritabanları" bileşeni PostgreSQL veritabanlarını da kapsar (`db-pg-<ad>.dump`). Geri yükleme ve klon MSSQL'deki gibi çalışır.
5. **Dış erişim (isteğe bağlı):** ayarlardan IP/CIDR listesi girin. UFW etkin olmalıdır; kurallar `hostpanel-pg` yorumuyla eklenir.

Not: PostgreSQL'de veritabanı **adları** tüm rollere görünür; içerik görünmez. Bir müşteri başka bir müşterinin veritabanına bağlanamaz, okuyamaz ve yazamaz. "İzolasyon testi" bunu iki yönde doğrular.

**Veri dizinini güvenli konuma taşıma (v0.8.0 öncesi kurulumlar):** MSSQL ve PostgreSQL verisi eskiden panel kullanıcısına ait `/var/lib/hostpanel` altındaydı. Veritabanları ve PostgreSQL sayfalarındaki "Veri dizinini güvenli konuma taşı" (`TASI` yazarak) container'ı kaldırır, dizini root'a ait `/var/lib/hostpanel-db/`'ye taşır (aynı disk; kopya değil, anlık) ve container'ı yeniden açar. Birkaç dakikalık kesinti olur; açılmazsa eski konuma otomatik dönülür. Güvenlik sayfası eski konumdaki kurulumları uyarır. Ayrıntılı adımlar, doğrulama komutları ve hata durumunda yapılacaklar: [docs/mssql-veri-tasima.md](docs/mssql-veri-tasima.md).

## E-posta
1. **Ön koşullar:**
   - Posta sunucusunun adı (ör. `mail.ornek.com`) için bu sunucuyu gösteren bir **A kaydı**.
   - Sağlayıcı panelinden sunucu IP'sinin **PTR** (ters DNS) kaydı = posta sunucusunun adı.
   - Sağlayıcı giden 25. portu açmış olmalı (E-posta sayfasındaki "Kontrol et" bunu dener).
   - Bu ad bir site ya da panel domain'i olamaz.
2. **E-posta → kurulum:** Docker yoksa "Docker'ı kur". Ardından posta sunucusunun adı, ilk alan adı, Let's Encrypt e-postası ve bellek (varsayılan 1024 MB) → "Posta sunucusunu kur".
   - İmaj `mailserver/docker-mailserver:17.0.0-r1`, container `hostpanel-mail`, veri `/var/lib/hostpanel-mail`.
   - 25, 465, 587 ve 993. portlar açılır. Bu portlar Docker üzerinden yayınlandığı için **UFW'den geçmez**; UFW onları kapatamaz.
   - Kurulum sertifikayı alır, DKIM anahtarını üretir ve açık röle testi yapar.
3. **Alan adı ekle** (müşteri seçilebilir) → alan adı sayfasında posta kutuları, kota ve yönlendirmeler.
   - Şifre panelde **saklanmaz**: oluşturma ve sıfırlamada bir kez gösterilir.
   - Zone panelin DNS'indeyse MX, SPF, DKIM ve DMARC kayıtları otomatik yayınlanır. Değilse sayfadaki tabloyu alan adının DNS sağlayıcısına girin.
4. **İstemci ayarları:** IMAP `<posta adı>:993` (SSL/TLS), SMTP `<posta adı>:465` (SSL/TLS) ya da `587` (STARTTLS); kullanıcı adı tam e-posta adresidir.
   - **Otomatik ayar:** E-posta → Teslim edilebilirlik → "Otomatik ayar adlarını sertifikaya ekle" (`autoconfig.` / `autodiscover.` + posta adının üst alan adı; A kayıtları bu sunucuyu göstermeli). Sonra Thunderbird ve Outlook yalnızca adres + şifreyle kurulur. iPhone/Mac için posta kutusu satırındaki **Apple profili** (şifre içermez; imzasız olduğu için iOS "doğrulanmamış" der).
5. **Teslim edilebilirlik** (E-posta → Teslim edilebilirlik):
   - **Gönderim sınırı:** her kutu saatte en fazla N ileti (varsayılan 200). Aşan iletiler geçici hatayla reddedilir. Kuyruk birikmesi ve olağan dışı gönderim bildirim olarak gelir (bildirim türü "Posta").
   - **Erişim:** alan adı sayfasında bir kutuyu **askıya alın** (giriş kapanır, posta gelmeye devam eder) ya da yalnızca **gönderimini durdurun** (isteğe bağlı olarak kuyruktaki iletileri silerek). Geri açmak son 10 dakikada kimlik doğrulaması ister.
   - **Catch-all:** alan adının bilinmeyen adreslerine gelen postalar paneldeki bir kutuya (spam'i artırır).
   - **Kara listeler:** sunucu IP'si ve alan adları her gün Spamhaus, SpamCop, Barracuda, PSBL, Mailspike'ta sorgulanır. Spamhaus genel DNS çözümleyicilerini yanıtlamaz; ücretsiz DQS anahtarı girilebilir.
   - **DMARC:** alan adı başına politika (none / quarantine / reject). Bir `dmarc@<alan adı>` kutusu seçilirse raporlar oraya gelir ve panelde alan adı başına özet (geçen/kalan IP'ler) gösterilir. Panel yalnızca bu kutuyu okur.
6. **Yedek:** E-posta sayfasından "Şimdi yedekle" ya da Yedekler → plan kapsamı "Posta sunucusu". Yedek tüm hesapları, DKIM anahtarlarını ve postaları içerir (tam yedek). Geri yükleme E-posta sayfasından yapılır.

Kaba kuvvet denemelerini container içindeki fail2ban engeller (yalnızca posta portları; SSH'a dokunmaz). Engellenen IP'ler E-posta sayfasından kaldırılabilir.

## İstatistikler
- **Site → İstatistik** sekmesi: son 7/30/90 gün; günlük istek grafiği, erişilebilirlik şeridi, en çok açılan sayfalar, kesintiler ve günlük tablo. Bugün canlı hesaplanır; önceki günler saklanır (400 gün).
- **İstatistikler** menüsü: tüm sitelerin özeti.
- Trafik nginx'in erişim logundan gelir: panelin kendi kontrolleri (127.0.0.1) ve Let's Encrypt doğrulamaları sayılmaz, botlar ayrı gösterilir. Site Cloudflare gibi bir proxy arkasındaysa ziyaretçi IP'leri proxy'nin IP'leridir.
- Erişilebilirlik, sitenin health check sonuçlarından hesaplanır (Genel sekmesindeki "Sağlık kontrolü" açık olmalı).

## Container güncellemeleri (MSSQL, posta)
- Panel her gün Microsoft Container Registry'ye ve Docker Hub'a bakar. Yeni sürüm çıkınca bir kez bildirim gönderir (Bildirimler → "Panel ve container güncellemeleri").
- **Ayarlar → Güncelleme → Container imajları** ya da ilgili sayfadaki **Güncelle** düğmesi:
  - **MSSQL:** yalnızca aynı SQL Server sürümünün yeni CU/GDR'leri (ör. `2025-CU10` → `2025-CU10-GDR1`). Yeni imaj önce indirilir, sonra SQL Server durdurulup veri dizininin kopyası alınır (`/var/backups/hostpanel/_mssql/pre-update`; yeterli boş disk gerekir) ve yeni sürümle başlatılır. Açılmazsa kopya ve eski sürüm otomatik geri konur.
  - **Posta sunucusu:** aynı ana sürümün yeni sürüm/revizyonları. Postalar ve hesaplar korunur; açılmazsa eski sürüme dönülür.
- Ana sürüm geçişleri (ör. SQL Server 2027, docker-mailserver 18) yalnızca bilgi olarak gösterilir.

## Sunucu güvenliği ve bakım
- **Sunucu → SSH:** parola ve root girişini kapatmak için önce bir yönetici anahtarınızın olması gerekir. "Uygula"dan sonra **bu oturumu kapatmadan** yeni bir terminalde bağlanmayı deneyin; girebiliyorsanız "Çalışıyor, onayla". 180 saniye içinde onaylanmazsa ayarlar root'un zamanlayıcısıyla geri alınır (panel çökse bile). SSH portu panelden değiştirilmez.
- **Sunucu → fail2ban:** şu anki IP adresiniz muaf listede olmadan ayar kaydedilmez.
- **Sunucu → Güncellemeler:** güncellemeler panelden bağımsız bir systemd biriminde çalışır (panel yeniden başlasa da yarıda kalmaz); paket kaldırılmaz, değiştirdiğiniz ayar dosyaları korunur. Docker paketleri ayrıca onaylanmadıkça güncellenmez (tüm container'lar yeniden başlar).
- **Yeniden başlatma:** `YENIDEN-BASLAT` yazarak planlanır, iptal edilebilir; açıldıktan birkaç dakika sonra panel ne geri geldi/gelmedi raporunu bildirim olarak gönderir.
- **Güvenlik** menüsü: SSH, UFW, beklenmeyen açık portlar, fail2ban, güncellemeler, 2FA, yedekler, SSL ve script bütünlüğü için tek sayfada denetim.
- Silme, gizli bilgi gösterme, geri yükleme ve sunucu ayarları gibi işlemler son 10 dakikada kimlik doğrulaması ister (şifre ya da 2FA kodu).

## İşletme ve izleme
- **Ayarlar → Bildirimler:** "Özet raporu" (her gün / her hafta, saat), "Dış izleme (heartbeat)" — panel 5 dakikada bir adrese istek atar; sunucu tamamen kapanırsa dış servis sizi uyarır. "Telegram komutlarına yanıt ver" açıkken bot yalnızca kayıtlı chat ID'den gelen **özel** mesajlara yanıt verir; `/yeniden_baslat <site> <2FA kodu>` için panelde 2FA açık olmalı.
- **Alan adları** menüsü: bitiş tarihleri her gün sorgulanır; RDAP'ı olmayan uzantılar için tarihi elle girin.
- **Sunucu → Metrikler / Disk temizliği**, **Yedekler → Doğrulama**, **Altyapılar → Yama güncellemeleri**, **Siteler** listesinde onay kutularıyla toplu işlemler.

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
Varsayılan olarak yalnızca panel kaldırılır. Siteler çalışmaya devam eder; veritabanları, posta sunucusu, yedekler, panel ayarları ve UFW kuralları korunur. Bunları da silmek için ayrı bayraklar vardır; her biri ayrıca yazılı onay ister:

| Bayrak | Siler |
|---|---|
| `--delete-sites` | Tüm siteler: servisler, nginx config'leri, site kullanıcıları, `/var/www/sites` |
| `--delete-databases` | MSSQL ve PostgreSQL container'ları ve tüm veritabanları |
| `--delete-mail` | Posta sunucusu, tüm posta kutuları ve postalar (`/var/lib/hostpanel-mail`), sertifikası ve vhost'u |
| `--delete-backups` | Yerel yedekler (`/var/backups/hostpanel`); Drive'dakiler kalır |
| `--purge-config` | Panel veritabanı, config, `master.key`, loglar, `hostpanel` kullanıcısı |

## Sunucu taşıma
1. **Eski sunucu:** Ayarlar → Taşıma → parola (en az 12 karakter) ile `.hpcfg` dosyasını indirin.
   - Dosyada admin hesabı + 2FA, ayarlar, bildirimler, müşteriler, yedek planları, DNS zone'ları ve kayıtları, Drive ayarları ve crypt anahtarları, özel runtime tanımları ve `master.key` bulunur.
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
4. DNS kullanılıyorsa: DNS → IP'leri kontrol edip kaydedin → "DNS sunucusunu kur"; registrar'da glue IP'lerini değiştirin. DNSSEC'li zone'lar yeni anahtarla imzalanır, yeni DS kaydını registrar'a girin.
5. MSSQL/PostgreSQL kullanılıyorsa sunucuyu kurun ve müşteri login'lerini/rollerini yeniden oluşturun (müşteri detayı).
6. E-posta kullanılıyorsa: posta sunucusunu aynı adla kurun, ardından Drive'dan taranan posta yedeğini E-posta sayfasından geri yükleyin (alan adları ve DKIM anahtarları yedekten gelir). A/PTR kayıtlarını yeni IP'ye çevirin.
7. Siteleri oluşturup yedekten geri yükleyin. DNS'i yeni sunucuya çevirip SSL alın.

## Güvenlik özeti
- **Yetki sınırı:**
  - Panel root olarak çalışmaz; root işleri yalnızca sudoers'ta tek tek listelenmiş `hp-*.sh` script'leriyle yapılır.
  - Script'ler her argümanı yeniden doğrular. Komutlar asla kabuk üzerinden kurulmaz.
- **Panel arkada:** panel yalnızca `127.0.0.1:8090`'da dinler; dışarıya nginx (TLS 1.2/1.3) açar.
- **Gizli bilgiler:** AES-256-GCM ile saklanır (`master.key`, 0600) ve loglarda maskelenir.
- **Yalnızca root'ta duranlar:** Drive token'ı, git deploy key'leri ve yedek dosyaları. Panel ele geçirilse bile bunları okuyamaz.
- **Site izolasyonu:** her site ayrı kullanıcı ve sandbox'la çalışır. MSSQL'de müşteriler birbirinin veritabanını göremez; PostgreSQL'de bağlanamaz.
- **E-posta:** ele geçirilmiş bir kutu saatlik sınırla sınırlanır ve tek tıkla durdurulur; panel müşteri postalarını okumaz (yalnızca seçilen DMARC rapor kutusu).
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

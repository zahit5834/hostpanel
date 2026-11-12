# MSSQL veri dizinini güvenli konuma taşıma

Bu rehber v0.8.0 öncesinde kurulmuş SQL Server'ın veri dizinini `/var/lib/hostpanel/mssql`'den `/var/lib/hostpanel-db/mssql`'e taşımayı anlatır. Taşıma panelden yapılır. Sondaki bölüm PostgreSQL'i kapsar.

> **Durum:** Taşıma kodu birim testlerinden geçti. Ortak taşıma fonksiyonu (`db_relocate`) ve PostgreSQL yolu geçici bir container'da uçtan uca denendi. **MSSQL yolu gerçek bir SQL Server container'ında denenmedi**, çünkü ikinci bir SQL Server için ~2 GB RAM gerekiyor. Otomatik geri dönüş var, ama başlamadan önce mutlaka yedek alın (adım 1).

---

## 1. Neden taşınıyor?

`/var/lib/hostpanel` panel kullanıcısına (`hostpanel`) aittir. Veritabanı dizini bu üst dizindeyken akış şöyledir:

1. Root helper (`hp-mssql.sh`) dizinin symlink olmadığını kontrol eder.
2. Ardından dizini kullanır (chown, container'a bağlama).

İki adımın arasında kısa bir pencere kalır. Panel ele geçirilirse, saldırgan bu pencerede dizini bir symlink ile değiştirip root'a başka bir sistem dizinini chown ettirebilir ya da container'a bağlatabilir.

Yeni üst dizin `/var/lib/hostpanel-db` root'a aittir (0711). Panel kullanıcısı oraya yazamaz, bu yüzden pencere tamamen kapanır.

Güvenlik sayfasında şu uyarıyı görüyorsanız taşıma gerekiyordur:

> **Veritabanı veri dizinleri** — MSSQL verisi panel kullanıcısına ait üst dizinde…

## 2. Taşıma neyi değiştirir, neyi değiştirmez?

| | Değişir mi? |
|---|---|
| Veri dizininin yeri (`/var/lib/hostpanel/mssql` → `/var/lib/hostpanel-db/mssql`) | **Evet** |
| `hostpanel-mssql` container'ı | Kaldırılır, aynı imaj ve ayarlarla yeniden oluşturulur |
| Veritabanları, login'ler, şifreler, tablolar | Hayır. Dosyalar yalnızca yeniden adlandırılır, kopyalanmaz ve içeriğe dokunulmaz |
| Sitelerin connection string'leri (`127.0.0.1:1433`) | Hayır. Site yeniden başlatmak gerekmez |
| Dış erişim / UFW kuralları (1433) | Hayır. Port tabanlıdır ve container `--network host`'ta kalır |
| Bellek sınırı, sürüm (Express/Developer), imaj etiketi | Hayır. Mevcut kayıtla yeniden oluşturulur |
| `sa` şifresi | Yenilenir (her yeniden oluşturmada yapılan güvenlik rotasyonu). Sizi etkilemez, panel saklar |
| DB silme yedekleri (`pre-drop-*.bak`) | Dizinle birlikte taşınır (`mssql/backup/`) |
| Site yedekleri (`/var/backups/hostpanel/…`) ve Drive | Hayır. Yeni yedekler yeni yolu kendiliğinden kullanır |

**Kesinti:** Container yeniden oluşturulurken ve SQL Server açılırken DB'li siteler veritabanına bağlanamaz. Bu genellikle 1–3 dakika sürer. Siteler çalışmaya devam eder, ama bu sürede DB isteyen sayfalar hata verir. Uygulamalar açılınca kendiliğinden yeniden bağlanır.

**Disk:** Ek alan gerekmez. Aynı diskte `mv` yalnızca yeniden adlandırmadır ve veri boyutundan bağımsız olarak anlıktır.

## 3. Ön koşullar

1. **Panel v0.8.0 veya üzeri** olmalı (Ayarlar → Güncelleme). Ayrıca Güvenlik sayfasında "Script bütünlüğü: uyumlu" görünmeli.
2. **SQL Server "çalışıyor" ya da "durdurulmuş"** durumda olmalı. "Hata" ya da "kuruluyor" durumunda düğme reddeder.
3. **Eski ve yeni konum aynı diskte** olmalı. Bunu panel kendisi kontrol eder; farklıysa hiçbir şeye dokunmadan reddeder (bkz. §8). Kontrol için:
   ```bash
   df -h /var/lib/hostpanel /var/lib
   ```
   İki satırda da aynı aygıt (ör. `/dev/sda2`) görünmeli.
4. **Yedek alın:**
   - Her DB'li site için site → Yedekler → "Şimdi yedekle". "Veritabanları" bileşeni seçili olsun; mümkünse "Drive'a da gönder" de işaretleyin.
   - Bu yedekler `/var/backups/hostpanel/` altına düşer, yani taşınan dizinin dışındadır.
5. **Sakin bir saat seçin:** yedek planlarının çalışma saati dışında ve trafiğin az olduğu bir zaman. İşler sırayla çalıştığı için bir yedek planı taşımayla çakışmaz; ama o saatte başlayan plan, taşıma bitene kadar bekler.
6. **Son 10 dakika içinde giriş yapmış olun.** Değilse panel şifre ya da 2FA kodu sorar, sonra aynı sayfaya döner.

## 4. Adım adım

1. **Veritabanları** menüsünü açın.
2. "SQL Server" kartında şu satırı görmelisiniz: `Veri dizini: /var/lib/hostpanel/mssql`. Altında sarı bir uyarı kutusu bulunur: **"Veri dizini eski konumda."**
3. Kutudaki alana büyük harflerle **`TASI`** yazın (Türkçe `I` değil, düz `I`).
4. **"Veri dizinini güvenli konuma taşı"** düğmesine basın. Onay penceresinde "Tamam" deyin.
5. Sayfanın üstünde canlı iş logu açılır. Pencereyi kapatsanız da iş devam eder; log Log Merkezi → İş Logları'ndan da izlenebilir.
6. İş "başarılı" bittiğinde sayfayı yenileyin:
   - `Veri dizini: /var/lib/hostpanel-db/mssql` görünmeli.
   - Uyarı kutusu kaybolmuş olmalı.

## 5. İş logunda ne göreceksiniz?

Başarılı bir taşımada satırlar kabaca şu sırayla gelir:

```
Container kaldırılıyor (veri korunur); SQL Server birkaç dakika erişilemez…
container kaldırıldı (veri korunuyor: /var/lib/hostpanel/mssql)
taşındı: /var/lib/hostpanel/mssql → /var/lib/hostpanel-db/mssql
docker run hostpanel-mssql (network host, 127.0.0.1:1433, memory …m)
container başlatıldı
SQL Server'ın açılması bekleniyor (en fazla 3m0s)…
SQL Server hazır.
sa şifresi yenilendi (container ortamındaki ilk şifre artık geçersiz).
Veri dizini taşındı: /var/lib/hostpanel-db/mssql
```

Notlar:

- Dış erişim açıksa `docker run` satırında `127.0.0.1` yerine `0.0.0.0` görünür.
- Sunucu durdurulmuş durumdayken taşıdıysanız, sondan önce `durduruldu` satırı gelir ve sunucu yine **durdurulmuş** kalır.
- Logda `UYARI: sa şifresi yenilenemedi` ya da `UYARI: max server memory ayarlanamadı` görülebilir. Bunlar taşımayı geri almaz; SQL Server yeni konumda çalışıyordur. Bir sonraki "Yeniden başlat" ya da bellek ayarı değişikliği bunları yeniden dener.

## 6. Doğrulama

Sunucuda (SSH):

```bash
# Yeni üst dizin root'a ait ve yalnızca geçişe açık olmalı:
sudo ls -ld /var/lib/hostpanel-db /var/lib/hostpanel-db/mssql
#   drwx--x--x root  root  … /var/lib/hostpanel-db
#   d…         10001 …     … /var/lib/hostpanel-db/mssql   (SQL Server'ın uid'i)

# Eski konum artık yok:
sudo ls -ld /var/lib/hostpanel/mssql          # → No such file or directory

# Container yeni dizini bağlamış olmalı:
sudo docker inspect -f '{{range .Mounts}}{{.Source}} → {{.Destination}}{{end}}' hostpanel-mssql
#   /var/lib/hostpanel-db/mssql → /var/opt/mssql

# Yalnızca yerelde dinliyor (dış erişim kapalıysa):
ss -ltnp | grep 1433                           # → 127.0.0.1:1433

# Veritabanı dosyaları yerinde:
sudo ls /var/lib/hostpanel-db/mssql/data | head
```

Panelde:

- **Veritabanları:** DB listesi ve boyutları eskisi gibi görünmeli.
- **Güvenlik:** "Veritabanı veri dizinleri" uyarısı kalkmış olmalı.
- **DB'li her siteyi** tarayıcıda açın. Veri okuyan bir sayfa, ör. giriş ya da liste sayfası, çalışmalı.
- İsterseniz bir site yedeği alın ve iş logunda `db-<ad>.bak` satırına bakın; yeni yol yedekte de çalışıyor demektir.

## 7. Bir şey ters giderse

### 7.1 Otomatik geri dönüş

Taşıma şu sırayla çalışır:

1. Container'ı kaldır.
2. Dizini taşı.
3. Yeni konumla aç.

Hatalar şöyle ele alınır:

- **1. adım başarısız:** Hiçbir şey taşınmaz, iş hata ile biter.
- **2. adım başarısız:** Container eski konumla yeniden açılır. Log: `veri dizini taşınamadı, eski konumda çalışmaya devam ediyor`.
- **3. adımda SQL Server 3 dakika içinde açılmaz:** Container kaldırılır, dizin **geri taşınır** ve container eski konumla açılır. Log: `yeni konumda açılmadı, eski konuma dönüldü`.

Geri dönüş durumlarında siteleriniz eski haliyle çalışmaya devam eder. Log Merkezi → Sistem Logları → "MSSQL container" kaynağındaki SQL Server çıktısını not alıp bana iletin.

### 7.2 Sunucu "hata" durumunda kaldıysa

Bu yalnızca hem yeni hem eski konumda açılış başarısız olursa olur; ör. disk tamamen doluysa ya da Docker çalışmıyorsa. Veri her durumda iki konumdan birindedir; taşıma dosya silmez.

1. Önce nedeni giderin:
   - `df -h /`
   - `systemctl status docker`
   - Log Merkezi → "MSSQL container"
2. Log Merkezi → **İş Logları** → başarısız `db.server.relocate` işini açın → **"Yeniden dene"**.
   - Adımlar tekrarlanabilir. Daha önce taşınmış dizin atlanır ve container verinin bulunduğu konumla açılır.
   - Helper, verinin iki konumda da bulunmadığı bir durumda boş bir SQL Server başlatmayı reddeder.

Verinin nerede olduğunu görmek için:

```bash
sudo ls -ld /var/lib/hostpanel/mssql /var/lib/hostpanel-db/mssql 2>&1
```

Tam olarak biri var olmalı.

### 7.3 Son çare: yedekten dönüş

Yeni sunucu boş açıldıysa ya da DB'ler eksik görünüyorsa site → Yedekler'den 3. adımda aldığınız yedeği geri yükleyin. Bu durum beklenmez, çünkü veri dosyalarına dokunulmaz.

## 8. Eski ve yeni konum farklı disklerdeyse

Örnek: `/var/lib/hostpanel` ayrı bir diske bağlanmış. Bu durumda panel taşımayı **reddeder** ve hiçbir şeye dokunmaz. Log mesajı: `… farklı dosya sistemlerinde (taşıma yalnızca aynı diskte yapılır)`.

Diskler arası taşıma bir kopyalamadır: veri boyutu kadar süre ve boş alan ister. Bu nedenle panel bunu tek tıkla yapmaz.

Bu sunucuda geçerli değildir: tek disk var (`/dev/sda2`).

Böyle bir kurulumda veri eski konumda kalabilir. Panel ve yedekler orada da çalışır, ve kalan risk yalnızca panelin zaten ele geçirilmiş olmasını gerektirir. Güvenlik sayfasındaki uyarı kalır.

## 9. PostgreSQL

Aynı işlem **Veritabanları → PostgreSQL** sayfasında yapılır: `TASI` yazıp "Veri dizinini güvenli konuma taşı" düğmesine basın.

- `postgres/` ve `postgres-backup/` (DB silme dökümleri) birlikte `/var/lib/hostpanel-db/` altına taşınır.
- Container yeniden oluşturulup hazır olması beklenir (en fazla 2 dakika). Açılmazsa eski konuma dönülür. `sa` rotasyonu PostgreSQL'de yoktur, süper kullanıcı şifresizdir.
- Sitelerin `127.0.0.1:5432` bağlantıları, `pg_hba` kuralları ve UFW değişmez.
- Doğrulama:
  ```bash
  sudo ls -ld /var/lib/hostpanel-db/postgres /var/lib/hostpanel-db/postgres-backup
  sudo docker inspect -f '{{range .Mounts}}{{.Source}} → {{.Destination}}{{end}}' hostpanel-postgres
  ```
- Hata durumunda §7'deki adımlar aynen geçerlidir. İş türü `pg.server.relocate`, log kaynağı "PostgreSQL container".

İki motoru ayrı zamanlarda taşıyın: önce birini taşıyıp siteleri doğrulayın, sonra diğerine geçin.

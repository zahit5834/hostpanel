package sysmaint

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/zahit5834/hostpanel/internal/exec"
)

// --- S4: disk assistant (list + delete one item at a time; nothing automatic) ---

// CleanCategory describes one kind of leftover.
type CleanCategory struct {
	ID, Label, Hint string
	Deletable       bool
	Items           []CleanItem
	Bytes           int64
}

// CleanItem is one deletable thing (file, directory, image, cache).
type CleanItem struct {
	Cat, ID, Label string
	Bytes          int64
	Time           time.Time
}

// cleanCats is the display order; uploads are the panel's own files.
var cleanCats = []CleanCategory{
	{ID: "predelete", Label: "Silinen sitelerin arşivleri", Hint: "Site silinirken alınan dosya + ayar arşivi (/var/backups/hostpanel/<site>/pre-delete-*).", Deletable: true},
	{ID: "predrop-mssql", Label: "Silinen MSSQL veritabanlarının yedekleri", Hint: "Veritabanı silinmeden önce alınan .bak dosyaları.", Deletable: true},
	{ID: "predrop-pg", Label: "Silinen PostgreSQL veritabanlarının dökümleri", Hint: "Veritabanı silinmeden önce alınan pg_dump dosyaları.", Deletable: true},
	{ID: "mssql-update", Label: "MSSQL güncelleme kopyaları", Hint: "İmaj güncellemesinden önce alınan veri kopyası (pre-update) ve başarısız güncellemenin verisi (failed-*). Güncelleme sorunsuz geçtiyse silinebilir.", Deletable: true},
	{ID: "dnsarchive", Label: "Silinen DNS zone arşivleri", Hint: "Zone dosyası ve DNSSEC anahtarları.", Deletable: true},
	{ID: "docker-image", Label: "Kullanılmayan Docker imajları", Hint: "Hiçbir container'ın kullanmadığı imajlar (güncellemeden kalan eski sürümler). Kullanılan imaj silinemez.", Deletable: true},
	{ID: "apt", Label: "apt paket önbelleği", Hint: "İndirilmiş .deb dosyaları (apt-get clean). Gerekirse yeniden indirilir.", Deletable: true},
	{ID: "journal", Label: "Sistem günlüğü (journal)", Hint: "30 günden eski journal kayıtları silinir (journalctl --vacuum-time=30d).", Deletable: true},
	{ID: "uploads", Label: "Yarım kalan yüklemeler", Hint: "Panelin yükleme dizininde 1 günden eski zip/.bak/döküm dosyaları.", Deletable: true},
	{ID: "mail", Label: "Posta arşivleri (yalnızca bilgi)", Hint: "Silinen posta kutuları, DKIM anahtarları ve geri yükleme öncesi kopya. Müşteri e-postası olduğu için panelden silinmez; gerekirse SSH ile elle.", Deletable: false},
}

var uploadNameRe = regexp.MustCompile(`^(upload|import|pgimport)-[0-9]+\.(zip|bak|dump)$`)

// UploadMaxAge is how old an upload must be to count as abandoned.
const UploadMaxAge = 24 * time.Hour

// ParseCleanList reads "hp-system.sh clean-list".
func ParseCleanList(out string) []CleanItem {
	var items []CleanItem
	for _, line := range strings.Split(out, "\n") {
		f := strings.Split(line, "\t")
		if len(f) < 4 {
			continue
		}
		n, err1 := strconv.ParseInt(f[2], 10, 64)
		ts, err2 := strconv.ParseInt(f[3], 10, 64)
		if err1 != nil || err2 != nil {
			continue
		}
		it := CleanItem{Cat: f[0], ID: f[1], Bytes: n, Time: time.Unix(ts, 0)}
		if len(f) > 4 {
			it.Label = f[4]
		}
		items = append(items, it)
	}
	return items
}

// Clean lists the leftovers by category (uploadDir is the panel's own).
func (s *Service) Clean(ctx context.Context, uploadDir string) ([]CleanCategory, error) {
	var items []CleanItem
	var err error
	if s.DryRun {
		s.mu.Lock()
		for _, it := range dryClean() {
			if !s.fakeCleaned[it.Cat+"\x00"+it.ID] {
				items = append(items, it)
			}
		}
		s.mu.Unlock()
	} else {
		cmd := exec.Helper(s.ScriptsDir, "hp-system.sh", "clean-list")
		cmd.Timeout = 5 * time.Minute
		var res exec.Result
		res, err = s.Runner.Run(ctx, cmd)
		items = ParseCleanList(res.Stdout)
	}
	items = append(items, uploadItems(uploadDir, time.Now())...)
	cats := make([]CleanCategory, len(cleanCats))
	copy(cats, cleanCats)
	for i := range cats {
		for _, it := range items {
			if it.Cat == cats[i].ID {
				cats[i].Items = append(cats[i].Items, it)
				cats[i].Bytes += it.Bytes
			}
		}
		sort.Slice(cats[i].Items, func(a, b int) bool { return cats[i].Items[a].Time.Before(cats[i].Items[b].Time) })
	}
	return cats, err
}

func uploadItems(dir string, now time.Time) []CleanItem {
	ents, _ := os.ReadDir(dir)
	var out []CleanItem
	for _, e := range ents {
		if !e.Type().IsRegular() || !uploadNameRe.MatchString(e.Name()) {
			continue
		}
		fi, err := e.Info()
		if err != nil || now.Sub(fi.ModTime()) < UploadMaxAge {
			continue
		}
		out = append(out, CleanItem{Cat: "uploads", ID: e.Name(), Bytes: fi.Size(), Time: fi.ModTime()})
	}
	return out
}

var cleanIDRe = regexp.MustCompile(`^[A-Za-z0-9@._:/-]{1,200}$`)

// CleanDelete removes one listed item. The helper validates again; uploads
// are removed by the panel (its own directory).
func (s *Service) CleanDelete(ctx context.Context, uploadDir, cat, id string) error {
	if !cleanIDRe.MatchString(id) || strings.Contains(id, "..") {
		return errors.New("geçersiz öğe")
	}
	switch cat {
	case "mail":
		return errors.New("posta arşivleri panelden silinmez")
	case "uploads":
		for _, it := range uploadItems(uploadDir, time.Now()) {
			if it.ID == id {
				return os.Remove(filepath.Join(uploadDir, id))
			}
		}
		return errors.New("dosya bulunamadı ya da 1 günden yeni (yükleme sürüyor olabilir)")
	}
	known := false
	for _, c := range cleanCats {
		known = known || (c.ID == cat && c.Deletable)
	}
	if !known {
		return errors.New("bilinmeyen kategori")
	}
	if s.DryRun {
		s.mu.Lock()
		if s.fakeCleaned == nil {
			s.fakeCleaned = map[string]bool{}
		}
		s.fakeCleaned[cat+"\x00"+id] = true
		s.mu.Unlock()
	}
	cmd := exec.Helper(s.ScriptsDir, "hp-system.sh", "clean-delete", cat, id)
	cmd.Timeout = 10 * time.Minute
	_, err := s.Runner.Run(ctx, cmd)
	return err
}

func dryClean() []CleanItem {
	now := time.Now()
	return []CleanItem{
		{Cat: "predelete", ID: "eski-site.com/pre-delete-20261001-101500.tar.zst", Bytes: 412 << 20, Time: now.AddDate(0, -1, -11)},
		{Cat: "predrop-mssql", ID: "pre-drop-shop_test-20261020-091200.bak", Bytes: 96 << 20, Time: now.AddDate(0, 0, -22)},
		{Cat: "mssql-update", ID: "pre-update", Bytes: 1800 << 20, Time: now.AddDate(0, 0, -3)},
		{Cat: "docker-image", ID: "sha256:" + strings.Repeat("ab", 32), Label: "mcr.microsoft.com/mssql/server:2025-CU9-ubuntu-24.04", Bytes: 1610 << 20, Time: now.AddDate(0, -2, 0)},
		{Cat: "apt", ID: "apt", Bytes: 230 << 20, Time: now.AddDate(0, 0, -1)},
		{Cat: "journal", ID: "journal", Bytes: 780 << 20, Time: now},
		{Cat: "mail", ID: "pre-delete-eski@ornek.com-20261012-120000.tar.zst", Bytes: 35 << 20, Time: now.AddDate(0, 0, -30)},
	}
}

package databases

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/zahit5834/hostpanel/internal/images"
	"github.com/zahit5834/hostpanel/internal/jobs"
)

// updateReady is how long a new cumulative update may take to come up (it
// upgrades master/msdb on the first start).
const updateReady = 15 * time.Minute

// StartImageUpdate queues an update of the SQL Server container to image,
// which must be a newer CU/GDR of the running line.
func (s *Service) StartImageUpdate(ctx context.Context, image string) (int64, error) {
	srv, err := s.Store.Server(ctx)
	if err != nil {
		return 0, ErrNoServer
	}
	if srv.Status != StatusRunning && srv.Status != StatusStopped {
		return 0, errors.New("sunucu çalışır ya da durdurulmuş durumda olmalı")
	}
	if !imageRe.MatchString(image) || !images.IsUpdate(images.MSSQL, srv.Image, image) {
		return 0, fmt.Errorf("%s, çalışan imajın (%s) güncellemesi değil", image, srv.Image)
	}
	return s.Jobs.Submit(ctx, jobs.Spec{Kind: "db.server.update", TargetType: "db_server", TargetID: "mssql",
		Summary: "MSSQL güncelleniyor: " + images.Tag(image), Params: map[string]any{"server_id": srv.ID, "image": image}})
}

// jobImageUpdate: pull the new image while the old one keeps running, stop
// and copy the data directory (pre-update snapshot), recreate on the new
// image. If the new version does not come up, the snapshot and the old
// image are put back (a cumulative update cannot be undone on the same data).
func (s *Service) jobImageUpdate(ctx context.Context, l *jobs.Log, p map[string]any) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	srv, err := s.Store.Server(ctx)
	if err != nil || srv.ID != paramID(p, "server_id") {
		return errors.New("sunucu kaydı bulunamadı")
	}
	image, _ := p["image"].(string)
	old, wasStopped := srv.Image, srv.Status == StatusStopped
	if !imageRe.MatchString(image) || !images.IsUpdate(images.MSSQL, old, image) {
		return fmt.Errorf("%s, çalışan imajın (%s) güncellemesi değil", image, old)
	}
	saPW, err := s.Box.OpenString(srv.SASealed)
	if err != nil {
		return err
	}
	l.Printf("Güncelleme: %s → %s", images.Tag(old), images.Tag(image))
	l.Printf("Yeni imaj indiriliyor (SQL Server çalışmaya devam ediyor)…")
	if _, err := s.helper(ctx, l, nil, nil, 45*time.Minute, "pull", image); err != nil {
		return fmt.Errorf("imaj indirilemedi, sunucuya dokunulmadı: %w", err)
	}
	l.Progress(30)
	l.Printf("SQL Server durduruluyor ve veri dizininin kopyası alınıyor (geri dönüş için; yedek dizini hariç)…")
	if _, err := s.helper(ctx, l, nil, nil, 3*time.Hour, "snapshot"); err != nil {
		if !wasStopped {
			s.helper(context.WithoutCancel(ctx), l, nil, nil, 2*time.Minute, "start")
		}
		return fmt.Errorf("güncelleme öncesi kopya alınamadı, güncelleme yapılmadı: %w", err)
	}
	l.Progress(50)
	bg := context.WithoutCancel(ctx) // from here on the server must end up running on some image
	if _, err := s.helper(bg, l, nil, nil, 2*time.Minute, "remove-container"); err != nil {
		return s.failServer(ctx, srv.ID, err)
	}
	s.Store.SetImage(bg, srv.ID, image)
	srv.Image = image
	err = s.createContainer(bg, l, srv, saPW)
	if err == nil {
		l.Printf("Sistem veritabanları yükseltiliyor olabilir; ilk açılış birkaç dakika sürebilir.")
		err = s.waitReadyFor(bg, l, updateReady)
	}
	if err != nil {
		l.Printf("Yeni sürüm açılmadı (%v); eski sürüme ve güncelleme öncesi veriye dönülüyor…", err)
		return s.rollbackImage(bg, l, srv, old, saPW, wasStopped, err)
	}
	l.Progress(85)
	if err := s.rotateSA(bg, l, srv); err != nil {
		l.Printf("UYARI: sa şifresi yenilenemedi: %v", err)
	}
	if err := s.configure(bg, l, srv); err != nil {
		l.Printf("UYARI: %v", err)
	}
	status := StatusRunning
	if wasStopped {
		s.helper(bg, l, nil, nil, 2*time.Minute, "stop")
		status = StatusStopped
	}
	s.Store.SetServerStatus(bg, srv.ID, status, "")
	l.Progress(100)
	l.Printf("MSSQL güncellendi: %s. Güncelleme öncesi kopya bir sonraki güncellemeye kadar /var/backups/hostpanel/_mssql/pre-update altında durur.", images.Tag(image))
	return nil
}

func (s *Service) rollbackImage(ctx context.Context, l *jobs.Log, srv Server, old, saPW string, wasStopped bool, cause error) error {
	s.helper(ctx, l, nil, nil, 2*time.Minute, "remove-container")
	if _, err := s.helper(ctx, l, nil, nil, 3*time.Hour, "snapshot-restore"); err != nil {
		return s.failServer(ctx, srv.ID, fmt.Errorf("güncelleme başarısız (%v) ve veri geri konamadı: %w", cause, err))
	}
	s.Store.SetImage(ctx, srv.ID, old)
	srv.Image = old
	if err := s.createContainer(ctx, l, srv, saPW); err != nil {
		return s.failServer(ctx, srv.ID, fmt.Errorf("güncelleme başarısız (%v), eski sürüm de başlatılamadı: %w", cause, err))
	}
	if err := s.waitReady(ctx, l); err != nil {
		return s.failServer(ctx, srv.ID, fmt.Errorf("güncelleme başarısız (%v), eski sürüm de açılmadı: %w", cause, err))
	}
	if err := s.rotateSA(ctx, l, srv); err != nil {
		l.Printf("UYARI: sa şifresi yenilenemedi: %v", err)
	}
	status := StatusRunning
	if wasStopped {
		s.helper(ctx, l, nil, nil, 2*time.Minute, "stop")
		status = StatusStopped
	}
	s.Store.SetServerStatus(ctx, srv.ID, status, "")
	l.Printf("Eski sürüme dönüldü: %s (başarısız verinin kopyası /var/backups/hostpanel/_mssql/ altında).", old)
	return fmt.Errorf("güncelleme başarısız, eski sürüme dönüldü: %w", cause)
}

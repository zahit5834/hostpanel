package mail

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/zahit5834/hostpanel/internal/images"
	"github.com/zahit5834/hostpanel/internal/jobs"
)

// StartImageUpdate queues an update of the mail container to image, which
// must be a newer release of the running major version.
func (s *Service) StartImageUpdate(ctx context.Context, image string) (int64, error) {
	srv, err := s.server(ctx)
	if err != nil {
		return 0, err
	}
	if srv.Status != StatusRunning && srv.Status != StatusStopped {
		return 0, errors.New("posta sunucusu çalışır ya da durdurulmuş durumda olmalı")
	}
	if !ValidImage(image) || !images.IsUpdate(images.Mail, srv.Image, image) {
		return 0, fmt.Errorf("%s, çalışan imajın (%s) güncellemesi değil", image, srv.Image)
	}
	return s.Jobs.Submit(ctx, jobs.Spec{Kind: "mail.update", TargetType: "mail", TargetID: srv.Hostname,
		Summary: "Posta sunucusu güncelleniyor: " + images.Tag(image), Params: map[string]any{"server_id": srv.ID, "image": image}})
}

// jobImageUpdate pulls the new image while the old container keeps
// serving, then recreates the container on the same directories. Mail,
// accounts and keys are plain files whose format does not change within a
// major version, so a failed start is undone by going back to the old image.
func (s *Service) jobImageUpdate(ctx context.Context, l *jobs.Log, p map[string]any) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	srv, err := s.Store.Server(ctx)
	if err != nil || srv.ID != paramID(p, "server_id") {
		return errors.New("sunucu kaydı bulunamadı")
	}
	image, _ := p["image"].(string)
	old, wasStopped := srv.Image, srv.Status == StatusStopped
	if !ValidImage(image) || !images.IsUpdate(images.Mail, old, image) {
		return fmt.Errorf("%s, çalışan imajın (%s) güncellemesi değil", image, old)
	}
	l.Printf("Güncelleme: %s → %s", images.Tag(old), images.Tag(image))
	l.Printf("Yeni imaj indiriliyor (posta sunucusu çalışmaya devam ediyor)…")
	if _, err := s.helper(ctx, l, nil, nil, 30*time.Minute, "pull", image); err != nil {
		return fmt.Errorf("imaj indirilemedi, sunucuya dokunulmadı: %w", err)
	}
	l.Progress(40)
	bg := context.WithoutCancel(ctx)
	l.Printf("Container yeniden oluşturuluyor (postalar, hesaplar ve anahtarlar %s altında korunur)…", DataDir)
	if _, err := s.helper(bg, l, nil, nil, 3*time.Minute, "remove"); err != nil {
		return s.failServer(ctx, srv.ID, err)
	}
	s.Store.SetImage(bg, srv.ID, image)
	srv.Image = image
	if err := s.createContainer(bg, l, srv); err != nil {
		l.Printf("Yeni sürüm açılmadı (%v); eski sürüme dönülüyor…", err)
		s.helper(bg, l, nil, nil, 3*time.Minute, "remove")
		s.Store.SetImage(bg, srv.ID, old)
		srv.Image = old
		if err2 := s.createContainer(bg, l, srv); err2 != nil {
			return s.failServer(ctx, srv.ID, fmt.Errorf("güncelleme başarısız (%v), eski sürüm de başlatılamadı: %w", err, err2))
		}
		s.finishUpdate(bg, l, srv, wasStopped)
		return fmt.Errorf("güncelleme başarısız, eski sürüme dönüldü (%s): %w", images.Tag(old), err)
	}
	s.finishUpdate(bg, l, srv, wasStopped)
	l.Progress(100)
	l.Printf("Posta sunucusu güncellendi: %s", images.Tag(image))
	return nil
}

func (s *Service) finishUpdate(ctx context.Context, l *jobs.Log, srv Server, wasStopped bool) {
	status := StatusRunning
	if wasStopped {
		s.helper(ctx, l, nil, nil, 3*time.Minute, "stop")
		status = StatusStopped
	}
	s.Store.SetServerStatus(ctx, srv.ID, status, "")
}

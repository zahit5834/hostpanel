package backups

import (
	"context"
	"errors"
	"fmt"
	"io"
	"time"

	"github.com/zahit5834/hostpanel/internal/jobs"
)

// Mail server backups (Faz 9): one backup = the whole mail server
// (configuration + every maildir), stored like a site backup under the
// pseudo domain MailDomain so plans, retention and Drive work unchanged.
const (
	MailDomain = "_mail"
	CompMail   = "mail"
	ScopeMail  = "mail"
)

// MailBackend is implemented by mail.Service.
type MailBackend interface {
	Installed(ctx context.Context) bool
	Backup(ctx context.Context, w io.Writer, name string) (int64, error)
	Restore(ctx context.Context, w io.Writer, name string) error
}

// IsMail reports whether b is a mail server backup.
func (b Backup) IsMail() bool { return b.Domain == MailDomain }

func (s *Service) mailReady(ctx context.Context) error {
	if s.Mail == nil || !s.Mail.Installed(ctx) {
		return errors.New("posta sunucusu kurulu değil")
	}
	return nil
}

// StartMailBackup queues a manual mail server backup.
func (s *Service) StartMailBackup(ctx context.Context, upload bool) (int64, error) {
	if err := s.mailReady(ctx); err != nil {
		return 0, err
	}
	if upload && !s.Remote(ctx).Configured() {
		return 0, errors.New("uzak hedef (Google Drive) yapılandırılmamış")
	}
	summary := "Yedek: posta sunucusu"
	if upload {
		summary += " → Drive"
	}
	return s.Jobs.Submit(ctx, jobs.Spec{Kind: "backup.mail", TargetType: "mail", TargetID: MailDomain, Summary: summary,
		Params: map[string]any{"upload": upload}})
}

func (s *Service) jobMailBackup(ctx context.Context, l *jobs.Log, p map[string]any) error {
	b, err := s.runMailBackup(ctx, l, KindManual, 0)
	if err != nil {
		return err
	}
	if up, _ := p["upload"].(bool); up {
		l.Progress(70)
		return s.upload(ctx, l, &b)
	}
	return nil
}

func (s *Service) runMailBackup(ctx context.Context, l *jobs.Log, kind string, planID int64) (Backup, error) {
	if err := s.mailReady(ctx); err != nil {
		return Backup{}, err
	}
	b := Backup{PlanID: planID, Domain: MailDomain, Name: s.newName(), Kind: kind,
		Components: []string{CompMail}, Status: StatusRunning, CreatedAt: s.now()}
	if err := s.Store.Insert(ctx, &b); err != nil {
		return b, err
	}
	s.Store.SetJob(ctx, b.ID, l.ID())
	l.Printf("Posta sunucusu yedeği başlıyor: %s (container çalışmaya devam eder)", b.Name)
	size, err := s.Mail.Backup(ctx, l, b.Name)
	if err != nil {
		rctx := context.WithoutCancel(ctx)
		s.helper(rctx, l, nil, nil, time.Minute, "delete", MailDomain, b.Name)
		s.Store.Finish(rctx, b.ID, StatusFailed, 0, false, err.Error())
		return b, fmt.Errorf("posta sunucusu yedeği başarısız: %w", err)
	}
	b.Status, b.SizeBytes, b.Local = StatusSuccess, size, true
	s.Store.Finish(ctx, b.ID, StatusSuccess, size, true, "")
	l.Printf("Yedek tamam: posta sunucusu/%s (%s)", b.Name, HumanSize(size))
	return b, nil
}

// StartMailRestore queues restoring a mail server backup (replaces every
// mailbox, alias and DKIM key with the backup's).
func (s *Service) StartMailRestore(ctx context.Context, id int64) (int64, error) {
	b, err := s.Store.Backup(ctx, id)
	if err != nil || !b.IsMail() {
		return 0, errors.New("yedek bulunamadı")
	}
	if b.Status != StatusSuccess || (!b.Local && !b.Remote) {
		return 0, errors.New("bu yedek geri yüklenemez")
	}
	if !b.Local && !s.Remote(ctx).Configured() {
		return 0, errors.New("yedek yalnızca Drive'da; önce uzak hedefi yapılandırın")
	}
	if err := s.mailReady(ctx); err != nil {
		return 0, err
	}
	return s.Jobs.Submit(ctx, jobs.Spec{Kind: "backup.mail.restore", TargetType: "mail", TargetID: MailDomain,
		Summary: "Geri yükleme: posta sunucusu/" + b.Name, Params: map[string]any{"backup_id": b.ID}})
}

func (s *Service) jobMailRestore(ctx context.Context, l *jobs.Log, p map[string]any) error {
	b, err := s.Store.Backup(ctx, paramID(p, "backup_id"))
	if err != nil || !b.IsMail() {
		return errors.New("yedek bulunamadı")
	}
	if !b.Local {
		srv := b.RemoteSrv
		if srv == "" {
			srv = s.serverName(ctx)
		}
		l.Printf("Drive'dan indiriliyor: %s/%s/%s", srv, b.Domain, b.Name)
		if _, err := s.helper(ctx, l, nil, nil, 0, "download", srv, b.Domain, b.Name); err != nil {
			return err
		}
		s.Store.SetLocation(ctx, b.ID, true, b.Remote)
	}
	l.Progress(20)
	l.Printf("Posta sunucusu durduruluyor, yapılandırma ve postalar yedektekiyle değiştiriliyor…")
	if err := s.Mail.Restore(ctx, l, b.Name); err != nil {
		return err
	}
	l.Progress(100)
	l.Printf("Geri yükleme tamam. Yedekten sonra gelen postalar önceki veride durur (bkz. job logu).")
	return nil
}

package backups

import (
	"context"
	"io"
	"testing"

	"github.com/zahit5834/hostpanel/internal/jobs"
)

type fakeMail struct {
	installed bool
	backups   []string
	restored  []string
}

func (f *fakeMail) Installed(context.Context) bool { return f.installed }
func (f *fakeMail) Backup(_ context.Context, w io.Writer, name string) (int64, error) {
	f.backups = append(f.backups, name)
	return 4096, nil
}
func (f *fakeMail) Restore(_ context.Context, w io.Writer, name string) error {
	f.restored = append(f.restored, name)
	return nil
}

func TestMailBackups(t *testing.T) {
	ctx := context.Background()
	s, _ := testService(t)
	p := Plan{Name: "posta", Scope: ScopeMail, Components: []string{CompFiles}, Schedule: "0 4 * * *", Destination: DestLocal, KeepLocal: 2}
	if err := s.ValidatePlan(ctx, &p); err == nil {
		t.Fatal("mail plan without a mail server")
	}
	fm := &fakeMail{}
	s.Mail = fm
	if _, err := s.StartMailBackup(ctx, false); err == nil {
		t.Fatal("backup of a missing mail server")
	}
	fm.installed = true
	if err := s.ValidatePlan(ctx, &p); err != nil || len(p.Components) != 1 || p.Components[0] != CompMail || p.SiteIDs != nil {
		t.Fatalf("%+v %v", p, err)
	}
	id, err := s.StartMailBackup(ctx, false)
	if err != nil {
		t.Fatal(err)
	}
	var list []Backup
	waitFor(t, func() bool {
		j, _ := s.Jobs.Get(ctx, id)
		list, _ = s.Store.Backups(ctx, Filter{Domain: MailDomain})
		return j.Status == jobs.StatusSuccess && len(list) == 1
	})
	b := list[0]
	if !b.IsMail() || !b.Local || b.SizeBytes != 4096 || len(fm.backups) != 1 || fm.backups[0] != b.Name || !b.Has(CompMail) {
		t.Fatalf("%+v %v", b, fm.backups)
	}
	if _, err := s.StartRestore(ctx, RestoreInput{BackupID: b.ID, TargetID: 1, Components: []string{CompFiles}}); err == nil {
		t.Fatal("mail backup restored into a site")
	}
	rid, err := s.StartMailRestore(ctx, b.ID)
	if err != nil {
		t.Fatal(err)
	}
	waitFor(t, func() bool { j, _ := s.Jobs.Get(ctx, rid); return j.Status == jobs.StatusSuccess })
	if len(fm.restored) != 1 || fm.restored[0] != b.Name {
		t.Fatal(fm.restored)
	}
}

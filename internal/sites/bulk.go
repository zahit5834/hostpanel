package sites

import (
	"context"
	"errors"
	"fmt"
	"slices"

	"github.com/zahit5834/hostpanel/internal/jobs"
	"github.com/zahit5834/hostpanel/internal/logs"
)

// --- K2: bulk operations (one job per site, failures don't stop the others) ---

// BulkOps are the operations offered on the site list.
var BulkOps = []string{OpRestart, OpMaintenanceOn, OpMaintenanceOff, OpReapplyNginx}

// BulkOpLabel is the Turkish label of a bulk operation.
func BulkOpLabel(op string) string {
	switch op {
	case OpRestart:
		return "yeniden başlat"
	case OpMaintenanceOn:
		return "bakım modunu aç"
	case OpMaintenanceOff:
		return "bakım modunu kapat"
	case OpReapplyNginx:
		return "nginx yapılandırmasını yeniden uygula"
	}
	return op
}

// SubmitOp queues one site operation as a job (bulk actions).
func (s *Service) SubmitOp(ctx context.Context, site Site, op string) (int64, error) {
	if !slices.Contains(BulkOps, op) {
		return 0, errors.New("geçersiz işlem")
	}
	return s.Jobs.Submit(ctx, jobs.Spec{Kind: "site.op", TargetType: "site", TargetID: site.Domain,
		Summary: site.Domain + ": " + BulkOpLabel(op), Retryable: true,
		Params: map[string]any{"site_id": site.ID, "op": op}})
}

func (s *Service) jobOp(ctx context.Context, l *jobs.Log, p map[string]any) error {
	var id int64
	switch v := p["site_id"].(type) {
	case float64:
		id = int64(v)
	case int64:
		id = v
	}
	op, _ := p["op"].(string)
	if !slices.Contains(BulkOps, op) {
		return errors.New("geçersiz işlem")
	}
	site, err := s.Store.Get(ctx, id)
	if err != nil {
		return errors.New("site bulunamadı")
	}
	l.Printf("%s: %s", site.Domain, BulkOpLabel(op))
	act := s.Activity.Begin(ctx, logs.Entry{Action: "site." + op, TargetType: "site", TargetID: site.Domain,
		Summary: site.Domain + " " + BulkOpLabel(op) + " (toplu)"}, map[string]any{"job_id": l.ID()})
	status, err := s.Operate(ctx, site, op)
	act.Finish(err)
	if err != nil {
		return fmt.Errorf("%s: %w", site.Domain, err)
	}
	if op == OpRestart {
		if prov, perr := s.provider(site); perr == nil && prov.Def().HasUnit() {
			site.Status = status
			if err := s.healthCheck(ctx, l, site, prov.Def()); err != nil {
				return err
			}
		}
	}
	l.Printf("Tamam (durum: %s)", status)
	l.Progress(100)
	return nil
}

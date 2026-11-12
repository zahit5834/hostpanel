package mail

import (
	"context"
	"sort"
	"time"
)

// ReportFileSeen reports whether a copied report mail was parsed already.
func (st *Store) ReportFileSeen(ctx context.Context, name string) (bool, error) {
	var n int
	err := st.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM dmarc_files WHERE name=?`, name).Scan(&n)
	return n > 0, err
}

// MarkReportFile records the outcome for a copied report mail.
func (st *Store) MarkReportFile(ctx context.Context, name string, at time.Time, status, detail string) error {
	_, err := st.db.ExecContext(ctx, `INSERT OR REPLACE INTO dmarc_files(name, seen_at, status, detail) VALUES (?,?,?,?)`,
		name, at.Unix(), status, detail)
	return err
}

// InsertReport stores one aggregate report; false if (org, report id) is
// known already (the same report delivered twice).
func (st *Store) InsertReport(ctx context.Context, f Feedback) (bool, error) {
	tx, err := st.db.BeginTx(ctx, nil)
	if err != nil {
		return false, err
	}
	defer tx.Rollback()
	res, err := tx.ExecContext(ctx, `INSERT OR IGNORE INTO dmarc_reports(org, report_id, domain, begin_at, end_at, policy, created_at)
		VALUES (?,?,?,?,?,?,?)`, f.Org, f.ReportID, f.Domain, f.Begin, f.End, f.Policy, time.Now().Unix())
	if err != nil {
		return false, err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return false, nil
	}
	id, _ := res.LastInsertId()
	for _, r := range f.Records {
		if _, err := tx.ExecContext(ctx, `INSERT INTO dmarc_records(report, source_ip, count, disposition, dkim, spf, header_from)
			VALUES (?,?,?,?,?,?,?)`, id, r.SourceIP, r.Count, r.Disposition, r.DKIM, r.SPF, r.HeaderFrom); err != nil {
			return false, err
		}
	}
	return true, tx.Commit()
}

// PurgeReports drops reports that ended before t and file marks older than
// the reports (a mail removed from the mailbox is gone from the copy dir too).
func (st *Store) PurgeReports(ctx context.Context, t time.Time) error {
	if _, err := st.db.ExecContext(ctx, `DELETE FROM dmarc_reports WHERE end_at < ?`, t.Unix()); err != nil {
		return err
	}
	_, err := st.db.ExecContext(ctx, `DELETE FROM dmarc_files WHERE seen_at < ?`, t.Add(-30*24*time.Hour).Unix())
	return err
}

// ReportFileErrors returns the latest parse failures (newest first).
func (st *Store) ReportFileErrors(ctx context.Context, n int) ([][2]string, error) {
	rows, err := st.db.QueryContext(ctx, `SELECT name, detail FROM dmarc_files WHERE status='error' ORDER BY seen_at DESC LIMIT ?`, n)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out [][2]string
	for rows.Next() {
		var a, b string
		if err := rows.Scan(&a, &b); err != nil {
			return nil, err
		}
		out = append(out, [2]string{a, b})
	}
	return out, rows.Err()
}

// ReportSummaries aggregates the reports that ended after since, per domain.
func (st *Store) ReportSummaries(ctx context.Context, since time.Time) ([]DMARCSummary, error) {
	rows, err := st.db.QueryContext(ctx, `SELECT r.domain, r.org, x.source_ip,
		SUM(x.count),
		SUM(CASE WHEN x.dkim='pass' OR x.spf='pass' THEN x.count ELSE 0 END),
		SUM(CASE WHEN x.dkim='pass' THEN x.count ELSE 0 END),
		SUM(CASE WHEN x.spf='pass' THEN x.count ELSE 0 END),
		COUNT(DISTINCT r.id)
		FROM dmarc_reports r JOIN dmarc_records x ON x.report = r.id
		WHERE r.end_at >= ? GROUP BY r.domain, r.org, x.source_ip`, since.Unix())
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	by := map[string]*DMARCSummary{}
	src := map[string]map[string]*DMARCSource{}
	orgs := map[string]map[string]bool{}
	for rows.Next() {
		var dom, org, ip string
		var c, p, dk, sp int64
		var reps int
		if err := rows.Scan(&dom, &org, &ip, &c, &p, &dk, &sp, &reps); err != nil {
			return nil, err
		}
		d := by[dom]
		if d == nil {
			d = &DMARCSummary{Domain: dom}
			by[dom], src[dom], orgs[dom] = d, map[string]*DMARCSource{}, map[string]bool{}
		}
		d.Total, d.Pass, d.DKIM, d.SPF = d.Total+c, d.Pass+p, d.DKIM+dk, d.SPF+sp
		orgs[dom][org] = true
		x := src[dom][ip]
		if x == nil {
			x = &DMARCSource{IP: ip}
			src[dom][ip] = x
		}
		x.Count, x.Pass, x.DKIMPass, x.SPFPass = x.Count+c, x.Pass+p, x.DKIMPass+dk, x.SPFPass+sp
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	var counts = map[string]int{}
	crow, err := st.db.QueryContext(ctx, `SELECT domain, COUNT(*) FROM dmarc_reports WHERE end_at >= ? GROUP BY domain`, since.Unix())
	if err == nil {
		for crow.Next() {
			var d string
			var n int
			if crow.Scan(&d, &n) == nil {
				counts[d] = n
			}
		}
		crow.Close()
	}
	out := make([]DMARCSummary, 0, len(by))
	for dom, d := range by {
		d.Reports = counts[dom]
		for _, x := range src[dom] {
			d.Sources = append(d.Sources, *x)
		}
		sort.Slice(d.Sources, func(i, j int) bool {
			if d.Sources[i].Count != d.Sources[j].Count {
				return d.Sources[i].Count > d.Sources[j].Count
			}
			return d.Sources[i].IP < d.Sources[j].IP
		})
		if len(d.Sources) > 20 {
			d.Sources = d.Sources[:20]
		}
		for o := range orgs[dom] {
			d.Orgs = append(d.Orgs, o)
		}
		sort.Strings(d.Orgs)
		out = append(out, *d)
	}
	return out, nil
}

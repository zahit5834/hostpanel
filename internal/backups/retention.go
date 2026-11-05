package backups

import (
	"sort"
	"time"
)

// Prune decides which copies of one plan's backups of one site to delete.
// Only successful backups are passed in. Rules:
//   - local: keep the newest keepLocal local copies (0 = keep none, used for
//     remote-only plans once the upload succeeded);
//   - remote: keep the newest keepRemote copies (0 = no count limit) and drop
//     copies older than keepRemoteDays (0 = no age limit);
//   - the newest remote copy is never deleted, so a plan whose uploads start
//     failing doesn't age its last good backup away.
func Prune(items []Backup, keepLocal, keepRemote, keepRemoteDays int, now time.Time) (local, remote []int64) {
	sorted := append([]Backup(nil), items...)
	sort.SliceStable(sorted, func(i, j int) bool {
		if !sorted[i].CreatedAt.Equal(sorted[j].CreatedAt) {
			return sorted[i].CreatedAt.After(sorted[j].CreatedAt)
		}
		return sorted[i].ID > sorted[j].ID
	})
	nl, nr := 0, 0
	cutoff := now.AddDate(0, 0, -keepRemoteDays)
	for _, b := range sorted {
		if b.Local {
			if nl++; nl > keepLocal {
				local = append(local, b.ID)
			}
		}
		if b.Remote {
			nr++
			if nr == 1 {
				continue
			}
			if (keepRemote > 0 && nr > keepRemote) || (keepRemoteDays > 0 && b.CreatedAt.Before(cutoff)) {
				remote = append(remote, b.ID)
			}
		}
	}
	return local, remote
}

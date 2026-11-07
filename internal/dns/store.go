package dns

import (
	"context"
	"database/sql"
	"time"
)

// Store accesses dns_zones and dns_records.
type Store struct{ db *sql.DB }

// NewStore wraps db.
func NewStore(db *sql.DB) *Store { return &Store{db: db} }

const zoneCols = `z.id, z.name, COALESCE(z.customer_id, 0), COALESCE(c.name, ''), z.serial, z.default_ttl,
	z.soa_refresh, z.soa_retry, z.soa_expire, z.soa_minimum, z.dnssec, z.auto_sites, z.created_at, z.updated_at,
	(SELECT COUNT(*) FROM dns_records r WHERE r.zone_id = z.id)`

func scanZone(sc interface{ Scan(...any) error }) (Zone, error) {
	var z Zone
	var created, updated int64
	err := sc.Scan(&z.ID, &z.Name, &z.CustomerID, &z.CustomerName, &z.Serial, &z.DefaultTTL, &z.Refresh, &z.Retry,
		&z.Expire, &z.Minimum, &z.DNSSEC, &z.AutoSites, &created, &updated, &z.RecordCount)
	z.CreatedAt, z.UpdatedAt = time.Unix(created, 0), time.Unix(updated, 0)
	return z, err
}

// Zones lists zones (customerID 0 = all) ordered by name.
func (st *Store) Zones(ctx context.Context, customerID int64) ([]Zone, error) {
	q := `SELECT ` + zoneCols + ` FROM dns_zones z LEFT JOIN customers c ON c.id = z.customer_id`
	var args []any
	if customerID > 0 {
		q += ` WHERE z.customer_id = ?`
		args = append(args, customerID)
	}
	rows, err := st.db.QueryContext(ctx, q+` ORDER BY z.name`, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Zone
	for rows.Next() {
		z, err := scanZone(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, z)
	}
	return out, rows.Err()
}

// ZoneNames returns every zone name.
func (st *Store) ZoneNames(ctx context.Context) ([]string, error) {
	rows, err := st.db.QueryContext(ctx, `SELECT name FROM dns_zones ORDER BY name`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var n string
		if err := rows.Scan(&n); err != nil {
			return nil, err
		}
		out = append(out, n)
	}
	return out, rows.Err()
}

// Zone loads one zone.
func (st *Store) Zone(ctx context.Context, id int64) (Zone, error) {
	return scanZone(st.db.QueryRowContext(ctx, `SELECT `+zoneCols+` FROM dns_zones z LEFT JOIN customers c ON c.id = z.customer_id WHERE z.id = ?`, id))
}

// ZoneByName loads one zone by name.
func (st *Store) ZoneByName(ctx context.Context, name string) (Zone, error) {
	return scanZone(st.db.QueryRowContext(ctx, `SELECT `+zoneCols+` FROM dns_zones z LEFT JOIN customers c ON c.id = z.customer_id WHERE z.name = ?`, name))
}

func nullID(id int64) any {
	if id <= 0 {
		return nil
	}
	return id
}

// InsertZone stores z and sets its ID.
func (st *Store) InsertZone(ctx context.Context, z *Zone) error {
	now := time.Now().Unix()
	res, err := st.db.ExecContext(ctx, `INSERT INTO dns_zones(name, customer_id, default_ttl, soa_refresh, soa_retry, soa_expire,
		soa_minimum, dnssec, auto_sites, created_at, updated_at) VALUES (?,?,?,?,?,?,?,?,?,?,?)`,
		z.Name, nullID(z.CustomerID), z.DefaultTTL, z.Refresh, z.Retry, z.Expire, z.Minimum, z.DNSSEC, z.AutoSites, now, now)
	if err != nil {
		return err
	}
	z.ID, _ = res.LastInsertId()
	return nil
}

// UpdateZone saves the editable zone settings.
func (st *Store) UpdateZone(ctx context.Context, z Zone) error {
	_, err := st.db.ExecContext(ctx, `UPDATE dns_zones SET customer_id=?, default_ttl=?, dnssec=?, auto_sites=?, updated_at=? WHERE id=?`,
		nullID(z.CustomerID), z.DefaultTTL, z.DNSSEC, z.AutoSites, time.Now().Unix(), z.ID)
	return err
}

// SetSerial stores the serial used for the last rendered file.
func (st *Store) SetSerial(ctx context.Context, id, serial int64) error {
	_, err := st.db.ExecContext(ctx, `UPDATE dns_zones SET serial=? WHERE id=?`, serial, id)
	return err
}

// DeleteZone removes a zone and its records.
func (st *Store) DeleteZone(ctx context.Context, id int64) error {
	_, err := st.db.ExecContext(ctx, `DELETE FROM dns_zones WHERE id=?`, id)
	return err
}

const recordCols = `id, zone_id, name, type, ttl, prio, weight, port, tag, value`

func scanRecord(sc interface{ Scan(...any) error }) (Record, error) {
	var r Record
	err := sc.Scan(&r.ID, &r.ZoneID, &r.Name, &r.Type, &r.TTL, &r.Prio, &r.Weight, &r.Port, &r.Tag, &r.Value)
	return r, err
}

// Records lists a zone's stored records.
func (st *Store) Records(ctx context.Context, zoneID int64) ([]Record, error) {
	rows, err := st.db.QueryContext(ctx, `SELECT `+recordCols+` FROM dns_records WHERE zone_id=? ORDER BY id`, zoneID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Record
	for rows.Next() {
		r, err := scanRecord(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

// Record loads one record of a zone.
func (st *Store) Record(ctx context.Context, zoneID, id int64) (Record, error) {
	return scanRecord(st.db.QueryRowContext(ctx, `SELECT `+recordCols+` FROM dns_records WHERE zone_id=? AND id=?`, zoneID, id))
}

// InsertRecord stores r and sets its ID.
func (st *Store) InsertRecord(ctx context.Context, r *Record) error {
	res, err := st.db.ExecContext(ctx, `INSERT INTO dns_records(zone_id, name, type, ttl, prio, weight, port, tag, value, created_at)
		VALUES (?,?,?,?,?,?,?,?,?,?)`, r.ZoneID, r.Name, r.Type, r.TTL, r.Prio, r.Weight, r.Port, r.Tag, r.Value, time.Now().Unix())
	if err != nil {
		return err
	}
	r.ID, _ = res.LastInsertId()
	return nil
}

// UpdateRecord saves r.
func (st *Store) UpdateRecord(ctx context.Context, r Record) error {
	_, err := st.db.ExecContext(ctx, `UPDATE dns_records SET name=?, type=?, ttl=?, prio=?, weight=?, port=?, tag=?, value=?
		WHERE zone_id=? AND id=?`, r.Name, r.Type, r.TTL, r.Prio, r.Weight, r.Port, r.Tag, r.Value, r.ZoneID, r.ID)
	return err
}

// DeleteRecord removes one record.
func (st *Store) DeleteRecord(ctx context.Context, zoneID, id int64) error {
	_, err := st.db.ExecContext(ctx, `DELETE FROM dns_records WHERE zone_id=? AND id=?`, zoneID, id)
	return err
}

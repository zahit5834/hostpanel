// Package customers stores the admin's customer records.
package customers

import (
	"context"
	"database/sql"
	"errors"
	"net/mail"
	"strings"
	"time"
)

// Customer is one client of the admin.
type Customer struct {
	ID        int64
	Name      string
	Company   string
	Phone     string
	Email     string
	Notes     string
	CreatedAt time.Time
	SiteCount int // filled by List
}

// Store accesses the customers table.
type Store struct{ db *sql.DB }

// New wraps db.
func New(db *sql.DB) *Store { return &Store{db: db} }

// Validate normalizes fields and returns a Turkish user-facing error.
func (c *Customer) Validate() error {
	c.Name = strings.TrimSpace(c.Name)
	c.Company = strings.TrimSpace(c.Company)
	c.Phone = strings.TrimSpace(c.Phone)
	c.Email = strings.TrimSpace(c.Email)
	c.Notes = strings.TrimSpace(c.Notes)
	if c.Name == "" || len(c.Name) > 120 {
		return errors.New("ad zorunlu (en fazla 120 karakter)")
	}
	if c.Email != "" {
		if _, err := mail.ParseAddress(c.Email); err != nil {
			return errors.New("geçersiz e-posta adresi")
		}
	}
	if len(c.Company) > 160 || len(c.Phone) > 40 || len(c.Notes) > 4000 {
		return errors.New("alanlardan biri çok uzun")
	}
	return nil
}

// Create inserts c and sets its ID.
func (s *Store) Create(ctx context.Context, c *Customer) error {
	if err := c.Validate(); err != nil {
		return err
	}
	now := time.Now().Unix()
	res, err := s.db.ExecContext(ctx, `INSERT INTO customers(name, company, phone, email, notes, created_at, updated_at)
		VALUES (?,?,?,?,?,?,?)`, c.Name, c.Company, c.Phone, c.Email, c.Notes, now, now)
	if err != nil {
		return err
	}
	c.ID, _ = res.LastInsertId()
	c.CreatedAt = time.Unix(now, 0)
	return nil
}

// Update saves changes to an existing customer.
func (s *Store) Update(ctx context.Context, c *Customer) error {
	if err := c.Validate(); err != nil {
		return err
	}
	_, err := s.db.ExecContext(ctx, `UPDATE customers SET name=?, company=?, phone=?, email=?, notes=?, updated_at=? WHERE id=?`,
		c.Name, c.Company, c.Phone, c.Email, c.Notes, time.Now().Unix(), c.ID)
	return err
}

// Get loads one customer.
func (s *Store) Get(ctx context.Context, id int64) (Customer, error) {
	var c Customer
	var created int64
	err := s.db.QueryRowContext(ctx, `SELECT id, name, company, phone, email, notes, created_at FROM customers WHERE id=?`, id).
		Scan(&c.ID, &c.Name, &c.Company, &c.Phone, &c.Email, &c.Notes, &created)
	c.CreatedAt = time.Unix(created, 0)
	return c, err
}

// List returns all customers with their site counts, optionally filtered by q.
func (s *Store) List(ctx context.Context, q string) ([]Customer, error) {
	query := `SELECT c.id, c.name, c.company, c.phone, c.email, c.notes, c.created_at,
		(SELECT COUNT(*) FROM sites WHERE customer_id=c.id) FROM customers c`
	query += ` ORDER BY c.name COLLATE NOCASE`
	// Filtering happens in Go: SQLite's LIKE is case-insensitive only for ASCII,
	// which breaks Turkish names (Ö/ö, Ş/ş). A single admin has few customers.
	q = strings.ToLower(strings.TrimSpace(q))
	rows, err := s.db.QueryContext(ctx, query)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Customer
	for rows.Next() {
		var c Customer
		var created int64
		if err := rows.Scan(&c.ID, &c.Name, &c.Company, &c.Phone, &c.Email, &c.Notes, &created, &c.SiteCount); err != nil {
			return nil, err
		}
		c.CreatedAt = time.Unix(created, 0)
		if q != "" && !strings.Contains(strings.ToLower(c.Name+" "+c.Company+" "+c.Email), q) {
			continue
		}
		out = append(out, c)
	}
	return out, rows.Err()
}

// ErrHasSites prevents deleting a customer that still owns sites.
var ErrHasSites = errors.New("müşterinin siteleri var; önce siteleri silin")

// Delete removes a customer without sites.
func (s *Store) Delete(ctx context.Context, id int64) error {
	var n int
	if err := s.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM sites WHERE customer_id=?`, id).Scan(&n); err != nil {
		return err
	}
	if n > 0 {
		return ErrHasSites
	}
	_, err := s.db.ExecContext(ctx, `DELETE FROM customers WHERE id=?`, id)
	return err
}

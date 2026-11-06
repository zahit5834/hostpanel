package customers

import (
	"context"
	"path/filepath"
	"testing"

	"github.com/zahit5834/hostpanel/internal/store"
)

func TestCRUD(t *testing.T) {
	db, err := store.Open(filepath.Join(t.TempDir(), "t.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	ctx := context.Background()
	store.Migrate(ctx, db)
	s := New(db)

	if err := s.Create(ctx, &Customer{Name: " "}); err == nil {
		t.Fatal("empty name accepted")
	}
	if err := s.Create(ctx, &Customer{Name: "A", Email: "bad"}); err == nil {
		t.Fatal("bad email accepted")
	}
	c := &Customer{Name: " Ahmet ", Company: "Örnek AŞ", Email: "a@ornek.com"}
	if err := s.Create(ctx, c); err != nil || c.ID == 0 {
		t.Fatal(err)
	}
	c.Phone = "0555"
	if err := s.Update(ctx, c); err != nil {
		t.Fatal(err)
	}
	got, _ := s.Get(ctx, c.ID)
	if got.Name != "Ahmet" || got.Phone != "0555" {
		t.Fatalf("%+v", got)
	}
	list, _ := s.List(ctx, "örnek")
	if len(list) != 1 {
		t.Fatalf("search n=%d", len(list))
	}
	db.Exec(`INSERT INTO sites(customer_id, domain, short_name, runtime_id, status, created_at, updated_at) VALUES(?, 'a.com', 'a_com', 'static', 'running', 0, 0)`, c.ID)
	if err := s.Delete(ctx, c.ID); err != ErrHasSites {
		t.Fatalf("delete with sites: %v", err)
	}
}

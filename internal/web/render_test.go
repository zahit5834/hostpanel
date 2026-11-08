package web

import (
	"fmt"
	"testing"
)

func TestRendererCacheBounded(t *testing.T) {
	r, err := newRenderer(assets, false)
	if err != nil {
		t.Fatal(err)
	}
	if len(r.cache) != 0 {
		t.Fatalf("startup validation cached %d pages", len(r.cache))
	}
	pages := []string{"dashboard", "sites", "server", "backups", "settings_general", "settings_update", "settings_transfer", "login"}
	for _, p := range pages {
		if _, err := r.get(p); err != nil {
			t.Fatal(err)
		}
	}
	if len(r.cache) != renderCacheSize || len(r.order) != renderCacheSize {
		t.Fatalf("cache %d order %d", len(r.cache), len(r.order))
	}
	if _, ok := r.cache["dashboard"]; ok {
		t.Fatal("least recently used page not evicted")
	}
	// A hit moves the page to the end, so it survives the next eviction.
	r.get("server")
	r.get("dashboard")
	if _, ok := r.cache["server"]; !ok {
		t.Fatalf("recently used page evicted: %v", r.order)
	}
	if got := fmt.Sprint(r.order); got != "[settings_transfer login server dashboard]" {
		t.Fatal(got)
	}
}

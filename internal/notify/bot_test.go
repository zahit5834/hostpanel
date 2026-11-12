package notify

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestParseCommand(t *testing.T) {
	for in, want := range map[string]string{
		"/durum": "durum|", "/Durum@HostPanelBot": "durum|", "/yeniden_baslat a.com 123456": "yeniden_baslat|a.com,123456",
		"/x;rm": "|", "/": "|", "/a b c d e f g": "a|b,c,d,e",
	} {
		c, a := ParseCommand(in)
		if got := c + "|" + strings.Join(a, ","); got != want {
			t.Errorf("%q: %q want %q", in, got, want)
		}
	}
}

// fakeBotAPI serves getUpdates from a queue and records sendMessage.
type fakeBotAPI struct {
	mu      sync.Mutex
	queue   []map[string]any
	sent    []string
	sentTo  []string
	offsets []string
}

func (f *fakeBotAPI) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	defer f.mu.Unlock()
	switch {
	case strings.HasSuffix(r.URL.Path, "/getUpdates"):
		f.offsets = append(f.offsets, r.URL.Query().Get("offset"))
		res := f.queue
		if r.URL.Query().Get("offset") == "-1" && len(res) > 0 {
			res = res[len(res)-1:]
		}
		f.queue = nil
		if len(res) == 0 && r.URL.Query().Get("timeout") != "0" {
			f.mu.Unlock()
			time.Sleep(50 * time.Millisecond) // a short "long poll"
			f.mu.Lock()
		}
		json.NewEncoder(w).Encode(map[string]any{"ok": true, "result": res})
	case strings.HasSuffix(r.URL.Path, "/sendMessage"):
		r.ParseForm()
		f.sent = append(f.sent, r.PostFormValue("text"))
		f.sentTo = append(f.sentTo, r.PostFormValue("chat_id"))
		fmt.Fprint(w, `{"ok":true}`)
	}
}

func msg(id int64, chat int64, typ, text string, age time.Duration) map[string]any {
	return map[string]any{"update_id": id, "message": map[string]any{"date": time.Now().Add(-age).Unix(), "text": text,
		"chat": map[string]any{"id": chat, "type": typ}}}
}

func TestBotOnlyAnswersOwnChat(t *testing.T) {
	s, _ := newSvc(t)
	api := &fakeBotAPI{queue: []map[string]any{msg(5, 42, "private", "/durum", 0)}} // queued before start: skipped
	srv := httptest.NewServer(api)
	defer srv.Close()
	s.TelegramAPI, s.Client = srv.URL, srv.Client()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	if err := s.Save(ctx, Input{TelegramOn: true, TelegramToken: testToken, TelegramChat: "@kanal", Commands: true}); err == nil {
		t.Fatal("commands with a channel name accepted")
	}
	if err := s.Save(ctx, Input{TelegramOn: true, TelegramToken: testToken, TelegramChat: "42", Commands: true}); err != nil {
		t.Fatal(err)
	}
	var mu sync.Mutex
	var cmds []string
	go s.RunBot(ctx, func(_ context.Context, cmd string, args []string) string {
		mu.Lock()
		cmds = append(cmds, cmd+" "+strings.Join(args, " "))
		mu.Unlock()
		return "yanıt: " + cmd
	})
	time.Sleep(150 * time.Millisecond)
	api.mu.Lock()
	api.queue = []map[string]any{
		msg(6, 42, "private", "/durum", 0),
		msg(7, 99, "private", "/durum", 0),             // another chat
		msg(8, 42, "group", "/siteler", 0),             // group with the same id is not possible, but type is checked
		msg(9, 42, "private", "/disk", 10*time.Minute), // stale
		msg(10, 42, "private", "merhaba", 0),           // not a command
		msg(11, 42, "private", "/yedekler", 0),
	}
	api.mu.Unlock()
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		mu.Lock()
		n := len(cmds)
		mu.Unlock()
		if n >= 2 {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	time.Sleep(100 * time.Millisecond)
	mu.Lock()
	defer mu.Unlock()
	if strings.Join(cmds, ";") != "durum ;yedekler " {
		t.Fatalf("handled %q", cmds)
	}
	api.mu.Lock()
	defer api.mu.Unlock()
	if len(api.sent) != 2 || api.sentTo[0] != "42" || !strings.Contains(api.sent[0], "<b>yanıt:</b> durum") {
		t.Fatalf("sent %q to %q", api.sent, api.sentTo)
	}
	// The queued update (5) is skipped: the start polls with -1 and update 5
	// never reached the handler (cmds above). Arrival order of the requests
	// at the fake server is not fixed (an aborted poll may land late), so no
	// offset other than -1 and ≥6 may appear at all.
	if api.offsets[0] != "-1" {
		t.Fatalf("offsets %v (queued update must be skipped)", api.offsets)
	}
	for _, o := range api.offsets {
		if o != "-1" && o != "6" && o != "12" {
			t.Fatalf("offsets %v", api.offsets)
		}
	}
}

func TestBotOffNoConnection(t *testing.T) {
	s, _ := newSvc(t)
	api := &fakeBotAPI{}
	srv := httptest.NewServer(api)
	defer srv.Close()
	s.TelegramAPI, s.Client = srv.URL, srv.Client()
	ctx, cancel := context.WithCancel(context.Background())
	s.Save(ctx, Input{TelegramOn: true, TelegramToken: testToken, TelegramChat: "42"})
	done := make(chan struct{})
	go func() { s.RunBot(ctx, func(context.Context, string, []string) string { return "" }); close(done) }()
	time.Sleep(150 * time.Millisecond)
	cancel()
	<-done
	if len(api.offsets) != 0 {
		t.Fatal("polled while commands are off")
	}
}

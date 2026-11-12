package notify

import (
	"strings"
	"testing"
)

func TestTelegramHTMLLayout(t *testing.T) {
	got := telegramHTML(Event{Title: "Posta kuyruğu <birikti>", Text: "Kuyrukta 60 ileti bekliyor (eşik 50). Bir hesap ele geçirilmiş olabilir: E-posta → Teslim edilebilirlik.\nKaynak IP: 1.2.3.4"})
	want := "🖥 <b>Posta kuyruğu &lt;birikti&gt;</b>\n\n" +
		"Kuyrukta 60 ileti bekliyor (eşik 50).\n" +
		"<b>Kaynak IP:</b> 1.2.3.4\n\n" +
		"👉 <i>Bir hesap ele geçirilmiş olabilir: E-posta → Teslim edilebilirlik.</i>"
	if got != want {
		t.Fatalf("got\n%s\nwant\n%s", got, want)
	}
}

func TestLayoutKeepsErrorsAndBullets(t *testing.T) {
	// Error texts are not labels; bullets and blank lines survive.
	got := plainBody("Get \"http://127.0.0.1:5001/\": dial tcp: connection refused\n\n\nTrafik:\n• a.com 10 istek. Sonra\n")
	want := "Get \"http://127.0.0.1:5001/\": dial tcp: connection refused\n\nTrafik:\n• a.com 10 istek. Sonra"
	if got != want {
		t.Fatalf("got %q", got)
	}
	if h := telegramHTML(Event{Text: "a <script>&"}); h != "a &lt;script&gt;&amp;" {
		t.Fatalf("escape: %q", h)
	}
	if m := message(Event{Title: "T", Text: "x"}); m != "T\n\nx" {
		t.Fatalf("message %q", m)
	}
	if !strings.HasPrefix(telegramPlain(Event{Title: "T"}), "🖥 T") {
		t.Fatal("plain")
	}
}

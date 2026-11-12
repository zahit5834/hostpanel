package notify

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"
)

// --- I5: Telegram commands (long polling; off by default) ---
//
// One goroutine. While the commands are off (or Telegram is not configured)
// it waits on a channel without a timer or connection. While on, it keeps one
// getUpdates long poll open (50 s) to api.telegram.org. Only private messages
// from the configured chat id are answered; everything else is ignored.

const (
	setTGCommands = "notify_telegram_commands" // "1" = answer commands
	pollTimeout   = 50                         // seconds (Telegram long poll)
	maxReply      = 3800                       // Telegram's limit is 4096 characters
	staleAfter    = 2 * time.Minute            // commands older than this are ignored
)

// BotHandler answers one command (text without the leading "/", e.g.
// "durum" or "yeniden_baslat site.com 123456"). It returns the reply.
type BotHandler func(ctx context.Context, cmd string, args []string) string

// CommandsOn reports whether Telegram commands are enabled.
func (s *Service) CommandsOn(ctx context.Context) bool {
	return s.get(ctx, setTGCommands, "") == "1"
}

// WakeBot restarts the poller after a settings change.
func (s *Service) WakeBot() {
	s.init()
	select {
	case s.botWake <- struct{}{}:
	default:
	}
}

type tgUpdate struct {
	UpdateID int64 `json:"update_id"`
	Message  *struct {
		Date int64  `json:"date"`
		Text string `json:"text"`
		Chat struct {
			ID   int64  `json:"id"`
			Type string `json:"type"`
		} `json:"chat"`
	} `json:"message"`
}

// RunBot polls for commands until ctx ends.
func (s *Service) RunBot(ctx context.Context, h BotHandler) {
	s.init()
	var offset int64
	primed := false
	backoff := 30 * time.Second
	for {
		c := s.Load(ctx)
		chat, chatErr := strconv.ParseInt(c.TelegramChat, 10, 64)
		if !c.Commands || !c.TelegramOn || c.TelegramToken == "" || chatErr != nil {
			primed = false
			select {
			case <-ctx.Done():
				return
			case <-s.botWake:
				continue
			}
		}
		if !primed {
			// Skip whatever was queued while the panel was down or the
			// commands were off: offset -1 returns only the newest update.
			ups, err := s.getUpdates(ctx, c.TelegramToken, -1, 0)
			if err == nil {
				offset = 0
				if len(ups) > 0 {
					offset = ups[len(ups)-1].UpdateID + 1
				}
				primed = true
			}
			if err != nil {
				if !s.botWait(ctx, err, &backoff) {
					return
				}
				continue
			}
		}
		pctx, cancel := context.WithCancel(ctx)
		done := make(chan struct{})
		go func() { // a settings change aborts the open long poll
			select {
			case <-s.botWake:
				cancel()
			case <-done:
			}
		}()
		ups, err := s.getUpdates(pctx, c.TelegramToken, offset, pollTimeout)
		close(done)
		aborted := pctx.Err() != nil && ctx.Err() == nil
		cancel()
		if ctx.Err() != nil {
			return
		}
		if aborted {
			primed = false
			continue
		}
		if err != nil {
			if !s.botWait(ctx, err, &backoff) {
				return
			}
			continue
		}
		backoff = 30 * time.Second
		for _, u := range ups {
			offset = u.UpdateID + 1
			m := u.Message
			if m == nil || m.Chat.ID != chat || m.Chat.Type != "private" || !strings.HasPrefix(m.Text, "/") {
				continue
			}
			if time.Since(time.Unix(m.Date, 0)) > staleAfter {
				continue
			}
			cmd, args := ParseCommand(m.Text)
			reply := h(ctx, cmd, args)
			if reply == "" {
				continue
			}
			if err := s.reply(ctx, c.TelegramToken, chat, reply); err != nil && s.Log != nil {
				s.Log.Warn("telegram reply failed", "err", err)
			}
		}
	}
}

// botWait sleeps after an error (doubling up to 10 minutes). False = ctx ended.
func (s *Service) botWait(ctx context.Context, err error, backoff *time.Duration) bool {
	if s.Log != nil {
		s.Log.Warn("telegram commands: poll failed", "err", err, "retry_in", backoff.String())
	}
	t := time.NewTimer(*backoff)
	defer t.Stop()
	*backoff = min(*backoff*2, 10*time.Minute)
	select {
	case <-ctx.Done():
		return false
	case <-s.botWake:
		*backoff = 30 * time.Second
	case <-t.C:
	}
	return true
}

// ParseCommand splits "/cmd@BotName a b" into ("cmd", [a b]); the command is
// lower-cased and limited to [a-z0-9_].
func ParseCommand(text string) (string, []string) {
	f := strings.Fields(strings.TrimPrefix(strings.TrimSpace(text), "/"))
	if len(f) == 0 {
		return "", nil
	}
	cmd, _, _ := strings.Cut(strings.ToLower(f[0]), "@")
	for _, r := range cmd {
		if !(r >= 'a' && r <= 'z' || r >= '0' && r <= '9' || r == '_') {
			return "", nil
		}
	}
	if len(f) > 5 {
		f = f[:5]
	}
	return cmd, f[1:]
}

func (s *Service) botClient() *http.Client {
	return &http.Client{Timeout: (pollTimeout + 20) * time.Second, Transport: s.Client.Transport}
}

func (s *Service) getUpdates(ctx context.Context, token string, offset int64, timeout int) ([]tgUpdate, error) {
	q := url.Values{"offset": {strconv.FormatInt(offset, 10)}, "timeout": {strconv.Itoa(timeout)},
		"allowed_updates": {`["message"]`}}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, s.TelegramAPI+"/bot"+token+"/getUpdates?"+q.Encode(), nil)
	if err != nil {
		return nil, errors.New("istek oluşturulamadı")
	}
	res, err := s.botClient().Do(req)
	if err != nil {
		var ue *url.Error
		if errors.As(err, &ue) {
			err = ue.Err
		}
		return nil, fmt.Errorf("bağlanılamadı: %s", strings.ReplaceAll(err.Error(), token, "***"))
	}
	defer res.Body.Close()
	var out struct {
		OK          bool       `json:"ok"`
		Description string     `json:"description"`
		Result      []tgUpdate `json:"result"`
	}
	if err := json.NewDecoder(io.LimitReader(res.Body, 1<<20)).Decode(&out); err != nil {
		return nil, fmt.Errorf("yanıt okunamadı (%s)", res.Status)
	}
	if !out.OK {
		return nil, fmt.Errorf("API hatası: %s", out.Description)
	}
	return out.Result, nil
}

func (s *Service) reply(ctx context.Context, token string, chat int64, text string) error {
	if len(text) > maxReply {
		cut := maxReply
		for cut > 0 && !utf8.RuneStart(text[cut]) {
			cut--
		}
		text = text[:cut] + "\n…"
	}
	c := Config{TelegramToken: token, TelegramChat: strconv.FormatInt(chat, 10)}
	sctx, cancel := context.WithTimeout(ctx, sendTimeout)
	defer cancel()
	return s.telegram(sctx, c, Event{Title: text})
}

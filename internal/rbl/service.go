package rbl

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"net"
	"net/netip"
	"slices"
	"sync"
	"time"

	"github.com/zahit5834/hostpanel/internal/crypto"
	"github.com/zahit5834/hostpanel/internal/store"
)

const (
	settingState  = "rbl_state"
	settingDQSKey = "rbl_dqs_key_sealed"
)

// State is the outcome of the last check.
type State struct {
	CheckedAt int64    `json:"checked_at"`
	DQS       bool     `json:"dqs,omitempty"`
	Results   []Result `json:"results,omitempty"`
}

// Listed returns the listed results.
func (st State) Listed() []Result {
	var out []Result
	for _, r := range st.Results {
		if r.Status == StatusListed {
			out = append(out, r)
		}
	}
	return out
}

// Refused reports whether some list refused the queries.
func (st State) Refused() bool {
	for _, r := range st.Results {
		if r.Status == StatusRefused {
			return true
		}
	}
	return false
}

// Checked is the time of the last check (zero = never).
func (st State) Checked() time.Time {
	if st.CheckedAt == 0 {
		return time.Time{}
	}
	return time.Unix(st.CheckedAt, 0)
}

// Change is a listing that appeared or disappeared since the last check.
type Change struct {
	Result
	Listed bool // false: removed from the list
}

// Service runs the checks and keeps the last state in settings.
type Service struct {
	DB       *sql.DB
	Box      *crypto.Box
	Resolver Resolver // nil = net.DefaultResolver
	// Targets returns the mail server's IPv4 addresses and the names to check
	// (mail host and mail domains); empty when no mail server is installed.
	Targets func(ctx context.Context) ([]netip.Addr, []string)

	mu sync.Mutex // one check at a time
}

func (s *Service) resolver() Resolver {
	if s.Resolver != nil {
		return s.Resolver
	}
	return net.DefaultResolver
}

// State returns the stored result of the last check.
func (s *Service) State(ctx context.Context) State {
	var st State
	json.Unmarshal([]byte(store.GetSetting(ctx, s.DB, settingState, "{}")), &st)
	return st
}

// HasKey reports whether a DQS key is stored.
func (s *Service) HasKey(ctx context.Context) bool {
	return store.GetSetting(ctx, s.DB, settingDQSKey, "") != ""
}

func (s *Service) key(ctx context.Context) string {
	sealed := store.GetSetting(ctx, s.DB, settingDQSKey, "")
	if sealed == "" || s.Box == nil {
		return ""
	}
	k, err := s.Box.OpenString(sealed)
	if err != nil || !ValidDQSKey(k) {
		return ""
	}
	return k
}

// SetKey stores (sealed) or, with "", removes the Spamhaus DQS key.
func (s *Service) SetKey(ctx context.Context, key string) error {
	if key == "" {
		return store.SetSetting(ctx, s.DB, settingDQSKey, "")
	}
	if !ValidDQSKey(key) {
		return errors.New("DQS anahtarı 26 karakter olmalı (küçük harf ve rakam)")
	}
	sealed, err := s.Box.SealString(key)
	if err != nil {
		return err
	}
	return store.SetSetting(ctx, s.DB, settingDQSKey, sealed)
}

// Run checks every list and returns the new state and the listings that
// appeared or disappeared (refused and failed queries keep the previous
// verdict, so a resolver hiccup does not report a removal).
func (s *Service) Run(ctx context.Context) (State, []Change, error) {
	if !s.mu.TryLock() {
		return State{}, nil, errors.New("kontrol zaten sürüyor")
	}
	defer s.mu.Unlock()
	var ips []netip.Addr
	var names []string
	if s.Targets != nil {
		ips, names = s.Targets(ctx)
	}
	if len(ips) == 0 && len(names) == 0 {
		return State{}, nil, errors.New("kontrol edilecek adres yok (posta sunucusu kurulu değil ya da sunucunun genel IPv4 adresi bilinmiyor)")
	}
	key := s.key(ctx)
	prev := s.State(ctx)
	st := State{CheckedAt: time.Now().Unix(), DQS: key != "", Results: Check(ctx, s.resolver(), key, ips, names)}
	was := map[string]bool{}
	for _, r := range prev.Results {
		if r.Status == StatusListed {
			was[r.List+" "+r.Target] = true
		}
	}
	var changes []Change
	for _, r := range st.Results {
		k := r.List + " " + r.Target
		switch r.Status {
		case StatusListed:
			if !was[k] {
				changes = append(changes, Change{Result: r, Listed: true})
			}
		case StatusClean:
			if was[k] {
				changes = append(changes, Change{Result: r})
			}
		}
	}
	slices.SortFunc(changes, func(a, b Change) int {
		if a.List != b.List {
			return compare(a.List, b.List)
		}
		return compare(a.Target, b.Target)
	})
	b, _ := json.Marshal(st)
	if err := store.SetSetting(ctx, s.DB, settingState, string(b)); err != nil {
		return st, changes, err
	}
	return st, changes, nil
}

func compare(a, b string) int {
	switch {
	case a < b:
		return -1
	case a > b:
		return 1
	}
	return 0
}

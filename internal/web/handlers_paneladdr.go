package web

import (
	"context"
	"fmt"
	"net/http"
	"strings"

	"github.com/zahit5834/hostpanel/internal/dns"
	"github.com/zahit5834/hostpanel/internal/logs"
	"github.com/zahit5834/hostpanel/internal/notify"
	"github.com/zahit5834/hostpanel/internal/paneladdr"
	"github.com/zahit5834/hostpanel/internal/ssl"
	"github.com/zahit5834/hostpanel/internal/store"
)

// setPanelTarget is the name being set up (DNS publishes it while the job runs).
const setPanelTarget = "panel_domain_target"

// panelAddrData is the "Panel adresi" card of Settings → General.
type panelAddrData struct {
	Addr     paneladdr.Addr
	URL      string
	Fallback string // https://<ip>:<port> ("" = none)
	Bases    []panelBase
	Label    string
	JobID    int64
	Running  bool
	IPs      []string // A/AAAA values for a zone outside the panel
}

type panelBase struct {
	Name   string
	InZone bool // a panel DNS zone covers it: the record is added automatically
}

func (s *Server) panelAddrData(r *http.Request) panelAddrData {
	ctx := r.Context()
	a := s.PanelAddr.Addr.Get()
	d := panelAddrData{Addr: a, URL: a.URL(), Label: "panel", JobID: parseInt64(r.URL.Query().Get("job"))}
	if p := a.FallbackPort(); p != 0 {
		// the address the admin entered (Settings → General) wins: behind NAT
		// the interface address is not the one reachable from outside
		ip := "<sunucu-ip>"
		if v4 := publicV4(s.SSL.ServerIPs(ctx)); len(v4) > 0 {
			ip = v4[len(v4)-1].String()
		}
		d.Fallback = fmt.Sprintf("https://%s:%d", ip, p)
	}
	for _, b := range s.PanelTaken(ctx).Bases {
		d.Bases = append(d.Bases, panelBase{Name: b, InZone: s.DNS != nil && s.DNS.ZoneCovering(ctx, "x."+b) != ""})
	}
	for _, ip := range s.SSL.ServerIPs(ctx) {
		if ip = ip.Unmap(); ip.IsGlobalUnicast() && !ip.IsPrivate() {
			d.IPs = append(d.IPs, ip.String())
		}
	}
	for _, st := range []string{"running", "queued"} {
		if list, err := s.Jobs.List(ctx, st, "panel.domain", "", 0, 1); err == nil && len(list) > 0 {
			d.Running, d.JobID = true, list[0].ID
		}
	}
	return d
}

// panelTaken lists the offered parents and every name the panel must not take.
func (s *Server) PanelTaken(ctx context.Context) paneladdr.Taken {
	t := paneladdr.Taken{Names: map[string]string{}, Manual: map[string]string{}}
	var zones, siteDomains []string
	list, _ := s.Sites.Store.List(ctx, 0)
	for _, st := range list {
		siteDomains = append(siteDomains, st.Domain)
		for _, n := range st.HostNames() {
			t.Names[n] = "site " + st.Domain
		}
	}
	if s.Mail != nil {
		mi := s.Mail.ZoneInfo(ctx)
		if mi.Host != "" {
			t.Names[mi.Host] = "posta sunucusu"
		}
		for _, h := range mi.ExtraHosts {
			t.Names[h] = "posta otomatik ayarı"
		}
	}
	if s.DNS != nil {
		st := s.DNS.Settings(ctx)
		for _, ns := range []string{st.NS1, st.NS2} {
			if ns != "" {
				t.Names[ns] = "nameserver"
			}
		}
		zs, _ := s.DNS.Store.Zones(ctx, 0)
		for _, z := range zs {
			zones = append(zones, z.Name)
			recs, _ := s.DNS.Store.Records(ctx, z.ID)
			for _, rec := range recs {
				if rec.Type == dns.TypeA || rec.Type == dns.TypeAAAA || rec.Type == dns.TypeCNAME {
					t.Manual[rec.FQDN(z.Name)] = rec.Type
				}
			}
		}
	}
	t.Bases = paneladdr.Bases(zones, siteDomains)
	return t
}

// PanelChanged records the change and tells the admin (security event).
func (s *Server) PanelChanged(ctx context.Context, old, cur paneladdr.Addr) {
	fallback := ""
	if p := cur.FallbackPort(); p != 0 {
		fallback = fmt.Sprintf("IP:%d", p)
	}
	summary := "Panel adresi değişti: " + cur.URL()
	if cur.Domain == "" {
		summary = "Panel adresi: yalnızca IP (" + fallback + ")"
	}
	before := old.URL()
	if before == "" {
		before = fmt.Sprintf("IP:%d", old.FallbackPort())
	}
	sys := logs.WithActor(ctx, logs.Actor{Source: logs.SourceSystem})
	s.Activity.Record(sys, logs.Entry{Action: "panel.domain", TargetType: "panel", TargetID: "address", Summary: summary,
		Diff: logs.LineDiff(before, strings.TrimSpace(cur.URL()+" "+fallback))}, nil)
	if s.Notify != nil {
		text := "Önceki: " + before
		if cur.Domain != "" && fallback != "" {
			text += "\nYedek giriş: " + fallback + " (self-signed)"
		}
		s.Notify.Send(ctx, notify.Event{Kind: notify.KindSecurity, Key: "panel.domain", NoDedupe: true, Title: summary, Text: text})
	}
}

// panelAddrSave starts the change (or the removal of the name).
func (s *Server) panelAddrSave(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	name := ""
	if r.PostFormValue("action") != "clear" {
		n, err := paneladdr.Name(r.PostFormValue("label"), r.PostFormValue("base"), s.PanelTaken(ctx))
		if err != nil {
			s.renderGeneral(w, r, http.StatusBadRequest, err.Error(), "")
			return
		}
		name = n
	}
	id, err := s.PanelAddr.Start(ctx, name)
	if err != nil {
		s.renderGeneral(w, r, http.StatusBadRequest, err.Error(), "")
		return
	}
	http.Redirect(w, r, fmt.Sprintf("/settings/general?job=%d#panel-address", id), http.StatusSeeOther)
}

// panel address hooks for paneladdr.Service and the DNS service.

// PanelTarget / SetPanelTarget / PanelDelegated / ACMEEmail are hooks of
// paneladdr.Service.
func (s *Server) PanelTarget(ctx context.Context) string {
	return store.GetSetting(ctx, s.DB, setPanelTarget, "")
}

func (s *Server) SetPanelTarget(ctx context.Context, name string) {
	store.SetSetting(ctx, s.DB, setPanelTarget, name)
}

func (s *Server) PanelDelegated(ctx context.Context, zone string) (bool, string) {
	d := s.DNS.CheckDelegation(ctx, zone, true)
	if d.OK {
		return true, ""
	}
	if d.Err != "" {
		return false, d.Err
	}
	return false, "NS kayıtları: " + strings.Join(d.Found, ", ")
}

func (s *Server) ACMEEmail(ctx context.Context) string {
	return store.GetSetting(ctx, s.DB, ssl.SettingACMEEmail, "")
}

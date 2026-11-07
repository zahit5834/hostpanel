package web

import (
	"database/sql"
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"strings"

	"github.com/zahit5834/hostpanel/internal/dns"
)

func init() {
	funcs["dnsTypes"] = func() []string { return dns.Types }
	funcs["caaTags"] = func() []string { return dns.CAATags }
	funcs["fqdn"] = func(r dns.Record, zone string) string { return r.FQDN(zone) }
}

type dnsPage struct {
	Installed bool
	Settings  dns.Settings
	IPsText   string
	Zones     []dns.Zone
	Customers any
	Status    map[string]string
	JobID     int64
	SameIP    bool // ns1 and ns2 resolve to the same single address
}

func (s *Server) renderDNS(w http.ResponseWriter, r *http.Request, status int, in *dns.Settings, errMsg, notice string) {
	ctx := r.Context()
	d := dnsPage{Installed: s.DNS.Installed(ctx), Settings: s.DNS.Settings(ctx)}
	if in != nil {
		d.Settings = *in
	}
	d.IPsText = dns.FormatIPs(d.Settings.IPs)
	d.SameIP = len(d.Settings.IPs) == 1 || (len(d.Settings.IPs) == 2 && d.Settings.IPs[0].Is4() != d.Settings.IPs[1].Is4())
	d.Zones, _ = s.DNS.Store.Zones(ctx, 0)
	d.Customers, _ = s.Customers.List(ctx, "")
	if d.Installed {
		d.Status = s.DNS.Status(ctx)
	}
	d.JobID, _ = strconv.ParseInt(r.URL.Query().Get("job"), 10, 64)
	s.render(w, r, status, "dns", "layout", Page{Title: "DNS", Nav: "dns", Data: d, Error: errMsg, Notice: notice})
}

func (s *Server) dnsIndex(w http.ResponseWriter, r *http.Request) {
	notice := ""
	if r.URL.Query().Get("saved") == "1" {
		notice = "DNS ayarları kaydedildi."
	}
	s.renderDNS(w, r, http.StatusOK, nil, "", notice)
}

func (s *Server) dnsSaveSettings(w http.ResponseWriter, r *http.Request) {
	in := dns.Settings{NS1: r.PostFormValue("ns1"), NS2: r.PostFormValue("ns2"), Hostmaster: r.PostFormValue("hostmaster")}
	ips, err := dns.ParseIPs(r.PostFormValue("ips"))
	if err == nil {
		in.IPs = ips
		err = s.DNS.SaveSettings(r.Context(), in)
	}
	if err != nil {
		s.renderDNS(w, r, http.StatusBadRequest, &in, err.Error(), "")
		return
	}
	http.Redirect(w, r, "/dns?saved=1", http.StatusSeeOther)
}

func (s *Server) dnsInstall(w http.ResponseWriter, r *http.Request) {
	id, err := s.DNS.StartInstall(r.Context())
	if err != nil {
		s.renderDNS(w, r, http.StatusBadRequest, nil, err.Error(), "")
		return
	}
	http.Redirect(w, r, fmt.Sprintf("/dns?job=%d", id), http.StatusSeeOther)
}

func (s *Server) dnsZoneCreate(w http.ResponseWriter, r *http.Request) {
	cust, _ := strconv.ParseInt(r.PostFormValue("customer_id"), 10, 64)
	z, job, err := s.DNS.CreateZone(r.Context(), r.PostFormValue("name"), cust, r.PostFormValue("dnssec") == "1")
	if err != nil {
		s.renderDNS(w, r, http.StatusBadRequest, nil, err.Error(), "")
		return
	}
	http.Redirect(w, r, zoneURL(z.ID, job), http.StatusSeeOther)
}

func zoneURL(id, job int64) string {
	if job > 0 {
		return fmt.Sprintf("/dns/zones/%d?job=%d", id, job)
	}
	return fmt.Sprintf("/dns/zones/%d", id)
}

func (s *Server) loadZone(w http.ResponseWriter, r *http.Request) (dns.Zone, bool) {
	id, ok := pathID(r)
	if !ok {
		http.NotFound(w, r)
		return dns.Zone{}, false
	}
	z, err := s.DNS.Store.Zone(r.Context(), id)
	if errors.Is(err, sql.ErrNoRows) {
		http.NotFound(w, r)
		return z, false
	}
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return z, false
	}
	return z, true
}

type zonePage struct {
	Zone      dns.Zone
	Records   []dns.Record
	Auto      []dns.Record
	Preview   string
	Edit      dns.Record // record in the form (ID 0 = new)
	Installed bool
	Settings  dns.Settings
	Customers any
	JobID     int64
}

func (s *Server) renderZone(w http.ResponseWriter, r *http.Request, status int, z dns.Zone, edit *dns.Record, errMsg string) {
	ctx := r.Context()
	d := zonePage{Zone: z, Installed: s.DNS.Installed(ctx), Settings: s.DNS.Settings(ctx), Edit: dns.Record{Type: dns.TypeA}}
	d.Records, _ = s.DNS.Store.Records(ctx, z.ID)
	dns.SortRecords(d.Records)
	if d.Settings.Ready() {
		d.Preview, d.Auto, _ = s.DNS.Preview(ctx, z)
	}
	if edit != nil {
		d.Edit = *edit
	} else if rid, err := strconv.ParseInt(r.URL.Query().Get("edit"), 10, 64); err == nil {
		if rec, err := s.DNS.Store.Record(ctx, z.ID, rid); err == nil {
			d.Edit = rec
		}
	}
	d.Customers, _ = s.Customers.List(ctx, "")
	d.JobID, _ = strconv.ParseInt(r.URL.Query().Get("job"), 10, 64)
	s.render(w, r, status, "dns_zone", "layout", Page{Title: z.Name + " · DNS", Nav: "dns", Data: d, Error: errMsg})
}

func (s *Server) dnsZone(w http.ResponseWriter, r *http.Request) {
	z, ok := s.loadZone(w, r)
	if !ok {
		return
	}
	s.renderZone(w, r, http.StatusOK, z, nil, "")
}

func recordFromForm(r *http.Request) dns.Record {
	num := func(k string) int {
		n, _ := strconv.Atoi(strings.TrimSpace(r.PostFormValue(k)))
		return n
	}
	return dns.Record{Name: r.PostFormValue("name"), Type: r.PostFormValue("type"), TTL: num("ttl"), Prio: num("prio"),
		Weight: num("weight"), Port: num("port"), Tag: r.PostFormValue("tag"), Value: r.PostFormValue("value")}
}

func (s *Server) dnsRecordSave(w http.ResponseWriter, r *http.Request) {
	z, ok := s.loadZone(w, r)
	if !ok {
		return
	}
	rec := recordFromForm(r)
	if v := r.PathValue("rid"); v != "" {
		rec.ID, _ = strconv.ParseInt(v, 10, 64)
		if rec.ID <= 0 {
			http.NotFound(w, r)
			return
		}
	}
	saved, job, err := s.DNS.SaveRecord(r.Context(), z, rec)
	if errors.Is(err, sql.ErrNoRows) {
		http.NotFound(w, r)
		return
	}
	if err != nil {
		s.renderZone(w, r, http.StatusBadRequest, z, &saved, err.Error())
		return
	}
	http.Redirect(w, r, zoneURL(z.ID, job), http.StatusSeeOther)
}

func (s *Server) dnsRecordDelete(w http.ResponseWriter, r *http.Request) {
	z, ok := s.loadZone(w, r)
	if !ok {
		return
	}
	rid, err := strconv.ParseInt(r.PathValue("rid"), 10, 64)
	if err != nil || rid <= 0 {
		http.NotFound(w, r)
		return
	}
	job, err := s.DNS.DeleteRecord(r.Context(), z, rid)
	if errors.Is(err, sql.ErrNoRows) {
		http.NotFound(w, r)
		return
	}
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	http.Redirect(w, r, zoneURL(z.ID, job), http.StatusSeeOther)
}

func (s *Server) dnsZoneSettings(w http.ResponseWriter, r *http.Request) {
	z, ok := s.loadZone(w, r)
	if !ok {
		return
	}
	z.CustomerID, _ = strconv.ParseInt(r.PostFormValue("customer_id"), 10, 64)
	z.DefaultTTL = formInt(r, "default_ttl", z.DefaultTTL)
	z.DNSSEC = r.PostFormValue("dnssec") == "1"
	z.AutoSites = r.PostFormValue("auto_sites") == "1"
	job, err := s.DNS.UpdateZone(r.Context(), z)
	if err != nil {
		s.renderZone(w, r, http.StatusBadRequest, z, nil, err.Error())
		return
	}
	http.Redirect(w, r, zoneURL(z.ID, job), http.StatusSeeOther)
}

func (s *Server) dnsZoneDelete(w http.ResponseWriter, r *http.Request) {
	z, ok := s.loadZone(w, r)
	if !ok {
		return
	}
	if strings.TrimSpace(r.PostFormValue("confirm")) != z.Name {
		s.renderZone(w, r, http.StatusBadRequest, z, nil, "Silmek için zone adını aynen yazın: "+z.Name)
		return
	}
	job, err := s.DNS.DeleteZone(r.Context(), z.ID)
	if err != nil {
		s.renderZone(w, r, http.StatusBadRequest, z, nil, err.Error())
		return
	}
	if job > 0 {
		http.Redirect(w, r, fmt.Sprintf("/dns?job=%d", job), http.StatusSeeOther)
		return
	}
	http.Redirect(w, r, "/dns", http.StatusSeeOther)
}

// dnsDelegation is the lazy "registrar points here?" fragment (zone list and zone page).
func (s *Server) dnsDelegation(w http.ResponseWriter, r *http.Request) {
	z, ok := s.loadZone(w, r)
	if !ok {
		return
	}
	d := s.DNS.CheckDelegation(r.Context(), z.Name, r.URL.Query().Get("refresh") == "1")
	s.render(w, r, http.StatusOK, "dns_zone", "dns-delegation", Page{Data: map[string]any{"Zone": z, "D": d,
		"Settings": s.DNS.Settings(r.Context()), "Full": r.URL.Query().Get("full") == "1"}})
}

// dnsCheck asks the local BIND for the zone and shows the DS records when DNSSEC is on.
func (s *Server) dnsCheck(w http.ResponseWriter, r *http.Request) {
	z, ok := s.loadZone(w, r)
	if !ok {
		return
	}
	data := map[string]any{"Zone": z, "DryRun": s.Cfg.DryRun}
	if err := s.DNS.CheckLocal(r.Context(), z.Name); err != nil {
		data["LocalErr"] = err.Error()
	}
	if z.DNSSEC {
		ds, err := s.DNS.DS(r.Context(), z.Name)
		data["DS"] = ds
		if err != nil {
			data["DSErr"] = err.Error()
		}
	}
	s.render(w, r, http.StatusOK, "dns_zone", "dns-check", Page{Data: data})
}

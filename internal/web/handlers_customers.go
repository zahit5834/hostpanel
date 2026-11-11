package web

import (
	"database/sql"
	"errors"
	"fmt"
	"net/http"
	"strconv"

	"github.com/zahit5834/hostpanel/internal/customers"
	"github.com/zahit5834/hostpanel/internal/databases"
	"github.com/zahit5834/hostpanel/internal/logs"
	"github.com/zahit5834/hostpanel/internal/pgsql"
)

func customerFromForm(r *http.Request) customers.Customer {
	return customers.Customer{
		Name:    r.PostFormValue("name"),
		Company: r.PostFormValue("company"),
		Phone:   r.PostFormValue("phone"),
		Email:   r.PostFormValue("email"),
		Notes:   r.PostFormValue("notes"),
	}
}

func (s *Server) customerList(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query().Get("q")
	list, err := s.Customers.List(r.Context(), q)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	block := "layout"
	if isHX(r) {
		block = "customer-table"
	}
	s.render(w, r, http.StatusOK, "customers", block, Page{Title: "Müşteriler", Nav: "customers", Data: map[string]any{"List": list, "Q": q}})
}

// customerForm embeds the customer so the template keeps using .Name etc.
type customerForm struct {
	customers.Customer
	DBAvailable bool // MSSQL running: offer "create login"
	CreateLogin bool
}

func (s *Server) customerNew(w http.ResponseWriter, r *http.Request) {
	s.render(w, r, http.StatusOK, "customer_form", "layout", Page{Title: "Yeni müşteri", Nav: "customers",
		Data: customerForm{DBAvailable: s.DBs.Available(r.Context())}})
}

func (s *Server) customerCreate(w http.ResponseWriter, r *http.Request) {
	c := customerFromForm(r)
	createLogin := r.PostFormValue("create_login") == "1"
	if err := s.Customers.Create(r.Context(), &c); err != nil {
		s.render(w, r, http.StatusBadRequest, "customer_form", "layout", Page{Title: "Yeni müşteri", Nav: "customers",
			Data: customerForm{Customer: c, DBAvailable: s.DBs.Available(r.Context()), CreateLogin: createLogin}, Error: err.Error()})
		return
	}
	s.Activity.Record(r.Context(), logs.Entry{Action: "customer.create", TargetType: "customer", TargetID: strconv.FormatInt(c.ID, 10),
		Summary: "Müşteri eklendi: " + c.Name}, map[string]any{"name": c.Name, "company": c.Company, "email": c.Email})
	if createLogin {
		if _, _, err := s.DBs.EnsureLogin(r.Context(), c.ID); err != nil {
			s.Activity.Record(r.Context(), logs.Entry{Action: "db.login.create", TargetType: "customer", TargetID: strconv.FormatInt(c.ID, 10),
				Status: logs.StatusFailed, Error: err.Error(), Summary: "MSSQL login'i oluşturulamadı"}, nil)
		}
	}
	http.Redirect(w, r, fmt.Sprintf("/customers/%d", c.ID), http.StatusSeeOther)
}

func (s *Server) loadCustomer(w http.ResponseWriter, r *http.Request) (customers.Customer, bool) {
	id, ok := pathID(r)
	if !ok {
		http.NotFound(w, r)
		return customers.Customer{}, false
	}
	c, err := s.Customers.Get(r.Context(), id)
	if errors.Is(err, sql.ErrNoRows) {
		http.NotFound(w, r)
		return c, false
	}
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return c, false
	}
	return c, true
}

func (s *Server) customerDetail(w http.ResponseWriter, r *http.Request) {
	c, ok := s.loadCustomer(w, r)
	if !ok {
		return
	}
	siteList, _ := s.Sites.Store.List(r.Context(), c.ID)
	targets := []string{strconv.FormatInt(c.ID, 10)}
	for _, st := range siteList {
		targets = append(targets, st.Domain)
	}
	dbs, _ := s.DBs.Store.Databases(r.Context(), databases.DBFilter{CustomerID: c.ID})
	for _, d := range dbs {
		targets = append(targets, d.Name)
	}
	pgdbs, _ := s.PG.Store.Databases(r.Context(), pgsql.DBFilter{CustomerID: c.ID})
	for _, d := range pgdbs {
		targets = append(targets, d.Name)
	}
	recent, _ := s.Activity.Query(r.Context(), logs.Filter{TargetIDs: targets, Limit: 20})
	data := map[string]any{"C": c, "Sites": siteList, "Recent": recent, "DBs": dbs, "DBAvailable": s.DBs.Available(r.Context())}
	if s.DNS != nil {
		data["Zones"], _ = s.DNS.Store.Zones(r.Context(), c.ID)
	}
	if s.Mail != nil {
		data["MailDomains"], _ = s.Mail.Store.Domains(r.Context(), c.ID)
	}
	if l, err := s.DBs.Store.LoginForCustomer(r.Context(), c.ID); err == nil {
		data["Login"] = &l
	}
	data["PGDBs"], data["PGAvailable"], data["PGRole"] = pgdbs, s.PG.Available(r.Context()), (*pgsql.Role)(nil)
	if role, err := s.PG.Store.RoleForCustomer(r.Context(), c.ID); err == nil {
		data["PGRole"] = &role
	}
	s.render(w, r, http.StatusOK, "customer", "layout", Page{Title: c.Name, Nav: "customers", Data: data})
}

func (s *Server) customerEdit(w http.ResponseWriter, r *http.Request) {
	c, ok := s.loadCustomer(w, r)
	if !ok {
		return
	}
	s.render(w, r, http.StatusOK, "customer_form", "layout", Page{Title: c.Name + " · Düzenle", Nav: "customers", Data: customerForm{Customer: c}})
}

func (s *Server) customerUpdate(w http.ResponseWriter, r *http.Request) {
	old, ok := s.loadCustomer(w, r)
	if !ok {
		return
	}
	c := customerFromForm(r)
	c.ID = old.ID
	if err := s.Customers.Update(r.Context(), &c); err != nil {
		s.render(w, r, http.StatusBadRequest, "customer_form", "layout", Page{Title: old.Name, Nav: "customers", Data: customerForm{Customer: c}, Error: err.Error()})
		return
	}
	before := fmt.Sprintf("ad: %s\nfirma: %s\ntelefon: %s\ne-posta: %s", old.Name, old.Company, old.Phone, old.Email)
	after := fmt.Sprintf("ad: %s\nfirma: %s\ntelefon: %s\ne-posta: %s", c.Name, c.Company, c.Phone, c.Email)
	s.Activity.Record(r.Context(), logs.Entry{Action: "customer.update", TargetType: "customer", TargetID: strconv.FormatInt(c.ID, 10),
		Summary: "Müşteri güncellendi: " + c.Name, Diff: logs.LineDiff(before, after)}, nil)
	http.Redirect(w, r, fmt.Sprintf("/customers/%d", c.ID), http.StatusSeeOther)
}

func (s *Server) customerDelete(w http.ResponseWriter, r *http.Request) {
	c, ok := s.loadCustomer(w, r)
	if !ok {
		return
	}
	if n, _ := s.Sites.Store.List(r.Context(), c.ID); len(n) > 0 {
		http.Error(w, customers.ErrHasSites.Error(), http.StatusBadRequest)
		return
	}
	// The SQL login is dropped on the server first (refused while it owns databases).
	if s.PG.Store.CountForCustomer(r.Context(), c.ID) > 0 {
		http.Error(w, "müşterinin PostgreSQL veritabanları var; önce veritabanlarını silin", http.StatusBadRequest)
		return
	}
	if err := s.DBs.PrepareCustomerDelete(r.Context(), c.ID); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	if err := s.PG.PrepareCustomerDelete(r.Context(), c.ID); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	if err := s.Customers.Delete(r.Context(), c.ID); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	s.Activity.Record(r.Context(), logs.Entry{Action: "customer.delete", TargetType: "customer", TargetID: strconv.FormatInt(c.ID, 10),
		Summary: "Müşteri silindi: " + c.Name}, nil)
	w.Header().Set("HX-Redirect", "/customers")
	w.WriteHeader(http.StatusNoContent)
}

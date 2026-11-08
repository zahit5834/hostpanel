package web

import (
	"database/sql"
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"strings"

	"github.com/zahit5834/hostpanel/internal/customers"
	"github.com/zahit5834/hostpanel/internal/databases"
	"github.com/zahit5834/hostpanel/internal/logs"
	"github.com/zahit5834/hostpanel/internal/sites"
)

type dbPageData struct {
	Server       *databases.Server
	DockerReady  bool
	Logins       []databases.Login
	DBs          []databases.Database
	Customers    []customers.Customer
	Sites        []sites.Site
	JobID        int64
	DefaultImage string
	DefaultMem   int
	MinMem       int
	MemTotalMB   int
	Editions     []string
	Form         databases.CreateInput
	Notice       string
}

func (s *Server) databasesPage(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	s.renderDatabases(w, r, http.StatusOK, databases.CreateInput{
		CustomerID: parseInt64(q.Get("customer")), SiteID: parseInt64(q.Get("site")), WriteEnv: q.Get("site") != "",
	}, "", "")
}

func (s *Server) renderDatabases(w http.ResponseWriter, r *http.Request, status int, form databases.CreateInput, errMsg, notice string) {
	ctx := r.Context()
	d := dbPageData{JobID: parseInt64(r.URL.Query().Get("job")), DefaultImage: databases.DefaultImage,
		DefaultMem: databases.DefaultMemoryMB, MinMem: databases.MinMemoryMB, MemTotalMB: s.DBs.MemTotalMB,
		Editions: databases.Editions, Form: form, DockerReady: s.DBs.DockerPresent(ctx)}
	if srv, err := s.DBs.Store.Server(ctx); err == nil {
		d.Server = &srv
	}
	d.Logins, _ = s.DBs.Store.Logins(ctx)
	d.DBs, _ = s.DBs.Store.Databases(ctx, databases.DBFilter{})
	d.Customers, _ = s.Customers.List(ctx, "")
	d.Sites, _ = s.Sites.Store.List(ctx, 0)
	s.render(w, r, status, "databases", "layout", Page{Title: "Veritabanları", Nav: "databases", Data: d, Error: errMsg, Notice: notice})
}

// databasesStatus is the lazily loaded live container card (docker stats takes ~1–2 s).
func (s *Server) databasesStatus(w http.ResponseWriter, r *http.Request) {
	st := s.DBs.LiveStatus(r.Context())
	s.render(w, r, http.StatusOK, "databases", "db-status", Page{Data: st})
}

func (s *Server) dbJobRedirect(w http.ResponseWriter, r *http.Request, id int64, err error) {
	if err != nil {
		s.renderDatabases(w, r, http.StatusBadRequest, databases.CreateInput{}, err.Error(), "")
		return
	}
	http.Redirect(w, r, fmt.Sprintf("/databases?job=%d", id), http.StatusSeeOther)
}

func (s *Server) dockerInstall(w http.ResponseWriter, r *http.Request) {
	id, err := s.DBs.StartDockerInstall(r.Context())
	if err == nil && r.PostFormValue("back") == "postgres" {
		http.Redirect(w, r, fmt.Sprintf("/postgres?job=%d", id), http.StatusSeeOther)
		return
	}
	s.dbJobRedirect(w, r, id, err)
}

func (s *Server) dbServerInstall(w http.ResponseWriter, r *http.Request) {
	in := databases.InstallInput{
		Edition:    r.PostFormValue("edition"),
		ProductKey: r.PostFormValue("product_key"),
		MemoryMB:   formInt(r, "memory_mb", databases.DefaultMemoryMB),
		AcceptEULA: r.PostFormValue("accept_eula") == "1",
	}
	id, err := s.DBs.StartInstall(r.Context(), in)
	s.dbJobRedirect(w, r, id, err)
}

func (s *Server) dbServerRemove(w http.ResponseWriter, r *http.Request) {
	act := s.Activity.Begin(r.Context(), logs.Entry{Action: "db.server.remove", TargetType: "db_server", TargetID: "mssql",
		Summary: "Yarım kalan MSSQL kurulumu kaldırıldı"}, nil)
	err := s.DBs.RemoveFailed(r.Context(), nil)
	act.Finish(err)
	if err != nil {
		s.renderDatabases(w, r, http.StatusBadRequest, databases.CreateInput{}, err.Error(), "")
		return
	}
	http.Redirect(w, r, "/databases", http.StatusSeeOther)
}

var dbOpLabels = map[string]string{"start": "başlatıldı", "stop": "durduruldu", "restart": "yeniden başlatıldı"}

func (s *Server) dbServerOp(w http.ResponseWriter, r *http.Request) {
	op := r.PathValue("op")
	label, ok := dbOpLabels[op]
	if !ok {
		http.NotFound(w, r)
		return
	}
	act := s.Activity.Begin(r.Context(), logs.Entry{Action: "db.server." + op, TargetType: "db_server", TargetID: "mssql",
		Summary: "MSSQL " + label}, nil)
	err := s.DBs.Operate(r.Context(), op)
	act.Finish(err)
	if err != nil {
		s.renderDatabases(w, r, http.StatusBadRequest, databases.CreateInput{}, "İşlem başarısız: "+err.Error(), "")
		return
	}
	http.Redirect(w, r, "/databases", http.StatusSeeOther)
}

func (s *Server) dbServerSettings(w http.ResponseWriter, r *http.Request) {
	in := databases.SettingsInput{
		MemoryMB: formInt(r, "memory_mb", 0),
		External: r.PostFormValue("external") == "1",
		AllowIPs: r.PostFormValue("allow_ips"),
	}
	id, diff, err := s.DBs.StartSettings(r.Context(), in)
	if err == nil {
		if j, jerr := s.Jobs.Get(r.Context(), id); jerr == nil {
			s.setActivityDiff(j.ActivityID, diff)
		}
	}
	s.dbJobRedirect(w, r, id, err)
}

func (s *Server) dbIsolationTest(w http.ResponseWriter, r *http.Request) {
	id, err := s.DBs.StartIsolationTest(r.Context())
	s.dbJobRedirect(w, r, id, err)
}

func (s *Server) dbRefreshSizes(w http.ResponseWriter, r *http.Request) {
	if err := s.DBs.RefreshSizes(r.Context()); err != nil {
		s.renderDatabases(w, r, http.StatusBadRequest, databases.CreateInput{}, "Boyutlar okunamadı: "+err.Error(), "")
		return
	}
	s.renderDatabases(w, r, http.StatusOK, databases.CreateInput{}, "", "Boyutlar güncellendi.")
}

func (s *Server) dbCreate(w http.ResponseWriter, r *http.Request) {
	in := databases.CreateInput{
		CustomerID: parseInt64(r.PostFormValue("customer_id")),
		Name:       r.PostFormValue("name"),
		SiteID:     parseInt64(r.PostFormValue("site_id")),
		WriteEnv:   r.PostFormValue("write_env") == "1",
		EnvKey:     r.PostFormValue("env_key"),
	}
	_, id, err := s.DBs.StartCreate(r.Context(), in)
	if err != nil {
		s.Activity.Record(r.Context(), logs.Entry{Action: "db.create", TargetType: "database", TargetID: in.Name,
			Status: logs.StatusFailed, Error: err.Error(), Summary: "Veritabanı oluşturulamadı"}, nil)
		s.renderDatabases(w, r, http.StatusBadRequest, in, err.Error(), "")
		return
	}
	http.Redirect(w, r, fmt.Sprintf("/databases?job=%d", id), http.StatusSeeOther)
}

func (s *Server) loadDatabase(w http.ResponseWriter, r *http.Request) (databases.Database, bool) {
	id, ok := pathID(r)
	if !ok {
		http.NotFound(w, r)
		return databases.Database{}, false
	}
	d, err := s.DBs.Store.Database(r.Context(), id)
	if errors.Is(err, sql.ErrNoRows) {
		http.NotFound(w, r)
		return d, false
	}
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return d, false
	}
	return d, true
}

type dbConnData struct {
	DB      databases.Database
	ADONET  string
	URL     string
	Login   string
	Pass    string
	Host    string
	Port    int
	Extern  bool
	Runtime string
}

// dbConnection reveals the connection strings (POST + CSRF, logged).
func (s *Server) dbConnection(w http.ResponseWriter, r *http.Request) {
	id, ok := pathID(r)
	if !ok {
		http.NotFound(w, r)
		return
	}
	ci, d, err := s.DBs.Connection(r.Context(), id)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	s.Activity.Record(r.Context(), logs.Entry{Action: "db.reveal", TargetType: "database", TargetID: d.Name,
		Summary: "Bağlantı bilgisi görüntülendi: " + d.Name}, nil)
	cd := dbConnData{DB: d, ADONET: ci.ADONET(), URL: ci.URL(), Login: ci.User, Pass: ci.Password, Host: ci.Host, Port: ci.Port}
	if srv, err := s.DBs.Store.Server(r.Context()); err == nil {
		cd.Extern = srv.External
	}
	s.render(w, r, http.StatusOK, "databases", "db-conn", Page{Data: cd})
}

func (s *Server) dbDelete(w http.ResponseWriter, r *http.Request) {
	d, ok := s.loadDatabase(w, r)
	if !ok {
		return
	}
	if strings.TrimSpace(r.PostFormValue("confirm")) != d.Name {
		s.renderDatabases(w, r, http.StatusBadRequest, databases.CreateInput{}, "Onay için veritabanı adını tam olarak yazın: "+d.Name, "")
		return
	}
	id, err := s.DBs.StartDrop(r.Context(), d)
	s.dbJobRedirect(w, r, id, err)
}

func (s *Server) dbLoginCreate(w http.ResponseWriter, r *http.Request) {
	cid := parseInt64(r.PostFormValue("customer_id"))
	l, created, err := s.DBs.EnsureLogin(r.Context(), cid)
	if err != nil {
		s.Activity.Record(r.Context(), logs.Entry{Action: "db.login.create", TargetType: "customer", TargetID: strconv.FormatInt(cid, 10),
			Status: logs.StatusFailed, Error: err.Error(), Summary: "MSSQL login'i oluşturulamadı"}, nil)
		s.renderDatabases(w, r, http.StatusBadRequest, databases.CreateInput{}, err.Error(), "")
		return
	}
	notice := "Login zaten vardı: " + l.Name
	if created {
		notice = "Login oluşturuldu: " + l.Name
	}
	back := r.PostFormValue("back")
	if back != "customer" {
		s.renderDatabases(w, r, http.StatusOK, databases.CreateInput{}, "", notice)
		return
	}
	http.Redirect(w, r, fmt.Sprintf("/customers/%d", cid), http.StatusSeeOther)
}

func (s *Server) dbLoginAction(w http.ResponseWriter, r *http.Request) {
	id, ok := pathID(r)
	if !ok {
		http.NotFound(w, r)
		return
	}
	ctx := r.Context()
	l, err := s.DBs.Store.Login(ctx, id)
	if err != nil {
		http.NotFound(w, r)
		return
	}
	entry := logs.Entry{TargetType: "customer", TargetID: strconv.FormatInt(l.CustomerID, 10)}
	var notice string
	switch r.PathValue("action") {
	case "password":
		entry.Action, entry.Summary = "db.login.password", "MSSQL login şifresi sıfırlandı: "+l.Name
		act := s.Activity.Begin(ctx, entry, nil)
		var updated []string
		updated, err = s.DBs.ResetPassword(ctx, id)
		act.Finish(err)
		notice = "Yeni şifre oluşturuldu (bağlantı bilgisinden görüntüleyebilirsiniz)."
		if len(updated) > 0 {
			notice += " Ortam değişkeni güncellenen siteler: " + strings.Join(updated, ", ") + " — yeni şifreyi kullanmaları için yeniden başlatın."
		}
	case "enable", "disable":
		enable := r.PathValue("action") == "enable"
		entry.Action, entry.Summary = "db.login."+r.PathValue("action"), "MSSQL login devre dışı bırakıldı: "+l.Name
		if enable {
			entry.Summary = "MSSQL login etkinleştirildi: " + l.Name
		}
		act := s.Activity.Begin(ctx, entry, nil)
		err = s.DBs.SetLoginEnabled(ctx, id, enable)
		act.Finish(err)
		notice = entry.Summary
	case "delete":
		entry.Action, entry.Summary = "db.login.delete", "MSSQL login silindi: "+l.Name
		act := s.Activity.Begin(ctx, entry, nil)
		_, err = s.DBs.DropLogin(ctx, id)
		act.Finish(err)
		notice = entry.Summary
	default:
		http.NotFound(w, r)
		return
	}
	if err != nil {
		s.renderDatabases(w, r, http.StatusBadRequest, databases.CreateInput{}, "İşlem başarısız: "+err.Error(), "")
		return
	}
	s.renderDatabases(w, r, http.StatusOK, databases.CreateInput{}, "", notice)
}

package web

import (
	"database/sql"
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"strings"

	"github.com/zahit5834/hostpanel/internal/customers"
	"github.com/zahit5834/hostpanel/internal/logs"
	"github.com/zahit5834/hostpanel/internal/pgsql"
	"github.com/zahit5834/hostpanel/internal/sites"
)

type pgPageData struct {
	Server       *pgsql.Server
	DockerReady  bool
	Roles        []pgsql.Role
	DBs          []pgsql.Database
	Customers    []customers.Customer
	Sites        []sites.Site
	JobID        int64
	DefaultImage string
	SuggestMem   int
	MinMem       int
	MemTotalMB   int
	Form         pgsql.CreateInput
}

func (s *Server) postgresPage(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	s.renderPG(w, r, http.StatusOK, pgsql.CreateInput{
		CustomerID: parseInt64(q.Get("customer")), SiteID: parseInt64(q.Get("site")), WriteEnv: q.Get("site") != "",
	}, "", "")
}

func (s *Server) renderPG(w http.ResponseWriter, r *http.Request, status int, form pgsql.CreateInput, errMsg, notice string) {
	ctx := r.Context()
	d := pgPageData{JobID: parseInt64(r.URL.Query().Get("job")), DefaultImage: pgsql.DefaultImage,
		SuggestMem: s.PG.SuggestMemory(), MinMem: pgsql.MinMemoryMB, MemTotalMB: s.PG.MemTotalMB,
		Form: form, DockerReady: s.PG.DockerPresent(ctx)}
	if srv, err := s.PG.Store.Server(ctx); err == nil {
		d.Server = &srv
	}
	d.Roles, _ = s.PG.Store.Roles(ctx)
	d.DBs, _ = s.PG.Store.Databases(ctx, pgsql.DBFilter{})
	d.Customers, _ = s.Customers.List(ctx, "")
	d.Sites, _ = s.Sites.Store.List(ctx, 0)
	s.render(w, r, status, "postgres", "layout", Page{Title: "PostgreSQL", Nav: "postgres", Data: d, Error: errMsg, Notice: notice})
}

func (s *Server) pgStatus(w http.ResponseWriter, r *http.Request) {
	st := s.PG.LiveStatus(r.Context())
	s.render(w, r, http.StatusOK, "postgres", "pg-status", Page{Data: st})
}

func (s *Server) pgJobRedirect(w http.ResponseWriter, r *http.Request, id int64, err error) {
	if err != nil {
		s.renderPG(w, r, http.StatusBadRequest, pgsql.CreateInput{}, err.Error(), "")
		return
	}
	http.Redirect(w, r, fmt.Sprintf("/postgres?job=%d", id), http.StatusSeeOther)
}

func (s *Server) pgServerInstall(w http.ResponseWriter, r *http.Request) {
	id, err := s.PG.StartInstall(r.Context(), formInt(r, "memory_mb", pgsql.DefaultMemoryMB))
	s.pgJobRedirect(w, r, id, err)
}

func (s *Server) pgServerRemove(w http.ResponseWriter, r *http.Request) {
	act := s.Activity.Begin(r.Context(), logs.Entry{Action: "pg.server.remove", TargetType: "db_server", TargetID: "postgres",
		Summary: "Yarım kalan PostgreSQL kurulumu kaldırıldı"}, nil)
	err := s.PG.RemoveFailed(r.Context(), nil)
	act.Finish(err)
	if err != nil {
		s.renderPG(w, r, http.StatusBadRequest, pgsql.CreateInput{}, err.Error(), "")
		return
	}
	http.Redirect(w, r, "/postgres", http.StatusSeeOther)
}

func (s *Server) pgServerOp(w http.ResponseWriter, r *http.Request) {
	op := r.PathValue("op")
	label, ok := dbOpLabels[op]
	if !ok {
		http.NotFound(w, r)
		return
	}
	act := s.Activity.Begin(r.Context(), logs.Entry{Action: "pg.server." + op, TargetType: "db_server", TargetID: "postgres",
		Summary: "PostgreSQL " + label}, nil)
	err := s.PG.Operate(r.Context(), op)
	act.Finish(err)
	if err != nil {
		s.renderPG(w, r, http.StatusBadRequest, pgsql.CreateInput{}, "İşlem başarısız: "+err.Error(), "")
		return
	}
	http.Redirect(w, r, "/postgres", http.StatusSeeOther)
}

func (s *Server) pgServerSettings(w http.ResponseWriter, r *http.Request) {
	in := pgsql.SettingsInput{
		MemoryMB: formInt(r, "memory_mb", 0),
		External: r.PostFormValue("external") == "1",
		AllowIPs: r.PostFormValue("allow_ips"),
	}
	id, diff, err := s.PG.StartSettings(r.Context(), in)
	if err == nil {
		if j, jerr := s.Jobs.Get(r.Context(), id); jerr == nil {
			s.setActivityDiff(j.ActivityID, diff)
		}
	}
	s.pgJobRedirect(w, r, id, err)
}

func (s *Server) pgIsolationTest(w http.ResponseWriter, r *http.Request) {
	id, err := s.PG.StartIsolationTest(r.Context())
	s.pgJobRedirect(w, r, id, err)
}

func (s *Server) pgRefreshSizes(w http.ResponseWriter, r *http.Request) {
	if err := s.PG.RefreshSizes(r.Context()); err != nil {
		s.renderPG(w, r, http.StatusBadRequest, pgsql.CreateInput{}, "Boyutlar okunamadı: "+err.Error(), "")
		return
	}
	s.renderPG(w, r, http.StatusOK, pgsql.CreateInput{}, "", "Boyutlar güncellendi.")
}

func (s *Server) pgCreate(w http.ResponseWriter, r *http.Request) {
	in := pgsql.CreateInput{
		CustomerID: parseInt64(r.PostFormValue("customer_id")),
		Name:       r.PostFormValue("name"),
		SiteID:     parseInt64(r.PostFormValue("site_id")),
		WriteEnv:   r.PostFormValue("write_env") == "1",
		EnvKey:     r.PostFormValue("env_key"),
	}
	_, id, err := s.PG.StartCreate(r.Context(), in)
	if err != nil {
		s.Activity.Record(r.Context(), logs.Entry{Action: "pg.db.create", TargetType: "database", TargetID: in.Name,
			Status: logs.StatusFailed, Error: err.Error(), Summary: "PostgreSQL veritabanı oluşturulamadı"}, nil)
		s.renderPG(w, r, http.StatusBadRequest, in, err.Error(), "")
		return
	}
	http.Redirect(w, r, fmt.Sprintf("/postgres?job=%d", id), http.StatusSeeOther)
}

type pgConnData struct {
	DB     pgsql.Database
	Npgsql string
	URL    string
	Role   string
	Pass   string
	Host   string
	Port   int
	Extern bool
}

// pgConnection reveals the connection strings (POST + CSRF, logged).
func (s *Server) pgConnection(w http.ResponseWriter, r *http.Request) {
	id, ok := pathID(r)
	if !ok {
		http.NotFound(w, r)
		return
	}
	ci, d, err := s.PG.Connection(r.Context(), id)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	s.Activity.Record(r.Context(), logs.Entry{Action: "pg.reveal", TargetType: "database", TargetID: d.Name,
		Summary: "PostgreSQL bağlantı bilgisi görüntülendi: " + d.Name}, nil)
	cd := pgConnData{DB: d, Npgsql: ci.Npgsql(), URL: ci.URL(), Role: ci.User, Pass: ci.Password, Host: ci.Host, Port: ci.Port}
	if srv, err := s.PG.Store.Server(r.Context()); err == nil {
		cd.Extern = srv.External
	}
	s.render(w, r, http.StatusOK, "postgres", "pg-conn", Page{Data: cd})
}

func (s *Server) pgDelete(w http.ResponseWriter, r *http.Request) {
	id, ok := pathID(r)
	if !ok {
		http.NotFound(w, r)
		return
	}
	d, err := s.PG.Store.Database(r.Context(), id)
	if errors.Is(err, sql.ErrNoRows) {
		http.NotFound(w, r)
		return
	}
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	if strings.TrimSpace(r.PostFormValue("confirm")) != d.Name {
		s.renderPG(w, r, http.StatusBadRequest, pgsql.CreateInput{}, "Onay için veritabanı adını tam olarak yazın: "+d.Name, "")
		return
	}
	jid, err := s.PG.StartDrop(r.Context(), d)
	s.pgJobRedirect(w, r, jid, err)
}

func (s *Server) pgRoleCreate(w http.ResponseWriter, r *http.Request) {
	cid := parseInt64(r.PostFormValue("customer_id"))
	role, created, err := s.PG.EnsureRole(r.Context(), cid)
	if err != nil {
		s.Activity.Record(r.Context(), logs.Entry{Action: "pg.role.create", TargetType: "customer", TargetID: strconv.FormatInt(cid, 10),
			Status: logs.StatusFailed, Error: err.Error(), Summary: "PostgreSQL rolü oluşturulamadı"}, nil)
		s.renderPG(w, r, http.StatusBadRequest, pgsql.CreateInput{}, err.Error(), "")
		return
	}
	if r.PostFormValue("back") == "customer" {
		http.Redirect(w, r, fmt.Sprintf("/customers/%d", cid), http.StatusSeeOther)
		return
	}
	notice := "Rol zaten vardı: " + role.Name
	if created {
		notice = "Rol oluşturuldu: " + role.Name
	}
	s.renderPG(w, r, http.StatusOK, pgsql.CreateInput{}, "", notice)
}

func (s *Server) pgRoleAction(w http.ResponseWriter, r *http.Request) {
	id, ok := pathID(r)
	if !ok {
		http.NotFound(w, r)
		return
	}
	ctx := r.Context()
	role, err := s.PG.Store.Role(ctx, id)
	if err != nil {
		http.NotFound(w, r)
		return
	}
	entry := logs.Entry{TargetType: "customer", TargetID: strconv.FormatInt(role.CustomerID, 10)}
	var notice string
	switch r.PathValue("action") {
	case "password":
		entry.Action, entry.Summary = "pg.role.password", "PostgreSQL rol şifresi sıfırlandı: "+role.Name
		act := s.Activity.Begin(ctx, entry, nil)
		var updated []string
		updated, err = s.PG.ResetPassword(ctx, id)
		act.Finish(err)
		notice = "Yeni şifre oluşturuldu (bağlantı bilgisinden görüntüleyebilirsiniz)."
		if len(updated) > 0 {
			notice += " Ortam değişkeni güncellenen siteler: " + strings.Join(updated, ", ") + " — yeni şifreyi kullanmaları için yeniden başlatın."
		}
	case "enable", "disable":
		enable := r.PathValue("action") == "enable"
		entry.Action, entry.Summary = "pg.role."+r.PathValue("action"), "PostgreSQL rolü devre dışı bırakıldı: "+role.Name
		if enable {
			entry.Summary = "PostgreSQL rolü etkinleştirildi: " + role.Name
		}
		act := s.Activity.Begin(ctx, entry, nil)
		err = s.PG.SetRoleEnabled(ctx, id, enable)
		act.Finish(err)
		notice = entry.Summary
	case "delete":
		entry.Action, entry.Summary = "pg.role.delete", "PostgreSQL rolü silindi: "+role.Name
		act := s.Activity.Begin(ctx, entry, nil)
		_, err = s.PG.DropRole(ctx, id)
		act.Finish(err)
		notice = entry.Summary
	default:
		http.NotFound(w, r)
		return
	}
	if err != nil {
		s.renderPG(w, r, http.StatusBadRequest, pgsql.CreateInput{}, "İşlem başarısız: "+err.Error(), "")
		return
	}
	s.renderPG(w, r, http.StatusOK, pgsql.CreateInput{}, "", notice)
}

func (s *Server) pgServerRelocate(w http.ResponseWriter, r *http.Request) {
	if r.PostFormValue("confirm") != relocateConfirm {
		s.pgJobRedirect(w, r, 0, errors.New("onay için "+relocateConfirm+" yazın"))
		return
	}
	id, err := s.PG.StartRelocate(r.Context())
	s.pgJobRedirect(w, r, id, err)
}

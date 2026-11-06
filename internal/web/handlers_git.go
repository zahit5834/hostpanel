package web

import (
	"database/sql"
	"errors"
	"fmt"
	"net/http"

	"hostpanel/internal/sites"
)

// gitTabData fills the Git card of the Deploy tab.
func (s *Server) gitTabData(r *http.Request, d *siteData) {
	d.GitDefaults = sites.GitDefaults(d.Site.RuntimeID)
	g, err := s.Sites.Store.Git(r.Context(), d.Site.ID)
	switch {
	case err == nil:
		if d.Git.RepoURL == "" {
			d.Git = g
		}
		d.GitSet = true
		d.GitInfo = s.Sites.GitInfo(r.Context(), d.Site)
	case errors.Is(err, sql.ErrNoRows):
		if d.Git.RepoURL == "" {
			d.Git = d.GitDefaults
		}
	}
}

func (s *Server) siteGitSave(w http.ResponseWriter, r *http.Request) {
	site, ok := s.loadSite(w, r)
	if !ok {
		return
	}
	g := sites.GitSettings{RepoURL: r.PostFormValue("repo_url"), Branch: r.PostFormValue("branch"),
		BuildCommand: r.PostFormValue("build_command"), OutputDir: r.PostFormValue("output_dir"),
		BuildTimeout: formInt(r, "build_timeout", sites.DefaultBuildTimeout)}
	if _, err := s.Sites.SaveGit(r.Context(), site, g); err != nil {
		s.renderSiteWith(w, r, http.StatusBadRequest, site, "deploy", err.Error(), func(d *siteData) { d.Git = g })
		return
	}
	http.Redirect(w, r, fmt.Sprintf("/sites/%d?tab=deploy#git", site.ID), http.StatusSeeOther)
}

func (s *Server) siteGitKeygen(w http.ResponseWriter, r *http.Request) {
	site, ok := s.loadSite(w, r)
	if !ok {
		return
	}
	if _, err := s.Sites.GitKeygen(r.Context(), site); err != nil {
		s.renderSite(w, r, http.StatusBadRequest, site, "deploy", err.Error(), "")
		return
	}
	s.renderSite(w, r, http.StatusOK, site, "deploy", "", "Yeni deploy key üretildi; eski anahtar artık çalışmaz. Public key'i repo'nun Deploy keys bölümüne ekleyin.")
}

func (s *Server) siteGitHostKeyReset(w http.ResponseWriter, r *http.Request) {
	site, ok := s.loadSite(w, r)
	if !ok {
		return
	}
	if err := s.Sites.GitResetHostKey(r.Context(), site); err != nil {
		s.renderSite(w, r, http.StatusBadRequest, site, "deploy", err.Error(), "")
		return
	}
	s.renderSite(w, r, http.StatusOK, site, "deploy", "", "Host anahtarı kaydı silindi; bir sonraki deploy'da sunucunun anahtarı yeniden kabul edilir.")
}

func (s *Server) siteGitDeploy(w http.ResponseWriter, r *http.Request) {
	site, ok := s.loadSite(w, r)
	if !ok {
		return
	}
	jobID, err := s.Sites.StartGitDeploy(r.Context(), site)
	if err != nil {
		s.renderSite(w, r, http.StatusBadRequest, site, "deploy", err.Error(), "")
		return
	}
	http.Redirect(w, r, fmt.Sprintf("/sites/%d?tab=deploy&job=%d", site.ID, jobID), http.StatusSeeOther)
}

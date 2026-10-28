package ui

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"net/http"

	"github.com/geodro/lerd/internal/cli"
	"github.com/geodro/lerd/internal/config"
	"github.com/geodro/lerd/internal/shareaccess"
	"github.com/geodro/lerd/internal/siteops"
)

func handleShareAccess(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	if !hasHostActionAuthority(r) {
		http.Error(w, "forbidden", 403)
		return
	}
	if r.Method != http.MethodGet && r.Method != http.MethodPut {
		w.Header().Set("Allow", "GET, PUT")
		http.Error(w, "method not allowed", 405)
		return
	}
	if r.Method == http.MethodGet && r.URL.Query().Get("export") == "1" {
		policies, err := cli.ShareAccessStore().Export()
		if err != nil {
			http.Error(w, "policies unavailable", 503)
			return
		}
		writeJSON(w, map[string]any{"version": 1, "policies": policies})
		return
	}
	siteName, branch := r.URL.Query().Get("site"), r.URL.Query().Get("branch")
	site, err := config.FindSite(siteName)
	if err != nil {
		http.Error(w, "site not found", 404)
		return
	}
	if branch != "" {
		if _, err = siteops.WorktreeDomain(site, branch); err != nil {
			http.Error(w, "worktree not found", 404)
			return
		}
	}
	store := cli.ShareAccessStore()
	if r.Method == http.MethodGet {
		p, e := store.Get(siteName, branch)
		if e != nil {
			http.Error(w, "policy unavailable", 503)
			return
		}
		writeJSON(w, p)
		return
	}
	if !passesCSRF(r) {
		http.Error(w, "forbidden", 403)
		return
	}
	data, err := io.ReadAll(http.MaxBytesReader(w, r.Body, 64<<10))
	if err != nil {
		http.Error(w, "invalid policy body", 400)
		return
	}
	var fields map[string]json.RawMessage
	if json.Unmarshal(data, &fields) != nil || fields["revision"] == nil || bytes.Equal(bytes.TrimSpace(fields["revision"]), []byte("null")) {
		http.Error(w, "revision is required", 400)
		return
	}
	var u shareaccess.Update
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	if dec.Decode(&u) != nil || u.Site != siteName || u.Branch != branch {
		http.Error(w, "invalid policy or target mismatch", 400)
		return
	}
	p, err := store.Put(u)
	if errors.Is(err, shareaccess.ErrConflict) {
		http.Error(w, "policy revision conflict", 409)
		return
	}
	if err != nil {
		http.Error(w, "policy rejected", 400)
		return
	}
	writeJSON(w, p)
}

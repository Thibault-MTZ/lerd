package ui

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/geodro/lerd/internal/config"
)

func TestShareAccessAPI(t *testing.T) {
	t.Setenv("XDG_CONFIG_HOME", t.TempDir())
	t.Setenv("XDG_DATA_HOME", t.TempDir())
	if err := config.AddSite(config.Site{Name: "demo", Domains: []string{"demo.test"}, Path: t.TempDir()}); err != nil {
		t.Fatal(err)
	}
	call := func(method, query, body string) *httptest.ResponseRecorder {
		r := httptest.NewRequest(method, "/api/share-access?"+query, strings.NewReader(body))
		r.RemoteAddr = "127.0.0.1:123"
		r.Header.Set("X-Lerd-CSRF", "1")
		w := httptest.NewRecorder()
		handleShareAccess(w, r)
		return w
	}
	w := call("GET", "site=demo", "")
	if w.Code != 200 {
		t.Fatal(w.Code)
	}
	var p map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &p); err != nil {
		t.Fatal(err)
	}
	if p["branch"] != "" || p["mode"] != "closed" || p["users"] == nil || p["networks"] == nil {
		t.Fatal(p)
	}
	body := `{"site":"demo","branch":"","mode":"password","networks":[],"credentials":[{"username":"reader","password":"secret password"}],"rate":{"requests_per_second":0,"burst":60},"revision":0}`
	w = call("PUT", "site=demo", body)
	if w.Code != 200 {
		t.Fatalf("put %d %s", w.Code, w.Body.String())
	}
	if strings.Contains(w.Body.String(), "secret password") || strings.Contains(w.Body.String(), "$2") {
		t.Fatal("credential leak")
	}
	if w = call("PUT", "site=demo", body); w.Code != 409 {
		t.Fatal(w.Code)
	}
	if w = call("GET", "site=unknown", ""); w.Code != 404 {
		t.Fatal(w.Code)
	}
	if w = call("GET", "site=demo&branch=unknown", ""); w.Code != 404 {
		t.Fatal(w.Code)
	}
	r := httptest.NewRequest(http.MethodPut, "/api/share-access?site=demo", strings.NewReader(body))
	r.RemoteAddr = "127.0.0.1:123"
	w = httptest.NewRecorder()
	handleShareAccess(w, r)
	if w.Code != 403 {
		t.Fatal("missing CSRF", w.Code)
	}
	site, _ := config.FindSite("demo")
	if site.PublicPort != 0 {
		t.Fatal("policy published site")
	}
}

func TestShareAccessWorktreeInheritanceAPI(t *testing.T) {
	t.Setenv("XDG_CONFIG_HOME", t.TempDir())
	t.Setenv("XDG_DATA_HOME", t.TempDir())
	main := t.TempDir()
	checkout := filepath.Join(t.TempDir(), "worktree")
	meta := filepath.Join(main, ".git", "worktrees", "feature-a")
	for _, dir := range []string{filepath.Join(main, ".git"), filepath.Join(meta), checkout} {
		if err := os.MkdirAll(dir, 0700); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(filepath.Join(meta, "HEAD"), []byte("ref: refs/heads/feature-a\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(meta, "gitdir"), []byte(filepath.Join(checkout, ".git")+"\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(checkout, ".git"), []byte("gitdir: "+meta+"\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := config.AddSite(config.Site{Name: "demo", Domains: []string{"demo.test"}, Path: main}); err != nil {
		t.Fatal(err)
	}
	call := func(method, branch, body string) *httptest.ResponseRecorder {
		r := httptest.NewRequest(method, "/api/share-access?site=demo&branch="+branch, strings.NewReader(body))
		r.RemoteAddr = "127.0.0.1:123"
		r.Header.Set("X-Lerd-CSRF", "1")
		w := httptest.NewRecorder()
		handleShareAccess(w, r)
		return w
	}
	root := call(http.MethodGet, "", "")
	if root.Code != 200 {
		t.Fatal(root.Code, root.Body.String())
	}
	if got := call(http.MethodPut, "", `{"site":"demo","branch":"","mode":"public","networks":[],"rate":{"requests_per_second":0,"burst":60},"revision":0}`); got.Code != 200 {
		t.Fatal(got.Code, got.Body.String())
	}
	branch := call(http.MethodGet, "feature-a", "")
	var policy map[string]any
	if err := json.Unmarshal(branch.Body.Bytes(), &policy); err != nil || branch.Code != 200 || policy["inherited"] != true || policy["mode"] != "public" || policy["parent_revision"] != float64(1) || policy["revision"] != float64(0) {
		t.Fatalf("inherited GET: status=%d policy=%v err=%v", branch.Code, policy, err)
	}
	body := `{"site":"demo","branch":"feature-a","mode":"closed","networks":[],"rate":{"requests_per_second":0,"burst":60},"revision":0,"parent_revision":1}`
	if got := call(http.MethodPut, "feature-a", body); got.Code != 200 {
		t.Fatal(got.Code, got.Body.String())
	}
	if got := call(http.MethodPut, "", `{"site":"demo","branch":"","mode":"public","networks":[],"rate":{"requests_per_second":0,"burst":60},"revision":1}`); got.Code != 200 {
		t.Fatal("parent update failed", got.Code, got.Body.String())
	}
	if got := call(http.MethodPut, "feature-a", `{"site":"demo","branch":"feature-a","inherit":true,"revision":1,"parent_revision":1}`); got.Code != 409 {
		t.Fatalf("stale parent revision status=%d body=%s", got.Code, got.Body.String())
	}
	if got := call(http.MethodPut, "feature-a", `{"site":"demo","branch":"feature-a","inherit":true,"revision":1,"parent_revision":2}`); got.Code != 200 {
		t.Fatal("reset failed", got.Code, got.Body.String())
	}
	reset := call(http.MethodGet, "feature-a", "")
	if err := json.Unmarshal(reset.Body.Bytes(), &policy); err != nil || reset.Code != 200 || policy["inherited"] != true || policy["mode"] != "public" || policy["revision"] != float64(2) {
		t.Fatalf("reset GET: status=%d policy=%v err=%v", reset.Code, policy, err)
	}
	stale := call(http.MethodPut, "feature-a", `{"site":"demo","branch":"feature-a","mode":"public","networks":[],"rate":{"requests_per_second":0,"burst":60},"revision":0,"parent_revision":2}`)
	if stale.Code != 409 {
		t.Fatalf("stale pre-reset revision status=%d body=%s", stale.Code, stale.Body.String())
	}
}

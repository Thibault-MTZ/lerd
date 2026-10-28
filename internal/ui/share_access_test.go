package ui

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
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

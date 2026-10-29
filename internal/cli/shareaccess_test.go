package cli

import (
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"testing"

	"github.com/geodro/lerd/internal/config"
	"github.com/geodro/lerd/internal/shareaccess"
)

func TestPublicPortAndIngressCannotBypassPolicy(t *testing.T) {
	t.Setenv("XDG_CONFIG_HOME", t.TempDir())
	t.Setenv("XDG_DATA_HOME", t.TempDir())
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Host != "demo.test" {
			t.Error(r.Host)
		}
		if r.Header.Get("X-Forwarded-For") != "192.0.2.12" {
			t.Error("unclean visitor header", r.Header.Get("X-Forwarded-For"))
		}
		w.WriteHeader(204)
	}))
	defer backend.Close()
	target, _ := url.Parse(backend.URL)
	_, p, _ := net.SplitHostPort(target.Host)
	port, _ := strconv.Atoi(p)
	cfg, err := config.LoadGlobal()
	if err != nil {
		t.Fatal(err)
	}
	cfg.Nginx.HTTPPort = port
	cfg.Share.PublicBaseDomain = "dev.example.com"
	if err = config.SaveGlobal(cfg); err != nil {
		t.Fatal(err)
	}
	if err = config.AddSite(config.Site{Name: "demo", Domains: []string{"demo.test"}, Path: t.TempDir(), PublicPort: 19300}); err != nil {
		t.Fatal(err)
	}
	srv, err := startPublicShareProxyFor("demo.test", 0, false, "demo", "")
	if err != nil {
		t.Fatal(err)
	}
	defer srv.Close()
	publicShareMu.Lock()
	publicShareServers["demo"] = srv
	publicShareMu.Unlock()
	defer func() { publicShareMu.Lock(); delete(publicShareServers, "demo"); publicShareMu.Unlock() }()
	ingress := httptest.NewServer(http.HandlerFunc(servePublicIngress))
	defer ingress.Close()
	_, bound, _ := net.SplitHostPort(srv.Addr)
	call := func(endpoint string) int {
		req, _ := http.NewRequest("GET", endpoint, nil)
		req.Host = "demo.dev.example.com"
		req.Header.Set("X-Forwarded-For", "192.0.2.12")
		res, e := http.DefaultClient.Do(req)
		if e != nil {
			t.Fatal(e)
		}
		defer res.Body.Close()
		return res.StatusCode
	}
	direct := "http://127.0.0.1:" + bound
	for _, endpoint := range []string{direct, ingress.URL} {
		if got := call(endpoint); got != 403 {
			t.Fatal("missing policy", got)
		}
	}
	if _, err = ShareAccessStore().Put(shareaccess.Update{Site: "demo", Mode: "ip", Networks: []string{"192.0.2.0/24"}, Rate: shareaccess.Rate{Burst: 60}}); err != nil {
		t.Fatal(err)
	}
	for _, endpoint := range []string{direct, ingress.URL} {
		if got := call(endpoint); got != 403 {
			t.Fatal("untrusted forwarding bypass", got)
		}
	}
	cfg.Share.TrustedProxies = []string{"127.0.0.1/32"}
	if err = config.SaveGlobal(cfg); err != nil {
		t.Fatal(err)
	}
	for _, endpoint := range []string{direct, ingress.URL} {
		if got := call(endpoint); got != 204 {
			t.Fatal("trusted request", got)
		}
	}
}

func TestPublicIngressAndDirectHandlerSharePolicy(t *testing.T) {
	t.Setenv("XDG_CONFIG_HOME", t.TempDir())
	t.Setenv("XDG_DATA_HOME", t.TempDir())
	if _, err := SetPublicBaseDomain("dev.example.com"); err != nil {
		t.Fatal(err)
	}
	if err := config.AddSite(config.Site{Name: "demo", Domains: []string{"demo.test"}, Path: t.TempDir(), PublicPort: 19300, WorktreePublicPorts: map[string]int{"feature/a": 19301}}); err != nil {
		t.Fatal(err)
	}
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(204) })
	store := ShareAccessStore()
	main := store.Middleware("demo", "", shareTrustedProxies, next)
	branch := store.Middleware("demo", "feature/a", shareTrustedProxies, next)
	publicShareMu.Lock()
	publicShareServers["demo"] = &http.Server{Handler: main}
	publicShareServers[publicWorktreeKey("demo", "feature/a")] = &http.Server{Handler: branch}
	publicShareMu.Unlock()
	t.Cleanup(func() {
		publicShareMu.Lock()
		delete(publicShareServers, "demo")
		delete(publicShareServers, publicWorktreeKey("demo", "feature/a"))
		publicShareMu.Unlock()
	})
	request := func(handler http.Handler, host string) int {
		r := httptest.NewRequest("GET", "http://"+host+"/", nil)
		r.RemoteAddr = "192.0.2.12:123"
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, r)
		return w.Code
	}
	ingress := http.HandlerFunc(servePublicIngress)
	if got := request(ingress, "demo.dev.example.com"); got != 403 {
		t.Fatal(got)
	}
	if _, err := store.Put(shareaccess.Update{Site: "demo", Mode: "ip", Networks: []string{"192.0.2.0/24"}, Rate: shareaccess.Rate{Burst: 60}}); err != nil {
		t.Fatal(err)
	}
	for _, handler := range []http.Handler{main, ingress} {
		if got := request(handler, "demo.dev.example.com"); got != 204 {
			t.Fatalf("allowed: %d", got)
		}
	}
	if got := request(ingress, "unknown.dev.example.com"); got != 403 {
		t.Fatalf("unknown host: %d", got)
	}
	// A registered worktree without an override follows its parent's IP rule.
	for _, handler := range []http.Handler{branch, ingress} {
		if got := request(handler, "demo-feature-a.dev.example.com"); got != 204 {
			t.Fatalf("inherited: %d", got)
		}
	}
	parent, err := store.Get("demo", "")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.Put(shareaccess.Update{Site: "demo", Branch: "feature/a", Mode: "closed", ParentRevision: &parent.Revision, Rate: shareaccess.Rate{Burst: 60}}); err != nil {
		t.Fatal(err)
	}
	for _, handler := range []http.Handler{branch, ingress} {
		if got := request(handler, "demo-feature-a.dev.example.com"); got != 403 {
			t.Fatalf("closed override: %d", got)
		}
	}
	// Registry entries alone cannot keep a stopped listener reachable.
	publicShareMu.Lock()
	delete(publicShareServers, "demo")
	publicShareMu.Unlock()
	if got := request(ingress, "demo.dev.example.com"); got != 403 {
		t.Fatal(got)
	}
}

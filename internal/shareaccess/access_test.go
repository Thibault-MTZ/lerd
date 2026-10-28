package shareaccess

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestPolicyValidationAndCAS(t *testing.T) {
	s := NewStore(filepath.Join(t.TempDir(), "policies.json"))
	p, err := s.Get("demo", "")
	if err != nil || p.Mode != "closed" || p.Revision != 0 {
		t.Fatalf("default: %+v %v", p, err)
	}
	u := Update{Site: "demo", Mode: "ip_and_password", Networks: []string{"192.0.2.0/24"}, Credentials: []Credential{{Username: "reader", Password: "a strong password"}}, Rate: Rate{Burst: 60}}
	p, err = s.Put(u)
	if err != nil || p.Revision != 1 || len(p.Users) != 1 {
		t.Fatalf("put: %+v %v", p, err)
	}
	if _, err = s.Put(u); err != ErrConflict {
		t.Fatalf("missing CAS conflict: %v", err)
	}
	u.Revision = 1
	u.Networks = []string{"invalid"}
	if _, err = s.Put(u); err == nil {
		t.Fatal("invalid CIDR accepted")
	}
	data, _ := os.ReadFile(s.path)
	if strings.Contains(string(data), "a strong password") {
		t.Fatal("clear password persisted")
	}
	info, _ := os.Stat(s.path)
	if info.Mode().Perm() != 0600 {
		t.Fatal("unsafe file permissions")
	}
}

func TestMiddlewareTrustAuthAndRate(t *testing.T) {
	s := NewStore(filepath.Join(t.TempDir(), "policies.json"))
	_, err := s.Put(Update{Site: "demo", Branch: "feature/a", Mode: "ip_and_password", Networks: []string{"192.0.2.0/24"}, Credentials: []Credential{{Username: "reader", Password: "secret password"}}, Rate: Rate{RequestsPerSecond: 0.001, Burst: 1}})
	if err != nil {
		t.Fatal(err)
	}
	h := s.Middleware("demo", "feature/a", func() ([]string, error) { return []string{"127.0.0.1/32"}, nil }, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "" {
			t.Error("share credential leaked to application")
		}
		w.WriteHeader(204)
	}))
	call := func(peer, ip, password string) *httptest.ResponseRecorder {
		r := httptest.NewRequest("GET", "http://demo.example/", nil)
		r.RemoteAddr = peer
		r.Header.Set("X-Forwarded-For", ip)
		if password != "" {
			r.SetBasicAuth("reader", password)
		}
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		return w
	}
	if w := call("198.51.100.4:10", "192.0.2.1", "secret password"); w.Code != 403 {
		t.Fatalf("spoof: %d", w.Code)
	}
	if w := call("127.0.0.1:10", "192.0.2.1, 198.51.100.1", "secret password"); w.Code != 403 {
		t.Fatalf("ambiguous IP: %d", w.Code)
	}
	if w := call("127.0.0.1:10", "192.0.2.2", ""); w.Code != 401 {
		t.Fatalf("auth: %d", w.Code)
	}
	if w := call("127.0.0.1:10", "192.0.2.1", "secret password"); w.Code != 204 {
		t.Fatalf("valid: %d", w.Code)
	}
	if w := call("127.0.0.1:10", "192.0.2.1", "secret password"); w.Code != 429 || w.Header().Get("Retry-After") == "" {
		t.Fatalf("rate: %d", w.Code)
	}
	// Another branch cannot inherit credentials or permissive mode.
	other := s.Middleware("demo", "feature/b", func() ([]string, error) { return nil, nil }, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { t.Error("closed branch reached backend") }))
	w := httptest.NewRecorder()
	other.ServeHTTP(w, httptest.NewRequest("GET", "http://demo.example/", nil))
	if w.Code != 403 {
		t.Fatal(w.Code)
	}
	if err := os.WriteFile(s.path, []byte("broken"), 0600); err != nil {
		t.Fatal(err)
	}
	if w := call("127.0.0.1:10", "192.0.2.2", "secret password"); w.Code != 403 {
		t.Fatalf("corrupt store did not close: %d", w.Code)
	}
}

func TestModesAreIndependentAndDefaultClosed(t *testing.T) {
	for _, mode := range []string{"closed", "public", "ip", "password", "ip_and_password", "ip_or_password"} {
		t.Run(mode, func(t *testing.T) {
			s := NewStore(filepath.Join(t.TempDir(), "access.json"))
			_, err := s.Put(Update{Site: "demo", Mode: mode, Networks: []string{"192.0.2.0/24"}, Credentials: []Credential{{Username: "reader", Password: "secret password"}}, Rate: Rate{Burst: 60}})
			if err != nil {
				t.Fatal(err)
			}
			h := s.Middleware("demo", "", func() ([]string, error) { return nil, nil }, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(204) }))
			for _, test := range []struct {
				ip, secret   string
				ipOK, authOK bool
			}{{"192.0.2.1", "secret password", true, true}, {"192.0.2.1", "wrong", true, false}, {"198.51.100.1", "secret password", false, true}, {"198.51.100.1", "", false, false}} {
				r := httptest.NewRequest("GET", "http://demo.example/", nil)
				r.RemoteAddr = test.ip + ":123"
				if test.secret != "" {
					r.SetBasicAuth("reader", test.secret)
				}
				w := httptest.NewRecorder()
				h.ServeHTTP(w, r)
				want := mode == "public" || mode == "ip" && test.ipOK || mode == "password" && test.authOK || mode == "ip_and_password" && test.ipOK && test.authOK || mode == "ip_or_password" && (test.ipOK || test.authOK)
				if (w.Code == 204) != want {
					t.Fatalf("%s ip=%v auth=%v code=%d", mode, test.ipOK, test.authOK, w.Code)
				}
			}
		})
	}
}

func TestAllowedIPPreservesApplicationBearer(t *testing.T) {
	s := NewStore(filepath.Join(t.TempDir(), "access.json"))
	_, err := s.Put(Update{Site: "demo", Mode: "ip_or_password", Networks: []string{"192.0.2.0/24"}, Credentials: []Credential{{Username: "reader", Password: "secret password"}}, Rate: Rate{Burst: 60}})
	if err != nil {
		t.Fatal(err)
	}
	h := s.Middleware("demo", "", func() ([]string, error) { return nil, nil }, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer application-token" {
			t.Error("application authorization removed")
		}
		w.WriteHeader(204)
	}))
	r := httptest.NewRequest("GET", "http://demo.example/", nil)
	r.RemoteAddr = "192.0.2.1:123"
	r.Header.Set("Authorization", "Bearer application-token")
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	if w.Code != 204 {
		t.Fatal(w.Code)
	}
}

func TestExportHasNoSecretsAndInvalidUpdatePreservesPolicy(t *testing.T) {
	s := NewStore(filepath.Join(t.TempDir(), "access.json"))
	_, err := s.Put(Update{Site: "demo", Mode: "password", Credentials: []Credential{{Username: "reader", Password: "secret password"}}, Rate: Rate{Burst: 60}})
	if err != nil {
		t.Fatal(err)
	}
	for _, u := range []Update{{Site: "demo", Revision: 1, Mode: "ip", Rate: Rate{Burst: 60}}, {Site: "demo", Revision: 1, Mode: "password", RemoveUsers: []string{"reader"}, Rate: Rate{Burst: 60}}, {Site: "demo", Revision: 1, Mode: "public", Rate: Rate{Burst: 0}}} {
		if _, err = s.Put(u); err == nil {
			t.Fatal("invalid update accepted")
		}
	}
	p, _ := s.Get("demo", "")
	if p.Revision != 1 || p.Mode != "password" {
		t.Fatal(p)
	}
	exported, err := s.Export()
	if err != nil || len(exported) != 1 {
		t.Fatal(err)
	}
	data, _ := json.Marshal(exported)
	if strings.Contains(string(data), "$2") || strings.Contains(string(data), "secret password") || strings.Contains(string(data), "password_hashes") {
		t.Fatal("export leaked credentials")
	}
}

package shareaccess

import (
	"encoding/json"
	"golang.org/x/crypto/bcrypt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestNewPasswordsAcceptNonemptyUTF8OfAnyLength(t *testing.T) {
	for _, secret := range []string{"x", "é", " ", strings.Repeat("密", 40), strings.Repeat("x", 128)} {
		s := NewStore(filepath.Join(t.TempDir(), "access.json"))
		_, err := s.Put(Update{Site: "demo", Mode: "password", Credentials: []Credential{{Username: "reader", Password: secret}}, Rate: Rate{Burst: 60}})
		if err != nil {
			t.Fatalf("%d bytes: %v", len(secret), err)
		}
		d, _ := s.read()
		hash := d.Policies[key("demo", "")].Hashes["reader"]
		if !strings.HasPrefix(hash, "$lerd$sha256-bcrypt$v1$") {
			t.Fatal("unversioned new credential")
		}
		h := s.Middleware("demo", "", func() ([]string, error) { return nil, nil }, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(204) }))
		r := httptest.NewRequest("GET", "http://demo.example/", nil)
		r.RemoteAddr = "192.0.2.1:123"
		r.SetBasicAuth("reader", secret)
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		if w.Code != 204 {
			t.Fatalf("%d bytes auth: %d", len(secret), w.Code)
		}
	}
}

func TestLegacyBcryptCredentialsStillAuthenticate(t *testing.T) {
	s := NewStore(filepath.Join(t.TempDir(), "access.json"))
	raw, err := bcrypt.GenerateFromPassword([]byte("legacy password"), bcrypt.MinCost)
	if err != nil {
		t.Fatal(err)
	}
	p := defaultPolicy("demo", "")
	p.Mode = "password"
	p.Revision = 1
	p.Users = []User{{Username: "reader"}}
	d := document{Version: 1, Policies: map[string]record{key("demo", ""): {Policy: p, Hashes: map[string]string{"reader": string(raw)}}}}
	data, _ := json.Marshal(d)
	if err = os.WriteFile(s.path, data, 0600); err != nil {
		t.Fatal(err)
	}
	h := s.Middleware("demo", "", func() ([]string, error) { return nil, nil }, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(204) }))
	r := httptest.NewRequest("GET", "http://demo.example/", nil)
	r.RemoteAddr = "192.0.2.1:123"
	r.SetBasicAuth("reader", "legacy password")
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	if w.Code != 204 {
		t.Fatal(w.Code)
	}
	if _, err = s.Put(Update{Site: "demo", Mode: "password", Revision: 1, Credentials: []Credential{{Username: "reader", Password: ""}}, Rate: Rate{Burst: 60}}); err == nil {
		t.Fatal("empty password accepted")
	}
}

func TestDenialStatusDefaultsAndHidesDeniedContent(t *testing.T) {
	s := NewStore(filepath.Join(t.TempDir(), "access.json"))
	p, err := s.Get("demo", "")
	if err != nil || p.DenialStatus != 403 {
		t.Fatalf("default: %+v %v", p, err)
	}
	for _, mode := range []string{"closed", "ip", "password"} {
		p, err = s.Put(Update{Site: "demo", Mode: mode, Networks: []string{"192.0.2.0/24"}, Credentials: []Credential{{Username: "reader", Password: "x"}}, Rate: Rate{Burst: 60}, Revision: p.Revision, DenialStatus: 404})
		if err != nil {
			t.Fatal(err)
		}
		h := s.Middleware("demo", "", func() ([]string, error) { return nil, nil }, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { t.Fatal("denied request reached private content") }))
		r := httptest.NewRequest("GET", "http://demo.example/", nil)
		r.RemoteAddr = "198.51.100.1:123"
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		want := 404
		if mode == "password" {
			want = 401
		}
		if w.Code != want {
			t.Fatalf("mode=%s code=%d", mode, w.Code)
		}
		if want == 404 && w.Body.String() != "404 page not found\n" {
			t.Fatal("non-neutral denial body", w.Body.String())
		}
	}
	data, _ := os.ReadFile(s.path)
	var doc map[string]any
	_ = json.Unmarshal(data, &doc)
	for _, entry := range doc["policies"].(map[string]any) {
		delete(entry.(map[string]any)["policy"].(map[string]any), "denial_status")
	}
	data, _ = json.Marshal(doc)
	if err = os.WriteFile(s.path, data, 0600); err != nil {
		t.Fatal(err)
	}
	p, err = s.Get("demo", "")
	if err != nil || p.DenialStatus != 403 {
		t.Fatalf("legacy: %+v %v", p, err)
	}
	if _, err = s.Put(Update{Site: "demo", Mode: "closed", Rate: Rate{Burst: 60}, Revision: p.Revision, DenialStatus: 200}); err == nil {
		t.Fatal("invalid denial code accepted")
	}
}

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
	parentRevision := uint64(0)
	_, err := s.Put(Update{Site: "demo", Branch: "feature/a", ParentRevision: &parentRevision, Mode: "ip_and_password", Networks: []string{"192.0.2.0/24"}, Credentials: []Credential{{Username: "reader", Password: "secret password"}}, Rate: Rate{RequestsPerSecond: 0.001, Burst: 1}})
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

func TestWorktreeInheritsParentChangesUntilOverride(t *testing.T) {
	s := NewStore(filepath.Join(t.TempDir(), "access.json"))
	parent, err := s.Put(Update{Site: "demo", Mode: "ip_and_password", Networks: []string{"192.0.2.0/24"}, Credentials: []Credential{{Username: "reader", Password: "parent secret"}}, Rate: Rate{RequestsPerSecond: 3, Burst: 9}, DenialStatus: 404})
	if err != nil {
		t.Fatal(err)
	}
	inherited, err := s.Get("demo", "feature-a")
	if err != nil || !inherited.Inherited || inherited.Revision != 0 || inherited.ParentRevision != parent.Revision || inherited.Mode != "ip_and_password" || inherited.DenialStatus != 404 || len(inherited.Users) != 1 || inherited.Users[0].Username != "reader" {
		t.Fatalf("inherited policy: %+v, %v", inherited, err)
	}

	parentRevision := inherited.ParentRevision
	branch, err := s.Put(Update{Site: "demo", Branch: "feature-a", ParentRevision: &parentRevision, Revision: inherited.Revision, Mode: "ip", Networks: []string{"198.51.100.0/24"}, Rate: Rate{RequestsPerSecond: 2, Burst: 4}})
	if err != nil || branch.Inherited || branch.Revision != 1 || branch.ParentRevision != parent.Revision || branch.Mode != "ip" || len(branch.Users) != 1 {
		t.Fatalf("branch override: %+v, %v", branch, err)
	}

	parent, err = s.Put(Update{Site: "demo", Revision: parent.Revision, Mode: "public", Rate: Rate{Burst: 60}})
	if err != nil {
		t.Fatal(err)
	}
	branch, err = s.Get("demo", "feature-a")
	if err != nil || branch.Inherited || branch.ParentRevision != parent.Revision || branch.Mode != "ip" || len(branch.Networks) != 1 || branch.Networks[0] != "198.51.100.0/24" || len(branch.Users) != 1 {
		t.Fatalf("parent edit changed override: %+v, %v", branch, err)
	}
}

func TestWorktreeResetInheritsCurrentParentAndKeepsCASGeneration(t *testing.T) {
	s := NewStore(filepath.Join(t.TempDir(), "access.json"))
	parent, err := s.Put(Update{Site: "demo", Mode: "ip", Networks: []string{"192.0.2.0/24"}, Rate: Rate{RequestsPerSecond: 1, Burst: 3}})
	if err != nil {
		t.Fatal(err)
	}
	parentRevision := parent.Revision
	branch, err := s.Put(Update{Site: "demo", Branch: "feature-a", ParentRevision: &parentRevision, Mode: "public", Rate: Rate{Burst: 60}})
	if err != nil {
		t.Fatal(err)
	}
	staleInheritedRevision := uint64(0)
	parent, err = s.Put(Update{Site: "demo", Revision: parent.Revision, Mode: "password", Credentials: []Credential{{Username: "owner", Password: "new parent secret"}}, Rate: Rate{Burst: 60}})
	if err != nil {
		t.Fatal(err)
	}
	parentRevision = parent.Revision
	reset, err := s.Put(Update{Site: "demo", Branch: "feature-a", Inherit: true, Revision: branch.Revision, ParentRevision: &parentRevision})
	if err != nil || !reset.Inherited || reset.Mode != "password" || reset.Revision != branch.Revision+1 || reset.ParentRevision != parent.Revision || len(reset.Users) != 1 || reset.Users[0].Username != "owner" {
		t.Fatalf("reset result: %+v, %v", reset, err)
	}
	if _, err = s.Put(Update{Site: "demo", Branch: "feature-a", Revision: staleInheritedRevision, ParentRevision: &parentRevision, Mode: "public", Rate: Rate{Burst: 60}}); err != ErrConflict {
		t.Fatalf("pre-reset inherited editor did not conflict: %v", err)
	}
	d, err := s.read()
	if err != nil || !d.Policies[key("demo", "feature-a")].Inherited || len(d.Policies[key("demo", "feature-a")].Hashes) != 0 {
		t.Fatalf("missing safe inheritance marker: %+v, %v", d.Policies[key("demo", "feature-a")], err)
	}
}

func TestWorktreeParentRevisionConflictDoesNotCreateOverride(t *testing.T) {
	s := NewStore(filepath.Join(t.TempDir(), "access.json"))
	parent, err := s.Put(Update{Site: "demo", Mode: "closed", Rate: Rate{Burst: 60}})
	if err != nil {
		t.Fatal(err)
	}
	inherited, _ := s.Get("demo", "feature-a")
	parent, err = s.Put(Update{Site: "demo", Revision: parent.Revision, Mode: "public", Rate: Rate{Burst: 60}})
	if err != nil {
		t.Fatal(err)
	}
	oldParentRevision := inherited.ParentRevision
	if _, err = s.Put(Update{Site: "demo", Branch: "feature-a", Revision: inherited.Revision, ParentRevision: &oldParentRevision, Mode: "public", Rate: Rate{Burst: 60}}); err != ErrConflict {
		t.Fatalf("stale parent revision accepted: %v", err)
	}
	branch, err := s.Get("demo", "feature-a")
	if err != nil || !branch.Inherited || branch.Mode != "public" || branch.ParentRevision != parent.Revision {
		t.Fatalf("stale write changed inherited branch: %+v, %v", branch, err)
	}
}

func TestClosedParentInheritsClosedAndDoesNotReachHandler(t *testing.T) {
	s := NewStore(filepath.Join(t.TempDir(), "access.json"))
	policy, err := s.Get("demo", "feature-a")
	if err != nil || !policy.Inherited || policy.Mode != "closed" || policy.ParentRevision != 0 {
		t.Fatalf("closed default: %+v, %v", policy, err)
	}
	h := s.Middleware("demo", "feature-a", func() ([]string, error) { return nil, nil }, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { t.Fatal("closed inherited share reached handler") }))
	w := httptest.NewRecorder()
	h.ServeHTTP(w, httptest.NewRequest("GET", "http://demo.example/", nil))
	if w.Code != 403 {
		t.Fatal(w.Code)
	}
}

func TestInheritedLegacyBcryptCredentialWorksInWorktree(t *testing.T) {
	s := NewStore(filepath.Join(t.TempDir(), "access.json"))
	hash, err := bcrypt.GenerateFromPassword([]byte("legacy parent password"), bcrypt.MinCost)
	if err != nil {
		t.Fatal(err)
	}
	p := defaultPolicy("demo", "")
	p.Mode = "password"
	p.Revision = 1
	p.Users = []User{{Username: "reader"}}
	d := document{Version: 1, Policies: map[string]record{key("demo", ""): {Policy: p, Hashes: map[string]string{"reader": string(hash)}}}}
	data, _ := json.Marshal(d)
	if err = os.WriteFile(s.path, data, 0600); err != nil {
		t.Fatal(err)
	}
	h := s.Middleware("demo", "feature-a", func() ([]string, error) { return nil, nil }, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(204) }))
	r := httptest.NewRequest("GET", "http://demo.example/", nil)
	r.RemoteAddr = "192.0.2.4:123"
	r.SetBasicAuth("reader", "legacy parent password")
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	if w.Code != 204 {
		t.Fatal(w.Code)
	}
}

func TestInheritedRateLimitIsAppliedPerWorktree(t *testing.T) {
	s := NewStore(filepath.Join(t.TempDir(), "access.json"))
	if _, err := s.Put(Update{Site: "demo", Mode: "public", Rate: Rate{RequestsPerSecond: 0.001, Burst: 1}}); err != nil {
		t.Fatal(err)
	}
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(204) })
	main := s.Middleware("demo", "", func() ([]string, error) { return nil, nil }, next)
	branch := s.Middleware("demo", "feature-a", func() ([]string, error) { return nil, nil }, next)
	call := func(h http.Handler) int {
		r := httptest.NewRequest("GET", "http://demo.example/", nil)
		r.RemoteAddr = "192.0.2.1:123"
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		return w.Code
	}
	if got := call(main); got != 204 {
		t.Fatal("first parent request", got)
	}
	if got := call(main); got != 429 {
		t.Fatal("parent quota was not enforced", got)
	}
	if got := call(branch); got != 204 {
		t.Fatal("branch did not inherit policy with an independent bucket", got)
	}
	if got := call(branch); got != 429 {
		t.Fatal("branch quota was not enforced", got)
	}
}

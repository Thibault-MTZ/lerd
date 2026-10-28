package ui

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"github.com/geodro/lerd/internal/plugins"
)

func TestSensitiveWriteOriginRejectsSibling(t *testing.T) {
	for _, test := range []struct {
		origin string
		want   bool
	}{{"https://app.example.test", false}, {"https://lerd.example.test", true}, {"http://lerd.example.test", false}, {"null", false}, {"", true}, {"http://lerd.localhost", true}} {
		r := httptest.NewRequest("POST", "http://lerd.example.test/api/plugins/echo/host", nil)
		r.Header.Set("X-Forwarded-For", "192.0.2.1")
		r.Header.Set("X-Forwarded-Proto", "https")
		r.Header.Set("Sec-Fetch-Site", "same-site")
		if test.origin != "" {
			r.Header.Set("Origin", test.origin)
		}
		if got := sameDashboardWriteOrigin(r); got != test.want {
			t.Errorf("%s: got %v", test.origin, got)
		}
	}
}

func TestSensitiveWriteOriginBehindLoopbackTLSProxy(t *testing.T) {
	for _, test := range []struct {
		peer, origin string
		want         bool
	}{
		{"127.0.0.1:123", "https://lerd.example.test", true},
		{"[::1]:123", "https://lerd.example.test", true},
		{"127.0.0.1:123", "https://app.example.test", false},
		{"192.0.2.5:123", "https://lerd.example.test", false},
	} {
		r := httptest.NewRequest("POST", "http://lerd.example.test/api/plugins/echo/host", nil)
		r.RemoteAddr = test.peer
		r.Header.Set("Origin", test.origin)
		r.Header.Set("X-Forwarded-Proto", "https")
		r.Header.Set("Sec-Fetch-Site", "same-site")
		if got := sameDashboardWriteOrigin(r); got != test.want {
			t.Errorf("peer=%s origin=%s got=%v", test.peer, test.origin, got)
		}
	}
}

func TestPluginSensitiveOriginStopsBeforeScript(t *testing.T) {
	installAPIPlugin(t)
	p, err := plugins.Find("echo")
	if err != nil {
		t.Fatal(err)
	}
	marker := filepath.Join(t.TempDir(), "ran")
	if err = os.WriteFile(filepath.Join(p.Dir, "bin", "say"), []byte("#!/bin/sh\ntouch '"+marker+"'\necho '{}'\n"), 0755); err != nil {
		t.Fatal(err)
	}
	r := httptest.NewRequest(http.MethodPost, "https://lerd.example.test/api/plugins/echo/host", nil)
	r.Header.Set("Origin", "https://app.example.test")
	r.Header.Set("Sec-Fetch-Site", "same-site")
	r.RemoteAddr = "127.0.0.1:123"
	w := httptest.NewRecorder()
	handlePluginAPI(w, r)
	if w.Code != 403 {
		t.Fatal(w.Code)
	}
	if _, err = os.Stat(marker); !os.IsNotExist(err) {
		t.Fatal("script invoked for sibling origin")
	}
	r = httptest.NewRequest(http.MethodPut, "https://lerd.example.test/api/share-access?site=demo", nil)
	r.Header.Set("Origin", "https://app.example.test")
	r.RemoteAddr = "127.0.0.1:123"
	w = httptest.NewRecorder()
	handleShareAccess(w, r)
	if w.Code != 403 {
		t.Fatal(w.Code)
	}
}

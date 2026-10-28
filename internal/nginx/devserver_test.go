package nginx

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"text/template"

	"github.com/geodro/lerd/internal/config"
)

// The dev server's whole point is one prefix carrying both assets and the
// hot-reload socket, so the location has to keep the upgrade headers.
func TestRenderVhost_devServerPrefixProxiesWithUpgrade(t *testing.T) {
	tmpl := sslVhostTemplate(t)
	data := VhostData{
		Domain:        "myapp.test",
		ServerNames:   "myapp.test",
		Path:          "/srv/myapp",
		PublicDir:     "public",
		FPMContainer:  "lerd-php84-fpm",
		CertDomain:    "myapp.test",
		UpstreamHost:  "192.0.2.1",
		DevServerBase: "/@lerd-vite/",
		DevServerPort: 5173,
	}

	out, err := renderVhost(tmpl, data)
	if err != nil {
		t.Fatalf("renderVhost: %v", err)
	}
	got := string(out)
	for _, want := range []string{
		"location ^~ /@lerd-vite/ {",
		"proxy_pass http://192.0.2.1:5173;",
		`proxy_set_header Upgrade $http_upgrade;`,
	} {
		if !strings.Contains(got, want) {
			t.Errorf("vhost missing %q:\n%s", want, got)
		}
	}
}

// A site with no dev server pinned must render exactly as it did before.
func TestRenderVhost_noDevServerNoLocations(t *testing.T) {
	tmpl := sslVhostTemplate(t)
	out, err := renderVhost(tmpl, VhostData{
		Domain:       "myapp.test",
		ServerNames:  "myapp.test",
		Path:         "/srv/myapp",
		PublicDir:    "public",
		FPMContainer: "lerd-php84-fpm",
		CertDomain:   "myapp.test",
	})
	if err != nil {
		t.Fatalf("renderVhost: %v", err)
	}
	if strings.Contains(string(out), "location ^~ ") {
		t.Errorf("unexpected dev server location:\n%s", out)
	}
}

func sslVhostTemplate(t *testing.T) *template.Template {
	t.Helper()
	raw, err := GetTemplate("vhost-ssl.conf.tmpl")
	if err != nil {
		t.Fatal(err)
	}
	tmpl, err := template.New("vhost").Parse(string(raw))
	if err != nil {
		t.Fatal(err)
	}
	return tmpl
}

// A stopped dev server must answer with a 502 the browser lets the page read,
// or a page on another of the site's domains only reports a CORS failure.
func TestRenderVhost_devServerDownAnswersReadable502(t *testing.T) {
	for _, name := range []string{"vhost.conf.tmpl", "vhost-ssl.conf.tmpl"} {
		raw, err := GetTemplate(name)
		if err != nil {
			t.Fatal(err)
		}
		tmpl := template.Must(template.New("vhost").Parse(string(raw)))
		out, err := renderVhost(tmpl, VhostData{
			Domain:        "myapp.test",
			ServerNames:   "myapp.test",
			Path:          "/srv/myapp",
			PublicDir:     "public",
			FPMContainer:  "lerd-php84-fpm",
			CertDomain:    "myapp.test",
			UpstreamHost:  "192.0.2.1",
			DevServerBase: "/@lerd-vite/",
			DevServerPort: 5173,
		})
		if err != nil {
			t.Fatalf("%s: renderVhost: %v", name, err)
		}
		got := string(out)
		for _, want := range []string{
			"error_page 502 = @lerd_dev_down;",
			"location @lerd_dev_down {",
			"add_header Access-Control-Allow-Origin * always;",
			"lerd worker list",
		} {
			if !strings.Contains(got, want) {
				t.Errorf("%s missing %q:\n%s", name, want, got)
			}
		}
	}
}

// A FrankenPHP or custom container site proxies everything else to its
// container, so without its own dev server location the app answers the
// prefix and the page loads with no assets.
func TestRenderContainerVhost_devServerPrefixAheadOfApp(t *testing.T) {
	tmp := t.TempDir()
	t.Setenv("XDG_CONFIG_HOME", tmp)
	t.Setenv("XDG_DATA_HOME", tmp)
	sitePath := t.TempDir()
	if err := os.MkdirAll(filepath.Join(sitePath, "node_modules", "vite"), 0755); err != nil {
		t.Fatal(err)
	}
	site := config.Site{Name: "myapp", Domains: []string{"myapp.test"}, Path: sitePath, DevServerPort: 5174}

	for _, ssl := range []bool{false, true} {
		out, err := renderContainerVhost(site, "lerd-fp-myapp", 8000, false, ssl)
		if err != nil {
			t.Fatalf("ssl=%v: renderContainerVhost: %v", ssl, err)
		}
		got := string(out)
		devAt := strings.Index(got, "location ^~ /@lerd-vite/ {")
		appAt := strings.Index(got, "location / {")
		if devAt < 0 || devAt > appAt {
			t.Errorf("ssl=%v: dev server location missing or after location /:\n%s", ssl, got)
		}
		for _, want := range []string{
			":5174;",
			"error_page 502 = @lerd_dev_down;",
			"location @lerd_dev_unprefixed {",
		} {
			if !strings.Contains(got, want) {
				t.Errorf("ssl=%v: vhost missing %q:\n%s", ssl, want, got)
			}
		}
	}
}

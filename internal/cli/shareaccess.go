package cli

import (
	"fmt"
	"net"
	"net/http"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/geodro/lerd/internal/config"
	gitpkg "github.com/geodro/lerd/internal/git"
	"github.com/geodro/lerd/internal/shareaccess"
)

var accessStores sync.Map

func ShareAccessStore() *shareaccess.Store {
	path := filepath.Join(config.ConfigDir(), "share-access.json")
	s, _ := accessStores.LoadOrStore(path, shareaccess.NewStore(path))
	return s.(*shareaccess.Store)
}
func shareTrustedProxies() ([]string, error) {
	cfg, err := config.LoadGlobal()
	if err != nil {
		return nil, err
	}
	return cfg.Share.TrustedProxies, nil
}

var publicIngressMu sync.Mutex
var publicIngress *http.Server

// StartPublicIngress shares the same protected handlers as the per-site ports.
// Unknown, inactive and colliding hostnames never reach an application.
func StartPublicIngress() error {
	cfg, err := config.LoadGlobal()
	if err != nil {
		return err
	}
	if cfg.Share.PublicListen == "" {
		return nil
	}
	publicIngressMu.Lock()
	defer publicIngressMu.Unlock()
	if publicIngress != nil {
		return nil
	}
	ln, err := net.Listen("tcp", cfg.Share.PublicListen)
	if err != nil {
		return fmt.Errorf("public ingress: %w", err)
	}
	publicIngress = &http.Server{Handler: http.HandlerFunc(servePublicIngress), ReadHeaderTimeout: 10 * time.Second, IdleTimeout: 90 * time.Second}
	go publicIngress.Serve(ln) //nolint:errcheck
	return nil
}
func StopPublicIngress() {
	publicIngressMu.Lock()
	defer publicIngressMu.Unlock()
	if publicIngress != nil {
		publicIngress.Close()
		publicIngress = nil
	}
}

func servePublicIngress(w http.ResponseWriter, r *http.Request) {
	cfg, err := config.LoadGlobal()
	if err != nil || cfg.Share.PublicBaseDomain == "" {
		http.Error(w, "Public share unavailable", 403)
		return
	}
	reg, err := config.LoadSites()
	if err != nil {
		http.Error(w, "Public share unavailable", 403)
		return
	}
	host := strings.ToLower(r.Host)
	if strings.Contains(host, ":") {
		h, _, e := net.SplitHostPort(host)
		if e != nil {
			http.Error(w, "Invalid host", 403)
			return
		}
		host = h
	}
	// Exactly one active target must own the hostname, including flattened worktrees.
	var target http.Handler
	matches := 0
	publicShareMu.Lock()
	for _, s := range reg.Sites {
		if s.Paused || s.Ignored {
			continue
		}
		if s.PublicPort != 0 && host == config.PublicShareHost(s.Name, cfg.Share.PublicBaseDomain) {
			if srv := publicShareServers[s.Name]; srv != nil {
				target = srv.Handler
				matches++
			}
		}
		for branch, port := range s.WorktreePublicPorts {
			if port != 0 && host == config.PublicShareWorktreeHost(s.Name, gitpkg.SanitizeBranch(branch), cfg.Share.PublicBaseDomain) {
				if srv := publicShareServers[publicWorktreeKey(s.Name, branch)]; srv != nil {
					target = srv.Handler
					matches++
				}
			}
		}
	}
	publicShareMu.Unlock()
	if matches != 1 {
		http.Error(w, "Public share not found", 403)
		return
	}
	target.ServeHTTP(w, r)
}

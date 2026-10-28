package ui

import (
	"net/http"
	"net/url"
	"strings"
)

// A sibling site is same-site in browsers, but cannot administer the dashboard.
// Local non-browser clients retain the existing CSRF/token requirement.
func sameDashboardWriteOrigin(r *http.Request) bool {
	if !unsafeMethod(r.Method) {
		return true
	}
	origins := r.Header.Values("Origin")
	if len(origins) == 0 {
		return true
	}
	if len(origins) != 1 {
		return false
	}
	origin := origins[0]
	u, err := url.Parse(origin)
	if err != nil || u.User != nil || u.RawQuery != "" || u.Fragment != "" || u.Path != "" || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
		return false
	}
	if allowedCORSOrigins[origin] {
		return true
	}
	scheme := "http"
	if r.TLS != nil {
		scheme = "https"
	} else if forwardedByProxy(r) && r.Header.Get("X-Forwarded-Proto") == "https" {
		scheme = "https"
	}
	return u.Scheme == scheme && strings.EqualFold(u.Host, r.Host)
}

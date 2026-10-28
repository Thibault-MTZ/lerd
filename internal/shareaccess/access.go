// Package shareaccess enforces portable access policies for native shares.
package shareaccess

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"net"
	"net/http"
	"net/netip"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/geodro/lerd/internal/config"
	"golang.org/x/crypto/bcrypt"
)

var ErrConflict = errors.New("policy revision conflict")

type Rate struct {
	RequestsPerSecond float64 `json:"requests_per_second"`
	Burst             int     `json:"burst"`
}
type User struct {
	Username string `json:"username"`
}
type Policy struct {
	Version     int      `json:"version"`
	Site        string   `json:"site"`
	Branch      string   `json:"branch"`
	Mode        string   `json:"mode"`
	Networks    []string `json:"networks"`
	Users       []User   `json:"users"`
	Rate        Rate     `json:"rate"`
	Revision    uint64   `json:"revision"`
	Enforcement string   `json:"enforcement"`
}
type Credential struct {
	Username string `json:"username"`
	Password string `json:"password"`
}
type Update struct {
	Site        string       `json:"site"`
	Branch      string       `json:"branch"`
	Mode        string       `json:"mode"`
	Networks    []string     `json:"networks"`
	Credentials []Credential `json:"credentials"`
	RemoveUsers []string     `json:"remove_users"`
	Rate        Rate         `json:"rate"`
	Revision    uint64       `json:"revision"`
}
type record struct {
	Policy Policy            `json:"policy"`
	Hashes map[string]string `json:"password_hashes"`
}
type document struct {
	Version  int               `json:"version"`
	Policies map[string]record `json:"policies"`
}
type bucket struct {
	tokens   float64
	at       time.Time
	revision uint64
	expires  time.Time
}
type Store struct {
	path    string
	mu      sync.Mutex
	buckets map[string]bucket
}

func NewStore(path string) *Store    { return &Store{path: path, buckets: map[string]bucket{}} }
func key(site, branch string) string { return site + "\x00" + branch }
func defaultPolicy(site, branch string) Policy {
	return Policy{Version: 1, Site: site, Branch: branch, Mode: "closed", Networks: []string{}, Users: []User{}, Rate: Rate{Burst: 60}, Enforcement: "native"}
}
func (s *Store) read() (document, error) {
	d := document{Version: 1, Policies: map[string]record{}}
	f, err := os.Open(s.path)
	if os.IsNotExist(err) {
		return d, nil
	}
	if err != nil {
		return d, err
	}
	defer f.Close()
	if info, e := f.Stat(); e != nil || info.Size() > 4<<20 {
		return d, errors.New("policy file unavailable or oversized")
	}
	dec := json.NewDecoder(io.LimitReader(f, 4<<20))
	dec.DisallowUnknownFields()
	if err = dec.Decode(&d); err != nil {
		return d, err
	}
	if dec.Decode(new(any)) != io.EOF {
		return d, errors.New("invalid policy document")
	}
	if d.Version != 1 || d.Policies == nil {
		return d, errors.New("unsupported policy document")
	}
	// Validate stored data too: corruption must never widen access.
	for k, r := range d.Policies {
		if k != key(r.Policy.Site, r.Policy.Branch) || r.Policy.Version != 1 || r.Policy.Revision == 0 {
			return d, errors.New("invalid policy identity")
		}
		if err = validate(r.Policy, r.Hashes); err != nil {
			return d, err
		}
	}
	return d, nil
}
func (s *Store) Get(site, branch string) (Policy, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	d, err := s.read()
	if err != nil {
		return Policy{}, err
	}
	if r, ok := d.Policies[key(site, branch)]; ok {
		return r.Policy, nil
	}
	return defaultPolicy(site, branch), nil
}

// Export omits password hashes. Importing authentication rules elsewhere requires
// entering credentials again rather than silently disabling authentication.
func (s *Store) Export() ([]Policy, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	d, err := s.read()
	if err != nil {
		return nil, err
	}
	out := make([]Policy, 0, len(d.Policies))
	for _, r := range d.Policies {
		out = append(out, r.Policy)
	}
	sort.Slice(out, func(i, j int) bool { return key(out[i].Site, out[i].Branch) < key(out[j].Site, out[j].Branch) })
	return out, nil
}
func validIdentity(v string) bool {
	return v != "" && len(v) <= 256 && !strings.ContainsAny(v, "\x00\r\n")
}
func validate(p Policy, hashes map[string]string) error {
	if !validIdentity(p.Site) || len(p.Branch) > 256 || strings.ContainsAny(p.Branch, "\x00\r\n") {
		return errors.New("invalid site or branch")
	}
	switch p.Mode {
	case "closed", "public", "ip", "password", "ip_and_password", "ip_or_password":
	default:
		return errors.New("invalid access mode")
	}
	if len(p.Networks) > 256 || len(hashes) > 100 {
		return errors.New("policy too large")
	}
	for _, v := range p.Networks {
		if _, err := netip.ParsePrefix(v); err != nil {
			return fmt.Errorf("invalid CIDR: %s", v)
		}
	}
	if (p.Mode == "ip" || p.Mode == "ip_and_password" || p.Mode == "ip_or_password") && len(p.Networks) == 0 {
		return errors.New("IP mode requires networks")
	}
	if (p.Mode == "password" || p.Mode == "ip_and_password" || p.Mode == "ip_or_password") && len(hashes) == 0 {
		return errors.New("password mode requires credentials")
	}
	for name, hash := range hashes {
		cost, err := bcrypt.Cost([]byte(hash))
		if !validUsername(name) || err != nil || cost > 14 || cost < 4 {
			return errors.New("invalid stored credential")
		}
	}
	if math.IsNaN(p.Rate.RequestsPerSecond) || math.IsInf(p.Rate.RequestsPerSecond, 0) || p.Rate.RequestsPerSecond < 0 || p.Rate.RequestsPerSecond > 100000 || p.Rate.Burst < 1 || p.Rate.Burst > 10000 {
		return errors.New("invalid request rate")
	}
	return nil
}
func validUsername(v string) bool {
	return validIdentity(v) && len(v) <= 128 && !strings.Contains(v, ":")
}
func (s *Store) Put(u Update) (Policy, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	d, err := s.read()
	if err != nil {
		return Policy{}, err
	}
	old, ok := d.Policies[key(u.Site, u.Branch)]
	if !ok {
		old = record{Policy: defaultPolicy(u.Site, u.Branch), Hashes: map[string]string{}}
	}
	if old.Policy.Revision != u.Revision {
		return Policy{}, ErrConflict
	}
	p := defaultPolicy(u.Site, u.Branch)
	p.Mode = u.Mode
	p.Networks = u.Networks
	p.Rate = u.Rate
	p.Revision = u.Revision + 1
	hashes := map[string]string{}
	for n, h := range old.Hashes {
		hashes[n] = h
	}
	if len(u.Credentials) > 100 || len(u.RemoveUsers) > 100 {
		return Policy{}, errors.New("too many credentials")
	}
	for _, n := range u.RemoveUsers {
		if !validUsername(n) {
			return Policy{}, errors.New("invalid username")
		}
		delete(hashes, n)
	}
	seen := map[string]bool{}
	for _, c := range u.Credentials {
		if !validUsername(c.Username) || len(c.Password) < 8 || len(c.Password) > 72 || seen[c.Username] {
			return Policy{}, errors.New("invalid credentials (password must contain 8 to 72 bytes)")
		}
		seen[c.Username] = true
		h, e := bcrypt.GenerateFromPassword([]byte(c.Password), bcrypt.DefaultCost)
		if e != nil {
			return Policy{}, e
		}
		hashes[c.Username] = string(h)
	}
	if p.Networks == nil {
		p.Networks = []string{}
	}
	for i, v := range p.Networks {
		if prefix, e := netip.ParsePrefix(v); e == nil {
			p.Networks[i] = prefix.Masked().String()
		}
	}
	if err = validate(p, hashes); err != nil {
		return Policy{}, err
	}
	names := make([]string, 0, len(hashes))
	for n := range hashes {
		names = append(names, n)
	}
	sort.Strings(names)
	for _, n := range names {
		p.Users = append(p.Users, User{n})
	}
	d.Policies[key(u.Site, u.Branch)] = record{p, hashes}
	data, err := json.MarshalIndent(d, "", "  ")
	if err != nil {
		return Policy{}, err
	}
	config.GuardRealWrite(s.path)
	if err = os.MkdirAll(filepath.Dir(s.path), 0700); err != nil {
		return Policy{}, err
	}
	f, err := os.CreateTemp(filepath.Dir(s.path), ".share-access-*")
	if err != nil {
		return Policy{}, err
	}
	tmp := f.Name()
	defer os.Remove(tmp)
	if err = f.Chmod(0600); err == nil {
		_, err = f.Write(data)
	}
	if err == nil {
		err = f.Sync()
	}
	closeErr := f.Close()
	if err == nil {
		err = closeErr
	}
	if err == nil {
		err = os.Rename(tmp, s.path)
	}
	if err != nil {
		return Policy{}, err
	}
	return p, nil
}

// ClientIP ignores all forwarding headers unless the socket peer is explicitly
// trusted. That peer must overwrite X-Forwarded-For with one validated address.
func ClientIP(r *http.Request, trusted []string) (netip.Addr, error) {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return netip.Addr{}, errors.New("invalid peer")
	}
	peer, err := netip.ParseAddr(host)
	if err != nil {
		return peer, err
	}
	peer = peer.Unmap()
	trustedPeer := false
	for _, v := range trusted {
		p, e := netip.ParsePrefix(v)
		if e != nil {
			return peer, errors.New("invalid trusted proxy network")
		}
		if p.Contains(peer) {
			trustedPeer = true
		}
	}
	if !trustedPeer {
		return peer, nil
	}
	values := r.Header.Values("X-Forwarded-For")
	if len(values) != 1 {
		return peer, errors.New("trusted proxy must supply one client IP")
	}
	ip, err := netip.ParseAddr(strings.TrimSpace(values[0]))
	if err != nil || ip.Zone() != "" {
		return peer, errors.New("invalid forwarded client IP")
	}
	return ip.Unmap(), nil
}
func (s *Store) allowRate(k string, p Policy) bool {
	if p.Rate.RequestsPerSecond == 0 {
		return true
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	now := time.Now()
	b, ok := s.buckets[k]
	if !ok && len(s.buckets) >= 10000 {
		for key, v := range s.buckets {
			if !v.expires.IsZero() && now.After(v.expires) {
				delete(s.buckets, key)
			}
		}
		if len(s.buckets) >= 10000 {
			return false
		}
	}
	if !ok || b.revision != p.Revision {
		b = bucket{tokens: float64(p.Rate.Burst), at: now, revision: p.Revision}
	}
	b.tokens = math.Min(float64(p.Rate.Burst), b.tokens+now.Sub(b.at).Seconds()*p.Rate.RequestsPerSecond)
	b.at = now
	refillSeconds := math.Max(3600, float64(p.Rate.Burst)/p.Rate.RequestsPerSecond)
	if refillSeconds < float64(math.MaxInt64)/float64(time.Second) {
		b.expires = now.Add(time.Duration(refillSeconds * float64(time.Second)))
	}
	allowed := b.tokens >= 1
	if allowed {
		b.tokens--
	}
	s.buckets[k] = b
	return allowed
}
func (s *Store) Middleware(site, branch string, trusted func() ([]string, error), next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		s.mu.Lock()
		d, err := s.read()
		s.mu.Unlock()
		if err != nil {
			http.Error(w, "Share access unavailable", 403)
			return
		}
		rec, ok := d.Policies[key(site, branch)]
		if !ok || rec.Policy.Mode == "closed" {
			http.Error(w, "Share access denied", 403)
			return
		}
		p := rec.Policy
		peers, err := trusted()
		if err != nil {
			http.Error(w, "Share access unavailable", 403)
			return
		}
		ip, err := ClientIP(r, peers)
		if err != nil {
			http.Error(w, "Invalid client identity", 403)
			return
		}
		// Count denied attempts too, before bcrypt work or application dispatch.
		if !s.allowRate(key(site, branch)+"\x00"+ip.String(), p) {
			w.Header().Set("Retry-After", strconv.Itoa(int(math.Min(86400, math.Ceil(1/p.Rate.RequestsPerSecond)))))
			http.Error(w, "Too many requests", 429)
			return
		}
		ipOK := false
		for _, v := range p.Networks {
			prefix, _ := netip.ParsePrefix(v)
			if prefix.Contains(ip) {
				ipOK = true
			}
		}
		user, password, basic := r.BasicAuth()
		authOK := false
		needsAuth := p.Mode == "password" || p.Mode == "ip_and_password" && ipOK || p.Mode == "ip_or_password" && !ipOK
		if hash, exists := rec.Hashes[user]; exists && basic && needsAuth {
			authOK = bcrypt.CompareHashAndPassword([]byte(hash), []byte(password)) == nil
		}
		permitted := false
		switch p.Mode {
		case "public":
			permitted = true
		case "ip":
			permitted = ipOK
		case "password":
			permitted = authOK
		case "ip_and_password":
			permitted = ipOK && authOK
		case "ip_or_password":
			permitted = ipOK || authOK
		}
		if !permitted {
			code := 403
			if p.Mode == "password" || p.Mode == "ip_or_password" || (p.Mode == "ip_and_password" && ipOK) {
				code = 401
				w.Header().Set("WWW-Authenticate", `Basic realm="Shared site", charset="UTF-8"`)
			}
			http.Error(w, "Share access denied", code)
			return
		}
		// Do not expose gate credentials or attacker-controlled proxy identity downstream.
		clone := r.Clone(r.Context())
		clone.Header = r.Header.Clone()
		if basic && needsAuth {
			clone.Header.Del("Authorization")
		}
		clone.Header.Del("Forwarded")
		clone.Header.Del("X-Real-IP")
		clone.Header.Set("X-Forwarded-For", ip.String())
		clone.RemoteAddr = net.JoinHostPort(ip.String(), "0")
		next.ServeHTTP(w, clone)
	})
}

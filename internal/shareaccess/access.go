// Package shareaccess enforces portable access policies for native shares.
package shareaccess

import (
	"crypto/sha256"
	"encoding/base64"
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

const passwordHashPrefix = "$lerd$sha256-bcrypt$v1$"

func passwordInput(secret string) []byte {
	digest := sha256.Sum256([]byte(secret))
	return []byte(base64.RawStdEncoding.EncodeToString(digest[:]))
}

func passwordMatches(hash, secret string) bool {
	input := []byte(secret)
	if strings.HasPrefix(hash, passwordHashPrefix) {
		hash = strings.TrimPrefix(hash, passwordHashPrefix)
		input = passwordInput(secret)
	}
	return bcrypt.CompareHashAndPassword([]byte(hash), input) == nil
}

type Rate struct {
	RequestsPerSecond float64 `json:"requests_per_second"`
	Burst             int     `json:"burst"`
}
type User struct {
	Username string `json:"username"`
}
type Policy struct {
	Version        int      `json:"version"`
	Site           string   `json:"site"`
	Branch         string   `json:"branch"`
	Inherited      bool     `json:"inherited"`
	ParentRevision uint64   `json:"parent_revision"`
	Mode           string   `json:"mode"`
	Networks       []string `json:"networks"`
	Users          []User   `json:"users"`
	Rate           Rate     `json:"rate"`
	Revision       uint64   `json:"revision"`
	Enforcement    string   `json:"enforcement"`
	DenialStatus   int      `json:"denial_status"`
}
type Credential struct {
	Username string `json:"username"`
	Password string `json:"password"`
}
type Update struct {
	Site           string       `json:"site"`
	Branch         string       `json:"branch"`
	Inherit        bool         `json:"inherit,omitempty"`
	ParentRevision *uint64      `json:"parent_revision,omitempty"`
	Mode           string       `json:"mode"`
	Networks       []string     `json:"networks"`
	Credentials    []Credential `json:"credentials"`
	RemoveUsers    []string     `json:"remove_users"`
	Rate           Rate         `json:"rate"`
	Revision       uint64       `json:"revision"`
	DenialStatus   int          `json:"denial_status"`
}
type record struct {
	Policy    Policy            `json:"policy"`
	Hashes    map[string]string `json:"password_hashes"`
	Inherited bool              `json:"inherited,omitempty"`
}
type document struct {
	Version  int               `json:"version"`
	Policies map[string]record `json:"policies"`
}
type bucket struct {
	tokens         float64
	at             time.Time
	revision       uint64
	parentRevision uint64
	expires        time.Time
}
type Store struct {
	path    string
	mu      sync.Mutex
	buckets map[string]bucket
}

func NewStore(path string) *Store    { return &Store{path: path, buckets: map[string]bucket{}} }
func key(site, branch string) string { return site + "\x00" + branch }
func defaultPolicy(site, branch string) Policy {
	return Policy{Version: 1, Site: site, Branch: branch, Mode: "closed", Networks: []string{}, Users: []User{}, Rate: Rate{Burst: 60}, Enforcement: "native", DenialStatus: 403}
}
func cloneHashes(src map[string]string) map[string]string {
	copy := make(map[string]string, len(src))
	for name, hash := range src {
		copy[name] = hash
	}
	return copy
}
func effectiveRecord(d document, site, branch string) record {
	branchRecord, branchExists := d.Policies[key(site, branch)]
	if branch == "" {
		if branchExists {
			branchRecord.Policy.Inherited = false
			branchRecord.Policy.ParentRevision = 0
			return branchRecord
		}
		return record{Policy: defaultPolicy(site, ""), Hashes: map[string]string{}}
	}
	parent, parentExists := d.Policies[key(site, "")]
	parentRevision := uint64(0)
	if parentExists {
		parentRevision = parent.Policy.Revision
	}
	if branchExists && !branchRecord.Inherited {
		branchRecord.Policy.Inherited = false
		branchRecord.Policy.ParentRevision = parentRevision
		return branchRecord
	}
	p := defaultPolicy(site, branch)
	hashes := map[string]string{}
	if parentExists {
		p = parent.Policy
		p.Site = site
		p.Branch = branch
		hashes = cloneHashes(parent.Hashes)
	}
	p.Inherited = true
	p.ParentRevision = parentRevision
	p.Revision = 0
	if branchExists {
		p.Revision = branchRecord.Policy.Revision
	}
	return record{Policy: p, Hashes: hashes, Inherited: true}
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
		if r.Policy.DenialStatus == 0 {
			r.Policy.DenialStatus = 403
			d.Policies[k] = r
		}
		if k != key(r.Policy.Site, r.Policy.Branch) || r.Policy.Version != 1 || r.Policy.Revision == 0 {
			return d, errors.New("invalid policy identity")
		}
		if err = validate(r.Policy, r.Hashes); err != nil {
			return d, err
		}
		if r.Inherited && (r.Policy.Branch == "" || len(r.Hashes) != 0 || r.Policy.Mode != "closed" || len(r.Policy.Users) != 0 || r.Policy.Inherited || r.Policy.ParentRevision != 0) {
			return d, errors.New("invalid inherited policy marker")
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
	return effectiveRecord(d, site, branch).Policy, nil
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
		if r.Inherited {
			continue
		}
		out = append(out, r.Policy)
	}
	sort.Slice(out, func(i, j int) bool { return key(out[i].Site, out[i].Branch) < key(out[j].Site, out[j].Branch) })
	return out, nil
}
func validIdentity(v string) bool {
	return v != "" && len(v) <= 256 && !strings.ContainsAny(v, "\x00\r\n")
}
func validate(p Policy, hashes map[string]string) error {
	if p.DenialStatus != 403 && p.DenialStatus != 404 {
		return errors.New("invalid denial status")
	}
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
		cost, err := bcrypt.Cost([]byte(strings.TrimPrefix(hash, passwordHashPrefix)))
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
	if !validIdentity(u.Site) || len(u.Branch) > 256 || strings.ContainsAny(u.Branch, "\x00\r\n") {
		return Policy{}, errors.New("invalid site or branch")
	}
	id := key(u.Site, u.Branch)
	old, exists := d.Policies[id]
	parent, parentExists := d.Policies[key(u.Site, "")]
	parentRevision := uint64(0)
	if parentExists {
		parentRevision = parent.Policy.Revision
	}
	if u.Inherit {
		if u.Branch == "" {
			return Policy{}, errors.New("site policies cannot inherit")
		}
		if u.ParentRevision == nil || *u.ParentRevision != parentRevision {
			return Policy{}, ErrConflict
		}
		if !exists || old.Inherited {
			return Policy{}, errors.New("worktree has no policy override")
		}
		if old.Policy.Revision != u.Revision || old.Policy.Revision == math.MaxUint64 {
			return Policy{}, ErrConflict
		}
		marker := defaultPolicy(u.Site, u.Branch)
		marker.Revision = old.Policy.Revision + 1
		d.Policies[id] = record{Policy: marker, Hashes: map[string]string{}, Inherited: true}
		if err = s.write(d); err != nil {
			return Policy{}, err
		}
		return effectiveRecord(d, u.Site, u.Branch).Policy, nil
	}
	branchRevision := uint64(0)
	base := record{Policy: defaultPolicy(u.Site, u.Branch), Hashes: map[string]string{}}
	var hashes map[string]string
	if u.Branch == "" {
		if exists {
			branchRevision = old.Policy.Revision
			hashes = cloneHashes(old.Hashes)
		}
	} else if exists && !old.Inherited {
		branchRevision = old.Policy.Revision
		base = old
		hashes = cloneHashes(old.Hashes)
	} else {
		if exists {
			branchRevision = old.Policy.Revision
		}
		base = effectiveRecord(d, u.Site, u.Branch)
		if u.ParentRevision == nil || *u.ParentRevision != parentRevision {
			return Policy{}, ErrConflict
		}
		hashes = cloneHashes(base.Hashes)
	}
	if u.Revision != branchRevision || branchRevision == math.MaxUint64 {
		return Policy{}, ErrConflict
	}
	p := defaultPolicy(u.Site, u.Branch)
	if u.Branch != "" {
		p = base.Policy
		p.Site = u.Site
		p.Branch = u.Branch
		p.Inherited = false
		p.ParentRevision = 0
	}
	p.Mode = u.Mode
	p.Networks = u.Networks
	p.Rate = u.Rate
	p.Revision = branchRevision + 1
	if u.DenialStatus != 0 {
		p.DenialStatus = u.DenialStatus
	}
	if hashes == nil {
		hashes = map[string]string{}
	}
	p.Users = []User{}
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
		if !validUsername(c.Username) || c.Password == "" || seen[c.Username] {
			return Policy{}, errors.New("invalid credentials (password must not be empty)")
		}
		seen[c.Username] = true
		h, e := bcrypt.GenerateFromPassword(passwordInput(c.Password), bcrypt.DefaultCost)
		if e != nil {
			return Policy{}, e
		}
		hashes[c.Username] = passwordHashPrefix + string(h)
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
	d.Policies[id] = record{Policy: p, Hashes: hashes}
	if err = s.write(d); err != nil {
		return Policy{}, err
	}
	return effectiveRecord(d, u.Site, u.Branch).Policy, nil
}

func (s *Store) write(d document) error {
	data, err := json.MarshalIndent(d, "", "  ")
	if err != nil {
		return err
	}
	config.GuardRealWrite(s.path)
	if err = os.MkdirAll(filepath.Dir(s.path), 0700); err != nil {
		return err
	}
	f, err := os.CreateTemp(filepath.Dir(s.path), ".share-access-*")
	if err != nil {
		return err
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
		return err
	}
	return nil
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
	parentRevision := uint64(0)
	if p.Inherited {
		parentRevision = p.ParentRevision
	}
	if !ok || b.revision != p.Revision || b.parentRevision != parentRevision {
		b = bucket{tokens: float64(p.Rate.Burst), at: now, revision: p.Revision, parentRevision: parentRevision}
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
		rec := effectiveRecord(d, site, branch)
		p := rec.Policy
		if p.Mode == "closed" {
			writeShareDenied(w, r, p.DenialStatus)
			return
		}
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
			authOK = passwordMatches(hash, password)
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
			code := p.DenialStatus
			if p.Mode == "password" || p.Mode == "ip_or_password" || (p.Mode == "ip_and_password" && ipOK) {
				code = 401
				w.Header().Set("WWW-Authenticate", `Basic realm="Shared site", charset="UTF-8"`)
			}
			writeShareDenied(w, r, code)
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

func writeShareDenied(w http.ResponseWriter, r *http.Request, status int) {
	if status == 404 {
		http.NotFound(w, r)
		return
	}
	http.Error(w, "Share access denied", status)
}

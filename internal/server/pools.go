// Package server implements the daemon's tunnel-facing control plane.
package server

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"tunnel/internal/names"
	"tunnel/internal/wire"

	quic "github.com/quic-go/quic-go"
)

func Identity(pub ed25519.PublicKey) string {
	sum := sha256.Sum256(pub)
	return hex.EncodeToString(sum[:])
}

func ValidName(name string) bool     { return names.Valid(name) }
func covered(host, root string) bool { return names.Covers(host, root) }
func parents(name string) []string {
	result := []string{name}
	for {
		_, tail, ok := strings.Cut(name, ".")
		if !ok {
			return result
		}
		name = tail
		result = append(result, name)
	}
}
func validListenerID(id string) bool {
	data, err := hex.DecodeString(id)
	return err == nil && len(data) == 16 && hex.EncodeToString(data) == id
}
func trafficClass(mode string) string {
	switch mode {
	case "http":
		return "http"
	case "acme", "byo", "raw", "private":
		return "tls"
	}
	return ""
}

type grant struct {
	pubkey   string
	routes   []string
	revoked  bool
	lastSeen time.Time
}
type registration struct{ name, mode string }
type poolKey struct{ name, class string }
type pool struct {
	owner, mode string
	members     []Selection
	next        uint64
}

// Selection identifies one willing live instance. Forward atomically reserves
// a stream under the manager lock; Select only inspects routing.
type Selection struct {
	SessionID  uint64
	ListenerID string
	Identity   string
	Name       string
	Mode       string
	Revision   string
}

type session struct {
	identity      string
	restricted    bool
	registrations map[string]registration
	used          map[string]registration
	updates       chan any
	stop          func()
	conn          *quic.Conn
	active        map[*forwarding]bool
	lastStreamID  int64
	connectedAt   time.Time
}

type routeStats struct {
	connections atomic.Uint64
	rxBytes     atomic.Uint64
	txBytes     atomic.Uint64
}

// Manager serializes authorization and live pool mutations. Approvals are
// in-memory in this stage; persistent admin state will wrap these operations.
type Manager struct {
	mu             sync.Mutex
	revision       uint64
	nextSession    uint64
	grants         map[string]grant
	owners         map[string]string
	sessions       map[uint64]*session
	pools          map[poolKey]*pool
	stats          map[string]*routeStats
	maxMembers     int
	storage        StateStorage
	stateErr       error
	invites        map[string]Invite
	issuance       map[string]joinRate
	globalIssuance joinRate
}

func NewManager() *Manager {
	return &Manager{grants: map[string]grant{}, owners: map[string]string{}, sessions: map[uint64]*session{}, pools: map[poolKey]*pool{}, stats: map[string]*routeStats{}, maxMembers: 128, invites: map[string]Invite{}}
}

// SetRoutes is an admin-only replacement of grants, never exposed on control.
// Revoked identities must be restored explicitly in the later admin layer.
// Warnings describe overlap with another identity and must be shown by the CLI.
func (m *Manager) SetRoutes(pub ed25519.PublicKey, routes []string) ([]string, error) {
	if len(pub) != ed25519.PublicKeySize {
		return nil, errors.New("invalid Ed25519 public key")
	}
	copyRoutes := append([]string{}, routes...)
	sort.Strings(copyRoutes)
	for i, name := range copyRoutes {
		if !ValidName(name) || i > 0 && name == copyRoutes[i-1] {
			return nil, fmt.Errorf("invalid or duplicate route %q", name)
		}
	}
	if len(copyRoutes) > 128 {
		return nil, errors.New("too many approved routes")
	}
	id := Identity(pub)
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.stateErr != nil {
		return nil, m.stateErr
	}
	if m.grants[id].revoked {
		return nil, errors.New("identity is revoked")
	}
	if m.revision == ^uint64(0) {
		return nil, errors.New("authorization revision exhausted")
	}
	warnings, err := m.validateRoutesLocked(id, copyRoutes)
	if err != nil {
		return nil, err
	}
	pubkey := base64.StdEncoding.EncodeToString(pub)
	state := m.stateLocked()
	state.Revision = strconv.FormatUint(m.revision+1, 10)
	state.Identities[id] = IdentityRecord{Pubkey: pubkey, Routes: copyRoutes}
	if err := m.persistLocked(state); err != nil {
		return nil, err
	}
	m.installRoutesLocked(id, pubkey, copyRoutes)
	m.revision++
	m.revalidateLocked()
	return warnings, nil
}

func (m *Manager) validateRoutesLocked(id string, routes []string) ([]string, error) {
	if len(routes) > 128 {
		return nil, errors.New("too many routes")
	}
	warnings := []string{}
	for i, name := range routes {
		if !ValidName(name) || i > 0 && routes[i-1] >= name {
			return nil, errors.New("invalid routes")
		}
		if owner := m.owners[name]; owner != "" && owner != id {
			return nil, fmt.Errorf("route %s already owned by %s", name, owner)
		}
		for existing, owner := range m.owners {
			if owner != id && (covered(name, existing) || covered(existing, name)) {
				warnings = append(warnings, fmt.Sprintf("%s overlaps %s owned by %s", name, existing, owner))
			}
		}
	}
	sort.Strings(warnings)
	return warnings, nil
}
func (m *Manager) installRoutesLocked(id, pubkey string, routes []string) {
	for _, old := range m.grants[id].routes {
		delete(m.owners, old)
	}
	m.grants[id] = grant{pubkey: pubkey, routes: append([]string{}, routes...)}
	for _, name := range routes {
		m.owners[name] = id
	}
}

func (m *Manager) ownerLocked(name string) string {
	for _, parent := range parents(name) {
		if owner := m.owners[parent]; owner != "" {
			return owner
		}
	}
	return ""
}

func (m *Manager) routeStatsLocked(name string) *routeStats {
	stats := m.stats[name]
	if stats != nil {
		return stats
	}
	stats = &routeStats{}
	m.stats[name] = stats
	return stats
}

func (m *Manager) connect(pub ed25519.PublicKey, stop func()) (uint64, <-chan any) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.nextSession++
	id := Identity(pub)
	g, approved := m.grants[id]
	updates := make(chan any, 32)
	m.sessions[m.nextSession] = &session{identity: id, restricted: !approved || g.revoked, registrations: map[string]registration{}, used: map[string]registration{}, updates: updates, stop: stop, lastStreamID: -1, connectedAt: time.Now()}
	return m.nextSession, updates
}

func (m *Manager) Snapshot(sessionID uint64, requestID string) (wire.RouteList, bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	s := m.sessions[sessionID]
	if s == nil {
		return wire.RouteList{}, false
	}
	return m.snapshotLocked(s, requestID), m.grants[s.identity].revoked
}

func (m *Manager) snapshotLocked(s *session, requestID string) wire.RouteList {
	g, approved := m.grants[s.identity]
	status := "unknown"
	if approved && !g.revoked && m.stateErr == nil {
		status = "approved"
	} else {
		for _, invite := range m.invites {
			if invite.Identity == s.identity {
				if invite.Status == "pending" {
					status = "pending"
					break
				}
				if invite.Status == "rejected" {
					status = "rejected"
				}
			}
		}
	}
	r := wire.RouteList{Envelope: wire.Envelope{Type: "RouteList", ID: requestID}, Identity: s.identity, Status: status, Routes: append([]string{}, g.routes...), Exclusions: []string{}, Withdrawn: []string{}, Revision: strconv.FormatUint(m.revision, 10)}
	if status != "approved" {
		r.Error = "identity is not approved"
	}
	candidates := []string{}
	for root, owner := range m.owners {
		if owner == s.identity {
			continue
		}
		for _, own := range g.routes {
			if covered(root, own) {
				candidates = append(candidates, root)
				break
			}
		}
	}
	sort.Strings(candidates)
	for _, root := range candidates {
		redundant := false
		for _, other := range candidates {
			if root != other && covered(root, other) {
				redundant = true
				break
			}
		}
		if !redundant {
			r.Exclusions = append(r.Exclusions, root)
		}
	}
	return r
}

func (m *Manager) Advertise(sessionID uint64, a wire.Advertise) wire.AdvertiseAck {
	m.mu.Lock()
	defer m.mu.Unlock()
	ack := wire.AdvertiseAck{Advertise: a, Code: "invalid_request"}
	ack.Type = "AdvertiseAck"
	ack.Revision = strconv.FormatUint(m.revision, 10)
	fail := func(code, message string) wire.AdvertiseAck { ack.Code = code; ack.Error = message; return ack }
	if !ValidName(a.Name) || !validListenerID(a.ListenerID) || trafficClass(a.Mode) == "" {
		return fail("invalid_request", "invalid name, listener ID, or mode")
	}
	revision, err := wire.Counter(a.Revision)
	if err != nil {
		return fail("invalid_request", err.Error())
	}
	s := m.sessions[sessionID]
	if s == nil {
		return fail("not_authorized", "session is no longer live")
	}
	g, approved := m.grants[s.identity]
	if m.stateErr != nil || s.restricted || !approved || g.revoked {
		return fail("not_authorized", "identity is not approved for forwarding")
	}
	if revision != m.revision {
		return fail("stale_routes", "refresh RouteList")
	}
	owner := m.ownerLocked(a.Name)
	if owner != s.identity {
		return fail("not_authorized", "name is not owned by this identity")
	}
	reg := registration{a.Name, a.Mode}
	if previous, exists := s.used[a.ListenerID]; exists {
		if previous != reg {
			return fail("invalid_request", "listener ID attributes are immutable")
		}
		if _, active := s.registrations[a.ListenerID]; !active {
			return fail("invalid_request", "closed listener ID cannot be reused")
		}
		ack.OK = true
		ack.Code = "ok"
		return ack
	}
	if len(s.used) >= 4096 || len(s.registrations) >= 128 {
		return fail("invalid_request", "listener limit reached")
	}
	key := poolKey{a.Name, trafficClass(a.Mode)}
	for _, existing := range s.registrations {
		if existing.name == a.Name && trafficClass(existing.mode) == key.class {
			return fail("duplicate_name", "name already advertised on this connection")
		}
	}
	p := m.pools[key]
	if p != nil {
		if p.owner != s.identity {
			return fail("owner_conflict", "pool belongs to another identity")
		}
		if p.mode != a.Mode {
			return fail("mode_conflict", "pool TLS modes must agree")
		}
		if len(p.members) >= m.maxMembers {
			return fail("invalid_request", "pool member limit reached")
		}
	} else {
		p = &pool{owner: s.identity, mode: a.Mode}
		m.pools[key] = p
	}
	s.registrations[a.ListenerID] = reg
	s.used[a.ListenerID] = reg
	p.members = append(p.members, Selection{SessionID: sessionID, ListenerID: a.ListenerID, Identity: s.identity, Name: a.Name, Mode: a.Mode})
	ack.OK = true
	ack.Code = "ok"
	return ack
}

func (m *Manager) removeLocked(sessionID uint64, listenerID string) {
	s := m.sessions[sessionID]
	if s == nil {
		return
	}
	reg, exists := s.registrations[listenerID]
	if !exists {
		return
	}
	delete(s.registrations, listenerID)
	for f := range s.active {
		if f.listenerID == listenerID && f.initializing {
			f.abort()
		}
	}
	key := poolKey{reg.name, trafficClass(reg.mode)}
	p := m.pools[key]
	if p == nil {
		return
	}
	members := p.members[:0]
	for _, member := range p.members {
		if member.SessionID != sessionID || member.ListenerID != listenerID {
			members = append(members, member)
		}
	}
	p.members = members
	if len(members) == 0 {
		delete(m.pools, key)
	}
}

func (m *Manager) Unadvertise(sessionID uint64, listenerID string) string {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.removeLocked(sessionID, listenerID)
	s := m.sessions[sessionID]
	if s == nil {
		return "-1"
	}
	return strconv.FormatInt(s.lastStreamID, 10)
}
func (m *Manager) Disconnect(sessionID uint64) {
	m.mu.Lock()
	defer m.mu.Unlock()
	s := m.sessions[sessionID]
	if s == nil {
		return
	}
	for id := range s.registrations {
		m.removeLocked(sessionID, id)
	}
	for f := range s.active {
		f.abort()
	}
	if g, ok := m.grants[s.identity]; ok {
		g.lastSeen = time.Now()
		m.grants[s.identity] = g
	}
	delete(m.sessions, sessionID)
}

// Select tests/inspects routing only; it is not a stream reservation. The public
// forwarding stage must add an atomic reservation before opening data streams.
func (m *Manager) Select(name, class string) (Selection, bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if !ValidName(name) || class != "tls" && class != "http" {
		return Selection{}, false
	}
	owner := m.ownerLocked(name)
	if owner == "" {
		return Selection{}, false
	}
	for _, parent := range parents(name) {
		p := m.pools[poolKey{parent, class}]
		if p == nil || p.owner != owner || len(p.members) == 0 {
			continue
		}
		member := p.members[p.next%uint64(len(p.members))]
		p.next++
		member.Revision = strconv.FormatUint(m.revision, 10)
		return member, true
	}
	return Selection{}, false
}

func (m *Manager) notifyLocked(s *session, event any) {
	select {
	case s.updates <- event:
	default:
		go s.stop()
	}
}
func (m *Manager) revalidateLocked() {
	for sessionID, s := range m.sessions {
		for f := range s.active {
			if m.ownerLocked(f.host) != s.identity {
				f.abort()
			}
		}
		withdrawn := []string{}
		for id, reg := range s.registrations {
			if m.ownerLocked(reg.name) != s.identity {
				m.removeLocked(sessionID, id)
				withdrawn = append(withdrawn, id)
			}
		}
		sort.Strings(withdrawn)
		event := m.snapshotLocked(s, "")
		event.Withdrawn = withdrawn
		m.notifyLocked(s, event)
	}
}

// Revoke immediately evicts every pool for this key. Connection teardown is
// independent of notification delivery; the transport aborts all its streams.
func (m *Manager) Revoke(pub ed25519.PublicKey, reason string) error {
	if len(pub) != ed25519.PublicKeySize {
		return errors.New("invalid public key")
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.revision == ^uint64(0) {
		return errors.New("authorization revision exhausted")
	}
	if m.stateErr != nil {
		return m.stateErr
	}
	id := Identity(pub)
	g := m.grants[id]
	pubkey := base64.StdEncoding.EncodeToString(pub)
	state := m.stateLocked()
	state.Revision = strconv.FormatUint(m.revision+1, 10)
	state.Identities[id] = IdentityRecord{Pubkey: pubkey, Routes: []string{}, Revoked: true}
	if err := m.persistLocked(state); err != nil {
		return err
	}
	for _, route := range g.routes {
		delete(m.owners, route)
	}
	m.grants[id] = grant{pubkey: pubkey, routes: []string{}, revoked: true}
	m.revision++
	for sessionID, s := range m.sessions {
		if s.identity != id {
			continue
		}
		for listener := range s.registrations {
			m.removeLocked(sessionID, listener)
		}
		m.notifyLocked(s, wire.Revoked{Envelope: wire.Envelope{Type: "Revoked", ID: ""}, Identity: id, Revision: strconv.FormatUint(m.revision, 10), Reason: reason})
		// Hard notification budget; pool eviction above is already complete.
		time.AfterFunc(time.Second, s.stop)
	}
	m.revalidateLocked()
	return nil
}

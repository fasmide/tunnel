package server

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"sort"
	"strconv"
	"time"

	"github.com/fasmide/tunnel/internal/wire"
)

type StateStorage interface {
	Get(string) ([]byte, error)
	Put(string, []byte) error
}
type IdentityRecord struct {
	Pubkey       string   `json:"pubkey"`
	Routes       []string `json:"routes"`
	Revoked      bool     `json:"revoked"`
	Online       bool     `json:"online,omitempty"`
	ConnectedFor string   `json:"connected_for,omitempty"`
	OfflineFor   string   `json:"offline_for,omitempty"`
}
type RouteRecord struct {
	Identity     string `json:"identity"`
	Pubkey       string `json:"pubkey"`
	Name         string `json:"name"`
	Revoked      bool   `json:"revoked"`
	Online       bool   `json:"online,omitempty"`
	ConnectedFor string `json:"connected_for,omitempty"`
	OfflineFor   string `json:"offline_for,omitempty"`
	Connections  uint64 `json:"connections,omitempty"`
	RXBytes      uint64 `json:"rx_bytes,omitempty"`
	TXBytes      uint64 `json:"tx_bytes,omitempty"`
	LatestRTT    string `json:"latest_rtt,omitempty"`
	SmoothedRTT  string `json:"smoothed_rtt,omitempty"`
	MinRTT       string `json:"min_rtt,omitempty"`
}
type Invite struct {
	ID       string    `json:"id"`
	Identity string    `json:"identity"`
	Join     wire.Join `json:"join"`
	Status   string    `json:"status"`
}
type diskState struct {
	Version    int                       `json:"version"`
	Revision   string                    `json:"revision"`
	Identities map[string]IdentityRecord `json:"identities"`
	Invites    map[string]Invite         `json:"invites"`
}

// OpenManager loads and validates the entire durable snapshot before listening.
// Only one daemon may own this store (the CLI enforces a process lock).
func OpenManager(storage StateStorage) (*Manager, error) {
	if storage == nil {
		return nil, errors.New("nil state storage")
	}
	m := NewManager()
	data, err := storage.Get("server/state")
	if errors.Is(err, fs.ErrNotExist) {
		m.storage = storage
		return m, nil
	}
	if err != nil {
		return nil, fmt.Errorf("load server state: %w", err)
	}
	if len(data) > 32*1024*1024 {
		return nil, errors.New("server state exceeds 32 MiB limit")
	}
	if err = wire.ValidateJSON(data); err != nil {
		return nil, fmt.Errorf("validate server state JSON: %w", err)
	}
	var state diskState
	if err = json.Unmarshal(data, &state); err != nil {
		return nil, fmt.Errorf("decode server state: %w", err)
	}
	revision, err := wire.Counter(state.Revision)
	if err != nil || state.Version != 1 || state.Identities == nil || state.Invites == nil {
		return nil, errors.New("invalid server state")
	}
	// Validate conflicts and canonical grants using the normal mutation path.
	for id, record := range state.Identities {
		pub, err := wire.Base64(record.Pubkey, 32)
		if err != nil || Identity(pub) != id {
			return nil, errors.New("invalid stored identity")
		}
		if record.Revoked && len(record.Routes) != 0 {
			return nil, errors.New("revoked identity has routes")
		}
		if _, err = m.SetRoutes(pub, record.Routes); err != nil {
			return nil, err
		}
		g := m.grants[id]
		g.revoked = record.Revoked
		m.grants[id] = g
	}
	for id, invite := range state.Invites {
		pub, err := wire.Base64(invite.Join.Request.Pubkey, 32)
		if err != nil || invite.ID != id || invite.Identity != Identity(pub) || wire.VerifyJoin(invite.Join, pub) != nil {
			return nil, errors.New("invalid stored invite")
		}
		if invite.Status != "pending" && invite.Status != "approved" && invite.Status != "rejected" {
			return nil, errors.New("invalid invite status")
		}
	}
	m.invites = state.Invites
	m.revision = revision
	m.storage = storage
	return m, nil
}
func (m *Manager) stateLocked() diskState {
	state := diskState{Version: 1, Revision: strconv.FormatUint(m.revision, 10), Identities: map[string]IdentityRecord{}, Invites: map[string]Invite{}}
	for id, g := range m.grants {
		state.Identities[id] = IdentityRecord{Pubkey: g.pubkey, Routes: append([]string{}, g.routes...), Revoked: g.revoked}
	}
	for id, invite := range m.invites {
		state.Invites[id] = invite
	}
	return state
}
func (m *Manager) persistLocked(state diskState) error {
	if m.storage == nil {
		return nil
	}
	data, err := json.Marshal(state)
	if err != nil {
		return fmt.Errorf("marshal server state: %w", err)
	}
	if len(data) > 32*1024*1024 {
		return errors.New("server state exceeds 32 MiB limit")
	}
	if err = m.storage.Put("server/state", data); err != nil {
		// A store can fail after rename. Freeze mutations and stop sessions rather
		// than serve with uncertain authorization. Operator must restart/recover.
		m.stateErr = fmt.Errorf("state commit failed; restart required: %w", err)
		for sessionID, s := range m.sessions {
			for id := range s.registrations {
				m.removeLocked(sessionID, id)
			}
			for f := range s.active {
				f.abort()
			}
			go s.stop()
		}
		return m.stateErr
	}
	return nil
}
func (m *Manager) SubmitJoin(pub ed25519.PublicKey, j wire.Join) wire.JoinResult {
	result := wire.JoinResult{Envelope: wire.Envelope{Type: "JoinResult", ID: j.ID}, Status: "error", Code: "invalid_signature", Routes: []string{}}
	if err := wire.VerifyJoin(j, pub); err != nil {
		result.Revision = m.Revision()
		result.Error = err.Error()
		return result
	}
	j = cloneInvite(Invite{Join: j}).Join
	m.mu.Lock()
	defer m.mu.Unlock()
	id := Identity(pub)
	g := m.grants[id]
	result.Routes = append([]string{}, g.routes...)
	result.Revision = strconv.FormatUint(m.revision, 10)
	fail := func(code, message string) wire.JoinResult { result.Code = code; result.Error = message; return result }
	if m.stateErr != nil {
		return fail("invalid_request", m.stateErr.Error())
	}
	if g.revoked {
		return fail("revoked", "identity is revoked")
	}
	payload, _ := wire.JoinBytes(j.Request)
	digest := sha256.Sum256(payload)
	for _, invite := range m.invites {
		if invite.Identity != id || invite.Join.Request.Nonce != j.Request.Nonce {
			continue
		}
		old, _ := wire.JoinBytes(invite.Join.Request)
		other := sha256.Sum256(old)
		if digest != other {
			return fail("replay_conflict", "nonce already used with different payload")
		}
		result.InviteID = invite.ID
		result.Status = invite.Status
		result.Code = "ok"
		return result
	}
	timestamp, err := wire.Timestamp(j.Request)
	now := time.Now().Unix()
	if err != nil || timestamp < now-300 || timestamp > now+300 {
		return fail("invalid_request", "join timestamp outside five-minute window")
	}
	if len(m.invites) >= 10000 {
		return fail("rate_limited", "join history limit reached")
	}
	count := 0
	for _, invite := range m.invites {
		if invite.Identity == id && invite.Status == "pending" {
			count++
		}
	}
	if count >= 16 {
		return fail("rate_limited", "too many pending requests for identity")
	}
	var nonce [16]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		return fail("invalid_request", err.Error())
	}
	inviteID := hex.EncodeToString(nonce[:])
	invite := Invite{ID: inviteID, Identity: id, Join: j, Status: "pending"}
	state := m.stateLocked()
	state.Invites[inviteID] = invite
	if err := m.persistLocked(state); err != nil {
		return fail("invalid_request", err.Error())
	}
	m.invites[inviteID] = invite
	result.InviteID = inviteID
	result.Status = "pending"
	result.Code = "ok"
	return result
}
func cloneInvite(invite Invite) Invite {
	invite.Join.Request.Routes = append([]string{}, invite.Join.Request.Routes...)
	metadata := map[string]string{}
	for k, v := range invite.Join.Request.Metadata {
		metadata[k] = v
	}
	invite.Join.Request.Metadata = metadata
	return invite
}

func (m *Manager) Invites() []Invite {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := []Invite{}
	for _, invite := range m.invites {
		if invite.Status == "pending" {
			out = append(out, cloneInvite(invite))
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out
}
func (m *Manager) Identities() map[string]IdentityRecord {
	m.mu.Lock()
	defer m.mu.Unlock()
	identities := m.stateLocked().Identities
	for _, session := range m.sessions {
		record, ok := identities[session.identity]
		if !ok {
			continue
		}
		record.Online = true
		record.ConnectedFor = time.Since(session.connectedAt).Round(time.Second).String()
		identities[session.identity] = record
	}
	for id, record := range identities {
		if record.Online || record.ConnectedFor != "" || record.OfflineFor != "" {
			continue
		}
		if last := m.grants[id].lastSeen; !last.IsZero() {
			record.OfflineFor = time.Since(last).Round(time.Second).String()
			identities[id] = record
		}
	}
	return identities
}

func (m *Manager) Routes() []RouteRecord {
	m.mu.Lock()
	defer m.mu.Unlock()
	routes := []RouteRecord{}
	seen := map[string]bool{}
	for id, grant := range m.grants {
		status := RouteRecord{Identity: id, Pubkey: grant.pubkey, Revoked: grant.revoked}
		if session, ok := m.identitySessionLocked(id); ok {
			status.Online = true
			status.ConnectedFor = time.Since(session.connectedAt).Round(time.Second).String()
			applyRouteRTT(&status, session)
		} else if !m.grants[id].lastSeen.IsZero() {
			status.OfflineFor = time.Since(m.grants[id].lastSeen).Round(time.Second).String()
		}
		for _, name := range grant.routes {
			row := status
			row.Name = name
			m.applyRouteStats(&row)
			routes = append(routes, row)
			seen[id+"\x00"+name] = true
		}
		if grant.revoked && len(grant.routes) == 0 {
			m.applyRouteStats(&status)
			routes = append(routes, status)
			seen[id+"\x00"] = true
		}
	}
	for _, session := range m.sessions {
		g, ok := m.grants[session.identity]
		if !ok {
			continue
		}
		for _, reg := range session.registrations {
			key := session.identity + "\x00" + reg.name
			if seen[key] {
				continue
			}
			row := RouteRecord{
				Identity:     session.identity,
				Pubkey:       g.pubkey,
				Name:         reg.name,
				Revoked:      g.revoked,
				Online:       true,
				ConnectedFor: time.Since(session.connectedAt).Round(time.Second).String(),
			}
			applyRouteRTT(&row, session)
			m.applyRouteStats(&row)
			routes = append(routes, row)
			seen[key] = true
		}
	}
	sort.Slice(routes, func(i, j int) bool {
		if routes[i].Identity != routes[j].Identity {
			return routes[i].Identity < routes[j].Identity
		}
		if routes[i].Name != routes[j].Name {
			return routes[i].Name < routes[j].Name
		}
		return routes[i].Pubkey < routes[j].Pubkey
	})
	return routes
}

func (m *Manager) identitySessionLocked(identity string) (*session, bool) {
	for _, session := range m.sessions {
		if session.identity == identity {
			return session, true
		}
	}
	return nil, false
}

func (m *Manager) applyRouteStats(route *RouteRecord) {
	if route == nil || route.Name == "" {
		return
	}
	stats := m.stats[route.Name]
	if stats == nil {
		return
	}
	route.Connections = stats.connections.Load()
	route.RXBytes = stats.rxBytes.Load()
	route.TXBytes = stats.txBytes.Load()
}

func applyRouteRTT(route *RouteRecord, session *session) {
	if route == nil || session == nil || session.conn == nil {
		return
	}
	stats := session.conn.ConnectionStats()
	route.LatestRTT = formatRTT(stats.LatestRTT)
	route.SmoothedRTT = formatRTT(stats.SmoothedRTT)
	route.MinRTT = formatRTT(stats.MinRTT)
}

func formatRTT(value time.Duration) string {
	if value <= 0 {
		return ""
	}
	return value.Round(time.Microsecond).String()
}

// DecideInvite commits invite status and authorization in a single snapshot.
func (m *Manager) DecideInvite(id string, approve bool) ([]string, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.stateErr != nil {
		return nil, m.stateErr
	}
	invite, ok := m.invites[id]
	if !ok {
		return nil, errors.New("unknown invite")
	}
	status := "rejected"
	if approve {
		status = "approved"
	}
	if invite.Status == status {
		return []string{}, nil
	}
	if invite.Status != "pending" {
		return nil, errors.New("invite already decided")
	}
	g := m.grants[invite.Identity]
	if approve && g.revoked {
		return nil, errors.New("identity is revoked")
	}
	state := m.stateLocked()
	invite.Status = status
	state.Invites[id] = invite
	warnings := []string{}
	routes := append([]string{}, g.routes...)
	if approve {
		set := map[string]bool{}
		for _, r := range routes {
			set[r] = true
		}
		for _, r := range invite.Join.Request.Routes {
			set[r] = true
		}
		routes = []string{}
		for r := range set {
			routes = append(routes, r)
		}
		sort.Strings(routes)
		var err error
		warnings, err = m.validateRoutesLocked(invite.Identity, routes)
		if err != nil {
			return nil, err
		}
		if m.revision == ^uint64(0) {
			return nil, errors.New("revision exhausted")
		}
		state.Revision = strconv.FormatUint(m.revision+1, 10)
		state.Identities[invite.Identity] = IdentityRecord{Pubkey: invite.Join.Request.Pubkey, Routes: routes}
	}
	if err := m.persistLocked(state); err != nil {
		return nil, err
	}
	m.invites[id] = invite
	if approve {
		m.installRoutesLocked(invite.Identity, invite.Join.Request.Pubkey, routes)
		m.revision++
		m.revalidateLocked()
	}
	return warnings, nil
}
func (m *Manager) publicKey(id string) (ed25519.PublicKey, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	g, ok := m.grants[id]
	if !ok {
		return nil, errors.New("unknown identity")
	}
	pub, err := base64.StdEncoding.DecodeString(g.pubkey)
	return ed25519.PublicKey(pub), err
}

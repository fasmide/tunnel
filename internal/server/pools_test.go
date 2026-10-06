package server

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"fmt"
	"strings"
	"sync"
	"testing"

	"tunnel/internal/wire"
)

func key(t *testing.T) ed25519.PublicKey {
	t.Helper()
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return pub
}
func approve(t *testing.T, m *Manager, pub ed25519.PublicKey, routes ...string) {
	t.Helper()
	if _, err := m.SetRoutes(pub, routes); err != nil {
		t.Fatal(err)
	}
}
func advertise(t *testing.T, m *Manager, session uint64, id int, name, mode string) wire.Advertise {
	t.Helper()
	a := wire.Advertise{Envelope: wire.Envelope{Type: "Advertise", ID: "2"}, ListenerID: fmt.Sprintf("%032x", id), Name: name, Mode: mode, Revision: m.Revision()}
	if ack := m.Advertise(session, a); !ack.OK {
		t.Fatalf("advertise: %+v", ack)
	}
	return a
}

func TestPoolingAndLongestMatch(t *testing.T) {
	m := NewManager()
	pub := key(t)
	approve(t, m, pub, "alice.example.com")
	a, _ := m.connect(pub, func() {})
	b, _ := m.connect(pub, func() {})
	advertise(t, m, a, 1, "alice.example.com", "raw")
	advertise(t, m, b, 2, "alice.example.com", "raw")
	for i := range 10 {
		got, ok := m.Select("foo.alice.example.com", "tls")
		want := a
		if i%2 == 1 {
			want = b
		}
		if !ok || got.SessionID != want {
			t.Fatalf("round-robin %d: %+v", i, got)
		}
	}
	advertise(t, m, b, 3, "api.alice.example.com", "raw")
	got, ok := m.Select("v1.api.alice.example.com", "tls")
	if !ok || got.ListenerID != fmt.Sprintf("%032x", 3) {
		t.Fatalf("specific: %+v", got)
	}
	if _, ok := m.Select("evilalice.example.com", "tls"); ok {
		t.Fatal("label boundary violation")
	}
	m.Disconnect(b)
	got, ok = m.Select("v1.api.alice.example.com", "tls")
	if !ok || got.SessionID != a {
		t.Fatal("same-owner fallback after disconnect")
	}
	m.Disconnect(a)
	if _, ok := m.Select("alice.example.com", "tls"); ok {
		t.Fatal("pool not cleaned")
	}
}

func TestOfflineCarveOutAndWithdrawal(t *testing.T) {
	m := NewManager()
	alice := key(t)
	bob := key(t)
	approve(t, m, alice, "alice.example.com")
	a, events := m.connect(alice, func() {})
	advertise(t, m, a, 1, "alice.example.com", "raw")
	specific := advertise(t, m, a, 2, "api.alice.example.com", "raw")
	warnings, err := m.SetRoutes(bob, []string{"api.alice.example.com"})
	if err != nil || len(warnings) == 0 {
		t.Fatalf("missing overlap warning: %v %v", warnings, err)
	}
	if _, ok := m.Select("api.alice.example.com", "tls"); ok {
		t.Fatal("offline carve-out leaked to ancestor identity")
	}
	event := (<-events).(wire.RouteList)
	if len(event.Withdrawn) != 1 || event.Withdrawn[0] != specific.ListenerID || len(event.Exclusions) != 1 {
		t.Fatalf("event: %+v", event)
	}
	b, _ := m.connect(bob, func() {})
	advertise(t, m, b, 3, "api.alice.example.com", "raw")
	got, ok := m.Select("v1.api.alice.example.com", "tls")
	if !ok || got.Identity != Identity(bob) {
		t.Fatal("wrong child owner")
	}
	if _, err := m.SetRoutes(bob, []string{"alice.example.com"}); err == nil {
		t.Fatal("identical owner tie accepted")
	}
	if err := m.Revoke(bob, "test"); err != nil {
		t.Fatal(err)
	}
	got, ok = m.Select("api.alice.example.com", "tls")
	if !ok || got.Identity != Identity(alice) {
		t.Fatal("removed carve-out did not return to parent")
	}
	if _, err := m.SetRoutes(bob, []string{"other.example.com"}); err == nil {
		t.Fatal("revoked key silently restored")
	}
}

func TestAuthorizationModeAndIDs(t *testing.T) {
	m := NewManager()
	alice := key(t)
	stranger := key(t)
	restricted, _ := m.connect(stranger, func() {})
	approve(t, m, alice, "alice.example.com")
	a, _ := m.connect(alice, func() {})
	b, _ := m.connect(alice, func() {})
	reg := advertise(t, m, a, 1, "alice.example.com", "raw")
	if ack := m.Advertise(a, reg); !ack.OK {
		t.Fatal("idempotent advertise failed")
	}
	changed := reg
	changed.Name = "foo.alice.example.com"
	if ack := m.Advertise(a, changed); ack.Code != "invalid_request" {
		t.Fatalf("immutable ID: %+v", ack)
	}
	conflicting := reg
	conflicting.ListenerID = fmt.Sprintf("%032x", 2)
	conflicting.Mode = "byo"
	if ack := m.Advertise(b, conflicting); ack.Code != "mode_conflict" {
		t.Fatalf("mode: %+v", ack)
	}
	if ack := m.Advertise(restricted, reg); ack.Code != "not_authorized" {
		t.Fatal("unapproved advertise accepted")
	}
	reg.Name = "unapproved.example.com"
	if ack := m.Advertise(b, reg); ack.Code != "not_authorized" {
		t.Fatal("scope expanded")
	}
	advertise(t, m, a, 4, "alice.example.com", "http")
	if got, ok := m.Select("foo.alice.example.com", "http"); !ok || got.Mode != "http" {
		t.Fatal("HTTP/TLS coexistence failed")
	}
	m.Unadvertise(a, fmt.Sprintf("%032x", 1))
	m.Unadvertise(a, fmt.Sprintf("%032x", 1))
	if _, ok := m.Select("alice.example.com", "tls"); ok {
		t.Fatal("unadvertise left pool")
	}
	reg.Name = "alice.example.com"
	if ack := m.Advertise(a, reg); ack.Code != "invalid_request" {
		t.Fatal("closed ID reused")
	}
	oldRevision := m.Revision()
	approve(t, m, alice, "alice.example.com", "other.example.com")
	reg.ListenerID = fmt.Sprintf("%032x", 5)
	reg.Revision = oldRevision
	if ack := m.Advertise(b, reg); ack.Code != "stale_routes" {
		t.Fatal("stale revision accepted")
	}
	approve(t, m, stranger, "stranger.example.com")
	reg.Name = "stranger.example.com"
	reg.Revision = m.Revision()
	if ack := m.Advertise(restricted, reg); ack.Code != "not_authorized" {
		t.Fatal("restricted bootstrap session promoted")
	}
}

func TestConcurrentRevokeAndSelection(t *testing.T) {
	m := NewManager()
	pub := key(t)
	approve(t, m, pub, "alice.example.com")
	a, _ := m.connect(pub, func() {})
	advertise(t, m, a, 1, "alice.example.com", "raw")
	var wg sync.WaitGroup
	for range 8 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for range 500 {
				m.Select("foo.alice.example.com", "tls")
			}
		}()
	}
	if err := m.Revoke(pub, "test"); err != nil {
		t.Fatal(err)
	}
	wg.Wait()
	if _, ok := m.Select("foo.alice.example.com", "tls"); ok {
		t.Fatal("revoked pool still routes")
	}
	snapshot, revoked := m.Snapshot(a, "3")
	if !revoked || len(snapshot.Routes) != 0 {
		t.Fatal("revocation missing from snapshot")
	}
}

func TestIdentitiesOnlineAndDurations(t *testing.T) {
	m := NewManager()
	pub := bytes.Repeat([]byte{1}, ed25519.PublicKeySize)
	if _, err := m.SetRoutes(ed25519.PublicKey(pub), []string{"app.example.com"}); err != nil {
		t.Fatal(err)
	}
	id := Identity(ed25519.PublicKey(pub))
	record := m.Identities()[id]
	if record.Online || record.ConnectedFor != "" || record.OfflineFor != "" {
		t.Fatalf("unexpected initial state: %+v", record)
	}
	sessionID, _ := m.connect(ed25519.PublicKey(pub), func() {})
	record = m.Identities()[id]
	if !record.Online || record.ConnectedFor == "" || record.OfflineFor != "" {
		t.Fatalf("identity not marked online: %+v", record)
	}
	m.Disconnect(sessionID)
	record = m.Identities()[id]
	if record.Online || record.OfflineFor == "" || record.ConnectedFor != "" {
		t.Fatalf("identity missing offline metadata after disconnect: %+v", record)
	}
}

func TestRoutesIncludeLiveAdvertisedDescendants(t *testing.T) {
	m := NewManager()
	pub := ed25519.PublicKey(bytes.Repeat([]byte{1}, ed25519.PublicKeySize))
	if _, err := m.SetRoutes(pub, []string{"hello.example.com"}); err != nil {
		t.Fatal(err)
	}
	sessionID, _ := m.connect(pub, func() {})
	ack := m.Advertise(sessionID, wire.Advertise{ListenerID: strings.Repeat("a", 32), Name: "hello.example.com", Mode: "acme", Revision: "1"})
	if !ack.OK {
		t.Fatalf("advertise root failed: %+v", ack)
	}
	ack = m.Advertise(sessionID, wire.Advertise{ListenerID: strings.Repeat("b", 32), Name: "pipsalat.hello.example.com", Mode: "acme", Revision: "1"})
	if !ack.OK {
		t.Fatalf("advertise descendant failed: %+v", ack)
	}
	routes := m.Routes()
	if len(routes) != 2 {
		t.Fatalf("got %d routes: %+v", len(routes), routes)
	}
	if routes[0].Identity != routes[1].Identity {
		t.Fatalf("expected same identity in both rows: %+v", routes)
	}
	if routes[0].Name != "hello.example.com" || routes[1].Name != "pipsalat.hello.example.com" {
		t.Fatalf("unexpected route rows: %+v", routes)
	}
	for _, route := range routes {
		if !route.Online || route.ConnectedFor == "" {
			t.Fatalf("route missing online metadata: %+v", route)
		}
	}
}

func TestRoutesIncludeRevokedIdentityWithoutRouteNames(t *testing.T) {
	m := NewManager()
	pub := ed25519.PublicKey(bytes.Repeat([]byte{2}, ed25519.PublicKeySize))
	if _, err := m.SetRoutes(pub, []string{"gone.example.com"}); err != nil {
		t.Fatal(err)
	}
	if err := m.Revoke(pub, "test revoke"); err != nil {
		t.Fatal(err)
	}
	routes := m.Routes()
	if len(routes) != 1 {
		t.Fatalf("got %d routes: %+v", len(routes), routes)
	}
	if !routes[0].Revoked || routes[0].Name != "" {
		t.Fatalf("unexpected revoked route row: %+v", routes[0])
	}
}

func TestRoutesIncludeStats(t *testing.T) {
	m := NewManager()
	stats := m.routeStatsLocked("stats.example.com")
	stats.connections.Store(7)
	stats.rxBytes.Store(1234)
	stats.txBytes.Store(5678)
	pub := ed25519.PublicKey(bytes.Repeat([]byte{3}, ed25519.PublicKeySize))
	if _, err := m.SetRoutes(pub, []string{"stats.example.com"}); err != nil {
		t.Fatal(err)
	}
	routes := m.Routes()
	if len(routes) != 1 {
		t.Fatalf("got %d routes: %+v", len(routes), routes)
	}
	if routes[0].Connections != 7 || routes[0].RXBytes != 1234 || routes[0].TXBytes != 5678 {
		t.Fatalf("missing stats on route row: %+v", routes[0])
	}
	if routes[0].LatestRTT != "" || routes[0].SmoothedRTT != "" || routes[0].MinRTT != "" {
		t.Fatalf("unexpected RTT values on offline route row: %+v", routes[0])
	}
}

func TestValidNames(t *testing.T) {
	for _, name := range []string{"a", "alice.example.com", "xn--bcher-kva.example", "a-b.example"} {
		if !ValidName(name) {
			t.Errorf("reject %s", name)
		}
	}
	for _, name := range []string{"", "Alice.example.com", "a.", "a..b", "*.example.com", "a:443", "127.0.0.1", "-a.example", "a-.example", "evil/alice"} {
		if ValidName(name) {
			t.Errorf("accept %s", name)
		}
	}
}

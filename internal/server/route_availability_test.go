package server

import (
	"bytes"
	"crypto/ed25519"
	"strings"
	"testing"

	"github.com/fasmide/tunnel/internal/wire"
)

func TestRouteAvailabilityFollowsPools(t *testing.T) {
	m := NewManager()
	pub := ed25519.PublicKey(bytes.Repeat([]byte{9}, ed25519.PublicKeySize))
	if _, err := m.SetRoutes(pub, []string{"example.net", "exact.example.net"}); err != nil {
		t.Fatal(err)
	}
	sessionID, _ := m.connect(pub, func() {})
	check := func(name, kind string, online bool) {
		t.Helper()
		for _, row := range m.Routes() {
			if row.Name == name {
				if row.Type != kind || row.Online != online {
					t.Fatalf("unexpected route: %+v", row)
				}
				return
			}
		}
		t.Fatalf("missing route %s", name)
	}
	// Connected identity without listeners does not make grants online.
	check("example.net", "grant", false)
	check("exact.example.net", "grant", false)
	advertise := func(name, id string) {
		t.Helper()
		ack := m.Advertise(sessionID, wire.Advertise{ListenerID: strings.Repeat(id, 32), Name: name, Mode: "acme", Revision: m.Revision()})
		if !ack.OK {
			t.Fatal(ack)
		}
	}
	advertise("child.example.net", "a")
	check("example.net", "grant", false)
	check("child.example.net", "listener", true)
	advertise("example.net", "b")
	check("example.net", "grant", true)
	check("exact.example.net", "grant", true) // Served through ancestor.
	if len(m.Routes()) != 3 {
		t.Fatal("grant/listener overlap created duplicate rows")
	}
	m.Unadvertise(sessionID, strings.Repeat("b", 32))
	check("example.net", "grant", false)
	check("exact.example.net", "grant", false)
	check("child.example.net", "listener", true)
	// Another instance keeps a descendant's counters alive until both leave.
	second, _ := m.connect(pub, func() {})
	ack := m.Advertise(second, wire.Advertise{ListenerID: strings.Repeat("c", 32), Name: "child.example.net", Mode: "acme", Revision: m.Revision()})
	if !ack.OK {
		t.Fatal(ack)
	}
	m.mu.Lock()
	m.routeStatsLocked("child.example.net").connections.Store(7)
	m.mu.Unlock()
	m.Disconnect(second)
	for _, row := range m.Routes() {
		if row.Name == "child.example.net" && row.Connections != 7 {
			t.Fatal("counter lost while another instance remained")
		}
	}
	m.Disconnect(sessionID)
	check("example.net", "grant", false)
	if len(m.Routes()) != 2 {
		t.Fatal("disconnected descendant remained in route list")
	}
}

package server

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"math/rand/v2"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/fasmide/tunnel/internal/wire"
	quic "github.com/quic-go/quic-go"
)

func TestConformanceControlRejectsMalformedFrames(t *testing.T) {
	framed := func(s string) []byte {
		data := make([]byte, 4)
		binary.BigEndian.PutUint32(data, uint32(len(s)))
		return append(data, []byte(s)...)
	}
	cases := map[string][]byte{
		"unknown_type":        framed(`{"type":"ExpandRoutes","id":"1"}`),
		"wrong_first_message": framed(`{"type":"Ping","id":"1"}`),
		"first_id_not_one":    framed(`{"type":"RouteList","id":"2"}`),
		"duplicate_keys":      framed(`{"type":"RouteList","id":"1","id":"2"}`),
		"missing_id":          framed(`{"type":"RouteList"}`),
		"null_id":             framed(`{"type":"RouteList","id":null}`),
		"zero_length":         {0, 0, 0, 0},
		"oversized_length":    {0, 1, 0, 1},
		"non_object":          framed(`[]`),
	}
	for name, data := range cases {
		t.Run(name, func(t *testing.T) {
			m := NewManager()
			s, roots := testServer(t, m)
			cert, _ := testCertificate(t, false)
			conn, stream := dialTest(t, s, roots, cert)
			if _, err := stream.Write(data); err != nil {
				t.Fatal(err)
			}
			select {
			case <-conn.Context().Done():
			case <-time.After(2 * time.Second):
				t.Fatal("invalid control frame left session live")
			}
			cause := context.Cause(conn.Context())
			var app *quic.ApplicationError
			if !errors.As(cause, &app) || app.ErrorCode != 1 {
				t.Fatalf("close cause %v, want protocol error 1", cause)
			}
		})
	}
}

func TestConformanceMissingAdvertiseFieldsCannotInstallPool(t *testing.T) {
	for _, field := range []string{"listener_id", "name", "mode", "revision"} {
		t.Run(field, func(t *testing.T) {
			m := NewManager()
			cert, pub := testCertificate(t, false)
			approve(t, m, pub, "alice.example.com")
			s, roots := testServer(t, m)
			conn, control := dialTest(t, s, roots, cert)
			request(t, control, wire.Envelope{Type: "RouteList", ID: "1"}, "1")
			a := map[string]string{"type": "Advertise", "id": "2", "listener_id": strings.Repeat("a", 32), "name": "alice.example.com", "mode": "raw", "revision": m.Revision()}
			delete(a, field)
			if err := wire.WriteFrame(control, a); err != nil {
				t.Fatal(err)
			}
			select {
			case <-conn.Context().Done():
			case <-time.After(2 * time.Second):
				t.Fatal("missing field not rejected")
			}
			if _, ok := m.Select("alice.example.com", "tls"); ok {
				t.Fatal("invalid advertise installed pool")
			}
		})
	}
}

// Compare implementation routing to a separately written label-based oracle.
// Fixed RNG seed makes failures reproducible; names/owners/pools are shuffled.
func TestConformanceRoutingAgainstReference(t *testing.T) {
	random := rand.New(rand.NewPCG(7, 19))
	for trial := range 40 {
		m := NewManager()
		keys := []string{}
		sessions := []uint64{}
		roots := map[string]string{}
		roots["example.com"] = ""
		for i := range 4 {
			pub := key(t)
			root := "example.com"
			if i > 0 {
				root = fmt.Sprintf("n%d.example.com", i)
			}
			approve(t, m, pub, root)
			id, _ := m.connect(pub, func() {})
			sessions = append(sessions, id)
			keys = append(keys, Identity(pub))
			roots[root] = Identity(pub)
		}
		pools := map[string]Selection{}
		for i, id := range sessions {
			root := "example.com"
			if i > 0 {
				root = fmt.Sprintf("n%d.example.com", i)
			}
			if random.IntN(2) == 0 {
				advertise(t, m, id, i+1, root, "raw")
				pools[root] = Selection{SessionID: id, Name: root, Identity: keys[i]}
			}
			specific := "api." + root
			if random.IntN(2) == 0 {
				advertise(t, m, id, i+10, specific, "raw")
				pools[specific] = Selection{SessionID: id, Name: specific, Identity: keys[i]}
			}
		}
		for _, host := range []string{"example.com", "foo.example.com", "n1.example.com", "api.n1.example.com", "v1.api.n1.example.com", "n2.example.com", "api.n2.example.com", "foo.n3.example.com", "eviln1.example.com", "outside.test"} {
			labels := strings.Split(host, ".")
			owner := ""
			var want Selection
			found := false
			for i := range labels {
				if o, ok := roots[strings.Join(labels[i:], ".")]; ok {
					owner = o
					break
				}
			}
			if owner != "" {
				for i := range labels {
					if p, ok := pools[strings.Join(labels[i:], ".")]; ok && p.Identity == owner {
						want = p
						found = true
						break
					}
				}
			}
			got, ok := m.Select(host, "tls")
			if ok != found || ok && (got.Name != want.Name || got.Identity != want.Identity || got.SessionID != want.SessionID) {
				t.Fatalf("trial %d host %s: got %+v %v want %+v %v", trial, host, got, ok, want, found)
			}
		}
	}
}

func TestConformanceDrainWatermarkAndPendingHeaderCancellation(t *testing.T) {
	m := NewManager()
	cert, pub := testCertificate(t, false)
	approve(t, m, pub, "alice.example.com")
	s, roots := testServer(t, m)
	conn, control := dialTest(t, s, roots, cert)
	request(t, control, wire.Envelope{Type: "RouteList", ID: "1"}, "1")
	listenerID := strings.Repeat("a", 32)
	request(t, control, wire.Advertise{Envelope: wire.Envelope{Type: "Advertise", ID: "2"}, ListenerID: listenerID, Name: "alice.example.com", Mode: "raw", Revision: m.Revision()}, "2")
	// Reserve a real server stream but leave its header unwritten: this is the
	// state of a Forward racing Unadvertise immediately after allocation.
	m.mu.Lock()
	var sessionID uint64
	for id := range m.sessions {
		sessionID = id
	}
	target := m.sessions[sessionID]
	stream, err := target.conn.OpenStream()
	if err != nil {
		m.mu.Unlock()
		t.Fatal(err)
	}
	target.lastStreamID = int64(stream.StreamID())
	left, right := net.Pipe()
	f := &forwarding{host: "alice.example.com", listenerID: listenerID, initializing: true, public: left, stream: stream}
	target.active[f] = true
	m.mu.Unlock()
	defer func() { _ = right.Close() }()
	watermark := m.Unadvertise(sessionID, listenerID)
	if watermark != fmt.Sprint(stream.StreamID()) {
		t.Fatalf("watermark %s", watermark)
	}
	if _, err := stream.Write([]byte("late header")); err == nil {
		t.Fatal("pending header not canceled before acknowledgement")
	}
	if _, ok := m.Select("alice.example.com", "tls"); ok {
		t.Fatal("removed pool selected")
	}
	m.mu.Lock()
	delete(target.active, f)
	m.mu.Unlock()
	data := request(t, control, wire.Envelope{Type: "Ping", ID: "3"}, "3")
	var pong wire.Pong
	if err := wire.Decode(data, &pong, "active_streams"); err != nil || pong.ActiveStreams != "0" {
		t.Fatalf("remote drain count %s %v", data, err)
	}
	_ = conn.CloseWithError(0, "done")
}

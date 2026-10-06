package server

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"math/big"
	"strings"
	"testing"
	"time"

	"github.com/fasmide/tunnel/internal/wire"
	quic "github.com/quic-go/quic-go"
)

func testCertificate(t *testing.T, server bool) (tls.Certificate, ed25519.PublicKey) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "test"}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}}
	if server {
		template.DNSNames = []string{"localhost"}
		template.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, pub, priv)
	if err != nil {
		t.Fatal(err)
	}
	leaf, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: priv, Leaf: leaf}, pub
}

func testServer(t *testing.T, m *Manager) (*Server, *x509.CertPool) {
	t.Helper()
	cert, _ := testCertificate(t, true)
	roots := x509.NewCertPool()
	roots.AddCert(cert.Leaf)
	s, err := Listen("127.0.0.1:0", &tls.Config{Certificates: []tls.Certificate{cert}}, m)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = s.Close() })
	return s, roots
}

func dialTest(t *testing.T, s *Server, roots *x509.CertPool, cert tls.Certificate) (*quic.Conn, *quic.Stream) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	conn, err := quic.DialAddr(ctx, s.Addr(), &tls.Config{ServerName: "localhost", RootCAs: roots, Certificates: []tls.Certificate{cert}, NextProtos: []string{wire.ALPN}}, nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = conn.CloseWithError(0, "test complete") })
	stream, err := conn.OpenStreamSync(ctx)
	if err != nil {
		t.Fatal(err)
	}
	return conn, stream
}

func request(t *testing.T, stream *quic.Stream, value any, requestID string) []byte {
	t.Helper()
	if err := stream.SetWriteDeadline(time.Now().Add(3 * time.Second)); err != nil {
		t.Fatal(err)
	}
	if err := wire.WriteFrame(stream, value); err != nil {
		t.Fatal(err)
	}
	if err := stream.SetReadDeadline(time.Now().Add(3 * time.Second)); err != nil {
		t.Fatal(err)
	}
	for {
		data, err := wire.ReadFrame(stream)
		if err != nil {
			t.Fatal(err)
		}
		var envelope wire.Envelope
		if err := json.Unmarshal(data, &envelope); err != nil {
			t.Fatal(err)
		}
		if envelope.ID == requestID || envelope.Type == "Revoked" {
			return data
		}
	}
}

func TestQUICControlAndPooling(t *testing.T) {
	m := NewManager()
	cert, pub := testCertificate(t, false)
	approve(t, m, pub, "alice.example.com")
	s, roots := testServer(t, m)
	c1, stream1 := dialTest(t, s, roots, cert)
	_, stream2 := dialTest(t, s, roots, cert)
	for _, stream := range []*quic.Stream{stream1, stream2} {
		data := request(t, stream, wire.Envelope{Type: "RouteList", ID: "1"}, "1")
		var routes wire.RouteList
		if err := json.Unmarshal(data, &routes); err != nil || routes.Status != "approved" || routes.Identity != Identity(pub) {
			t.Fatalf("routes: %s %v", data, err)
		}
		a := wire.Advertise{Envelope: wire.Envelope{Type: "Advertise", ID: "2"}, ListenerID: strings.Repeat("a", 32), Name: "alice.example.com", Mode: "raw", Revision: routes.Revision}
		data = request(t, stream, a, "2")
		var ack wire.AdvertiseAck
		if err := json.Unmarshal(data, &ack); err != nil || !ack.OK {
			t.Fatalf("ack: %s %v", data, err)
		}
	}
	first, ok := m.Select("foo.alice.example.com", "tls")
	if !ok {
		t.Fatal("no pool")
	}
	second, ok := m.Select("foo.alice.example.com", "tls")
	if !ok || second.SessionID == first.SessionID {
		t.Fatal("instances did not pool")
	}
	data := request(t, stream1, wire.Envelope{Type: "Ping", ID: "3"}, "3")
	var pong wire.Envelope
	if err := json.Unmarshal(data, &pong); err != nil {
		t.Fatal(err)
	}
	if pong.Type != "Pong" {
		t.Fatalf("ping: %s", data)
	}
	request(t, stream1, wire.Unadvertise{Envelope: wire.Envelope{Type: "Unadvertise", ID: "4"}, ListenerID: strings.Repeat("a", 32)}, "4")
	got, _ := m.Select("alice.example.com", "tls")
	if got.SessionID != second.SessionID {
		t.Fatal("unadvertise removed wrong member")
	}
	_ = c1.CloseWithError(0, "done")
	if err := m.Revoke(pub, "test revoke"); err != nil {
		t.Fatal(err)
	}
	if _, ok := m.Select("alice.example.com", "tls"); ok {
		t.Fatal("revoke did not immediately evict")
	}
	if err := stream2.SetReadDeadline(time.Now().Add(3 * time.Second)); err != nil {
		t.Fatal(err)
	}
	// QUIC close may overtake the best-effort Revoked frame, but must arrive.
	if _, err := wire.ReadFrame(stream2); err == nil {
		if _, err := wire.ReadFrame(stream2); err == nil {
			t.Fatal("revoked connection stayed alive")
		}
	}
}

func TestQUICUnknownKeyAndProtocolViolation(t *testing.T) {
	m := NewManager()
	s, roots := testServer(t, m)
	cert, _ := testCertificate(t, false)
	conn, stream := dialTest(t, s, roots, cert)
	data := request(t, stream, wire.Envelope{Type: "RouteList", ID: "1"}, "1")
	var routes wire.RouteList
	if err := json.Unmarshal(data, &routes); err != nil {
		t.Fatal(err)
	}
	if routes.Status != "unknown" {
		t.Fatalf("unexpected approval: %s", data)
	}
	a := wire.Advertise{Envelope: wire.Envelope{Type: "Advertise", ID: "2"}, ListenerID: strings.Repeat("b", 32), Name: "alice.example.com", Mode: "raw", Revision: routes.Revision}
	data = request(t, stream, a, "2")
	var ack wire.AdvertiseAck
	if err := json.Unmarshal(data, &ack); err != nil {
		t.Fatal(err)
	}
	if ack.OK || ack.Code != "not_authorized" {
		t.Fatalf("unknown advertised: %s", data)
	}
	if _, ok := m.Select("alice.example.com", "tls"); ok {
		t.Fatal("unknown key routed")
	}
	// Request IDs cannot be replayed.
	if err := wire.WriteFrame(stream, wire.Envelope{Type: "Ping", ID: "2"}); err != nil {
		t.Fatal(err)
	}
	select {
	case <-conn.Context().Done():
	case <-time.After(3 * time.Second):
		t.Fatal("protocol violation not closed")
	}
}

func TestQUICRejectsExtraClientStream(t *testing.T) {
	m := NewManager()
	s, roots := testServer(t, m)
	cert, _ := testCertificate(t, false)
	conn, stream := dialTest(t, s, roots, cert)
	request(t, stream, wire.Envelope{Type: "RouteList", ID: "1"}, "1")
	extra, err := conn.OpenStreamSync(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := extra.Write([]byte{1}); err != nil {
		t.Fatal(err)
	}
	select {
	case <-conn.Context().Done():
	case <-time.After(3 * time.Second):
		t.Fatal("extra stream permitted")
	}
}

func TestQUICDisconnectCleanup(t *testing.T) {
	m := NewManager()
	cert, pub := testCertificate(t, false)
	approve(t, m, pub, "alice.example.com")
	s, roots := testServer(t, m)
	conn, stream := dialTest(t, s, roots, cert)
	request(t, stream, wire.Envelope{Type: "RouteList", ID: "1"}, "1")
	request(t, stream, wire.Advertise{Envelope: wire.Envelope{Type: "Advertise", ID: "2"}, ListenerID: strings.Repeat("c", 32), Name: "alice.example.com", Mode: "raw", Revision: m.Revision()}, "2")
	_ = conn.CloseWithError(0, "disconnect")
	deadline := time.Now().Add(3 * time.Second)
	for {
		if _, ok := m.Select("alice.example.com", "tls"); !ok {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("disconnect left live pool")
		}
		time.Sleep(time.Millisecond)
	}
}

func TestQUICRejectsInvalidCertificates(t *testing.T) {
	m := NewManager()
	s, roots := testServer(t, m)
	wrong, _ := testCertificate(t, true)
	for _, certs := range [][]tls.Certificate{nil, {wrong}} {
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		conn, err := quic.DialAddr(ctx, s.Addr(), &tls.Config{ServerName: "localhost", RootCAs: roots, Certificates: certs, NextProtos: []string{wire.ALPN}}, nil)
		if err == nil {
			stream, openErr := conn.OpenStreamSync(ctx)
			if openErr == nil {
				if err := stream.SetDeadline(time.Now().Add(time.Second)); err != nil {
					t.Fatal(err)
				}
				if err := wire.WriteFrame(stream, wire.Envelope{Type: "RouteList", ID: "1"}); err != nil {
					t.Fatal(err)
				}
				if _, readErr := wire.ReadFrame(stream); readErr == nil {
					t.Fatal("invalid certificate admitted to control")
				}
			}
			_ = conn.CloseWithError(0, "test complete")
		}
		cancel()
	}
}

func TestIdentityValidation(t *testing.T) {
	cert, pub := testCertificate(t, false)
	got, err := verifyIdentity(cert.Certificate, time.Now())
	if err != nil || Identity(got) != Identity(pub) {
		t.Fatalf("identity: %v", err)
	}
	if _, err := verifyIdentity(nil, time.Now()); err == nil {
		t.Fatal("missing accepted")
	}
	if _, err := verifyIdentity(cert.Certificate, time.Now().Add(2*time.Hour)); err == nil {
		t.Fatal("expired accepted")
	}
	serverCert, _ := testCertificate(t, true)
	if _, err := verifyIdentity(serverCert.Certificate, time.Now()); err == nil {
		t.Fatal("wrong EKU accepted")
	}
	damaged := append([]byte{}, cert.Certificate[0]...)
	damaged[len(damaged)-1] ^= 1
	if _, err := verifyIdentity([][]byte{damaged}, time.Now()); err == nil {
		t.Fatal("bad self-signature accepted")
	}
}

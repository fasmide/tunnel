package tunnel

import (
	"bytes"
	"context"
	"crypto/tls"
	"errors"
	"io"
	"net"
	"testing"
	"time"

	"tunnel/internal/server"
)

func eventually(t *testing.T, check func() bool) {
	t.Helper()
	until := time.Now().Add(5 * time.Second)
	for !check() {
		if time.Now().After(until) {
			t.Fatal("condition did not become true")
		}
		time.Sleep(5 * time.Millisecond)
	}
}
func startRestartable(t *testing.T, m *server.Manager) (*server.Server, *tls.Config, *tls.Config) {
	t.Helper()
	cert, roots := applicationCertificate(t)
	// The test certificate covers alice.example.com, and both sessions trust it.
	serverTLS := &tls.Config{Certificates: []tls.Certificate{cert}}
	s, err := server.Listen("127.0.0.1:0", serverTLS, m)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = s.Close() })
	return s, serverTLS, &tls.Config{ServerName: "alice.example.com", RootCAs: roots}
}
func reopenServer(t *testing.T, addr string, config *tls.Config, m *server.Manager) *server.Server {
	t.Helper()
	deadline := time.Now().Add(time.Second)
	for {
		s, err := server.Listen(addr, config, m)
		if err == nil {
			return s
		}
		if time.Now().After(deadline) {
			t.Fatal(err)
		}
		time.Sleep(10 * time.Millisecond)
	}
}

func TestReconnectPreservesListenerAndFailsInflight(t *testing.T) {
	m := server.NewManager()
	creds := identity(t)
	grant(t, m, creds, "alice.example.com")
	s, config, trust := startRestartable(t, m)
	addr := s.Addr()
	c := connected(t, s, trust, creds)
	l := listenRaw(t, c, "alice.example.com")
	peer, forwardDone := routePublic(t, s, "alice.example.com", nil)
	old := accept(t, l)
	_ = s.Close()
	if _, err := old.Read(make([]byte, 1)); err == nil {
		t.Fatal("inflight read survived transport loss")
	}
	_ = old.Close()
	_ = peer.Close()
	<-forwardDone
	eventually(t, func() bool { return c.Status() == "reconnecting" })
	nextAccepted := make(chan net.Conn, 1)
	go func() {
		conn, err := l.Accept()
		if err == nil {
			nextAccepted <- conn
		}
	}()
	select {
	case <-nextAccepted:
		t.Fatal("Accept returned during outage")
	case <-time.After(30 * time.Millisecond):
	}
	restarted := reopenServer(t, addr, config, m)
	t.Cleanup(func() { _ = restarted.Close() })
	eventually(t, func() bool { _, ok := m.Select("alice.example.com", "tls"); return c.Status() == "connected" && ok })
	newPeer, newDone := routePublic(t, restarted, "alice.example.com", nil)
	var conn net.Conn
	select {
	case conn = <-nextAccepted:
	case <-time.After(3 * time.Second):
		t.Fatal("same listener did not recover")
	}
	if _, err := newPeer.Write([]byte("new bytes only")); err != nil {
		t.Fatal(err)
	}
	if err := newPeer.CloseWrite(); err != nil {
		t.Fatal(err)
	}
	body, err := io.ReadAll(conn)
	if err != nil || string(body) != "new bytes only" {
		t.Fatal("bytes replayed or recovery failed")
	}
	if err := conn.(interface{ CloseWrite() error }).CloseWrite(); err != nil {
		t.Fatal(err)
	}
	if _, err := io.ReadAll(newPeer); err != nil {
		t.Fatal(err)
	}
	if err := conn.Close(); err != nil {
		t.Fatal(err)
	}
	<-newDone
}
func TestReconnectRevalidatesEditedAndRevokedRoutes(t *testing.T) {
	for _, revoke := range []bool{false, true} {
		t.Run(map[bool]string{false: "edit", true: "revoke"}[revoke], func(t *testing.T) {
			m := server.NewManager()
			creds := identity(t)
			grant(t, m, creds, "alice.example.com")
			s, config, trust := startRestartable(t, m)
			addr := s.Addr()
			c := connected(t, s, trust, creds)
			l := listenRaw(t, c, "alice.example.com")
			if err := s.Close(); err != nil {
				t.Fatal(err)
			}
			eventually(t, func() bool { return c.Status() == "reconnecting" })
			if revoke {
				if err := m.Revoke(creds.PublicKey(), "offline revoke"); err != nil {
					t.Fatal(err)
				}
			} else {
				grant(t, m, creds, "other.example.com")
			}
			restarted := reopenServer(t, addr, config, m)
			t.Cleanup(func() { _ = restarted.Close() })
			eventually(t, func() bool {
				if revoke {
					return c.Status() == "denied"
				}
				return c.Status() == "connected" && len(c.Listening()) == 0
			})
			if _, err := l.Accept(); err == nil {
				t.Fatal("withdrawn listener survived reconnect")
			}
			if _, ok := m.Select("alice.example.com", "tls"); ok {
				t.Fatal("revoked root re-advertised")
			}
		})
	}
}
func TestGracefulDrainWaitsAndAcceptsAllocatedStream(t *testing.T) {
	s, m, trust := runningServer(t)
	creds := identity(t)
	grant(t, m, creds, "alice.example.com")
	c := connected(t, s, trust, creds)
	l := listenRaw(t, c, "alice.example.com")
	peer, forwardDone := routePublic(t, s, "alice.example.com", nil)
	eventually(t, func() bool { c.mu.Lock(); defer c.mu.Unlock(); return len(c.active) == 1 })
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	drained := make(chan error, 1)
	go func() { drained <- c.CloseGracefully(ctx) }()
	eventually(t, func() bool { _, ok := m.Select("alice.example.com", "tls"); return c.Status() == "draining" && !ok })
	if _, err := c.ListenHTTP(ctx, "alice.example.com"); err == nil {
		t.Fatal("new listener permitted while draining")
	}
	select {
	case err := <-drained:
		t.Fatalf("drain ignored queued stream: %v", err)
	default:
	}
	conn := accept(t, l)
	if _, err := peer.Write([]byte("finish request")); err != nil {
		t.Fatal(err)
	}
	if err := peer.CloseWrite(); err != nil {
		t.Fatal(err)
	}
	body, err := io.ReadAll(conn)
	if err != nil || string(body) != "finish request" {
		t.Fatal("allocated stream not serviceable")
	}
	payload := make([]byte, 128*1024)
	for i := range payload {
		payload[i] = byte(i)
	}
	if _, err := conn.Write(payload); err != nil {
		t.Fatal(err)
	}
	_ = conn.Close()
	response, err := io.ReadAll(peer)
	if err != nil || !bytes.Equal(response, payload) {
		t.Fatalf("graceful drain truncated response: %d %v", len(response), err)
	}
	<-forwardDone
	if err := <-drained; err != nil {
		t.Fatal(err)
	}
	if c.Status() != "closed" {
		t.Fatal("drain did not close client")
	}
	if _, err := l.Accept(); !errors.Is(err, net.ErrClosed) {
		t.Fatalf("Accept after drain: %v", err)
	}
}
func TestGracefulDeadlineAndCloseCancelReconnect(t *testing.T) {
	s, m, trust := runningServer(t)
	creds := identity(t)
	grant(t, m, creds, "alice.example.com")
	c := connected(t, s, trust, creds)
	l := listenRaw(t, c, "alice.example.com")
	peer, done := routePublic(t, s, "alice.example.com", nil)
	conn := accept(t, l)
	ctx, cancel := context.WithTimeout(context.Background(), 40*time.Millisecond)
	defer cancel()
	if err := c.CloseGracefully(ctx); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("drain deadline: %v", err)
	}
	if _, err := conn.Read(make([]byte, 1)); err == nil {
		t.Fatal("deadline did not abort stream")
	}
	_ = conn.Close()
	_ = peer.Close()
	<-done
	c2 := connected(t, s, trust, creds)
	listenRaw(t, c2, "alice.example.com")
	_ = s.Close()
	eventually(t, func() bool { return c2.Status() == "reconnecting" })
	_ = c2.Close()
	time.Sleep(50 * time.Millisecond)
	if c2.Status() != "closed" {
		t.Fatal("Close allowed reconnect")
	}
}

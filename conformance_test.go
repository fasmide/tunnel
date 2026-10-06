package tunnel

import (
	"bufio"
	"context"
	"crypto/tls"
	"io"
	"net"
	"net/http"
	"sync"
	"testing"
	"time"

	"tunnel/internal/server"
)

// These named acceptance cases deliberately exercise public TCP + real QUIC,
// not just pool inspection. Run with -run Conformance and -race.
func TestConformanceV1HTTPS(t *testing.T) {
	s, m, trust := runningServer(t)
	alice, bob := identity(t), identity(t)
	grant(t, m, alice, "alice.example.com")
	a, b := connected(t, s, trust, alice), connected(t, s, trust, alice)
	cert, roots := applicationCertificate(t)
	serveApplication(t, listenRaw(t, a, "alice.example.com"), cert, "a")
	serveApplication(t, listenRaw(t, b, "alice.example.com"), cert, "b")
	edge, err := s.ListenTLS("127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Run("same_key_HA_subtree", func(t *testing.T) {
		for i := range 8 {
			want := "a:real HTTPS request"
			if i%2 == 1 {
				want = "b:real HTTPS request"
			}
			if got := edgeRequest(t, edge, roots, "foo.alice.example.com"); got != want {
				t.Fatalf("request %d: %s want %s", i, got, want)
			}
		}
	})
	t.Run("specific_listener_in_other_instance", func(t *testing.T) {
		serveApplication(t, listenRaw(t, b, "api.alice.example.com"), cert, "specific")
		if got := edgeRequest(t, edge, roots, "v1.api.alice.example.com"); got != "specific:real HTTPS request" {
			t.Fatal(got)
		}
	})
	t.Run("cross_identity_carveout", func(t *testing.T) {
		warnings, err := m.SetRoutes(bob.PublicKey(), []string{"api.alice.example.com"})
		if err != nil || len(warnings) == 0 {
			t.Fatalf("warning: %v %v", warnings, err)
		}
		// Ownership takes effect before notification reaches old clients.
		dialer := tls.Dialer{Config: &tls.Config{RootCAs: roots, ServerName: "api.alice.example.com"}}
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		if conn, err := dialer.DialContext(ctx, "tcp", edge.Addr().String()); err == nil {
			_ = conn.Close()
			t.Fatal("offline carve-out reached parent")
		}
		child := connected(t, s, trust, bob)
		serveApplication(t, listenRaw(t, child, "api.alice.example.com"), cert, "bob")
		if got := edgeRequest(t, edge, roots, "v1.api.alice.example.com"); got != "bob:real HTTPS request" {
			t.Fatal(got)
		}
		if _, err := a.ListenRaw(context.Background(), "outside.example.com"); err == nil {
			t.Fatal("scope expanded")
		}
	})
	t.Run("disconnect_one_member_keeps_other", func(t *testing.T) {
		_ = a.Close()
		eventually(t, func() bool {
			selection, ok := m.Select("foo.alice.example.com", "tls")
			return ok && selection.Identity == alice.Identity() && lenPoolForTest(m) == 1
		})
		for range 4 {
			if got := edgeRequest(t, edge, roots, "foo.alice.example.com"); got != "b:real HTTPS request" {
				t.Fatal(got)
			}
		}
	})
}

// Manager's public Select is used only for eventual availability. The client
// status/HTTPS response, rather than server-private counters, are acceptance evidence.
func lenPoolForTest(m *server.Manager) int {
	first, ok := m.Select("foo.alice.example.com", "tls")
	if !ok {
		return 0
	}
	second, ok := m.Select("foo.alice.example.com", "tls")
	if !ok {
		return 0
	}
	if first.SessionID != second.SessionID {
		return 2
	}
	return 1
}

func TestConformanceRevokeAllInstancesImmediately(t *testing.T) {
	s, m, trust := runningServer(t)
	creds := identity(t)
	grant(t, m, creds, "alice.example.com")
	clients := []*Client{connected(t, s, trust, creds), connected(t, s, trust, creds)}
	listeners := []net.Listener{listenRaw(t, clients[0], "alice.example.com"), listenRaw(t, clients[1], "alice.example.com")}
	peers := []net.Conn{}
	accepted := []net.Conn{}
	forwarding := []<-chan error{}
	for _, l := range listeners {
		peer, done := routePublic(t, s, "alice.example.com", nil)
		peers = append(peers, peer)
		accepted = append(accepted, accept(t, l))
		forwarding = append(forwarding, done)
	}
	start := time.Now()
	if err := m.Revoke(creds.PublicKey(), "conformance revoke"); err != nil {
		t.Fatal(err)
	}
	if _, ok := m.Select("alice.example.com", "tls"); ok {
		t.Fatal("pool remained after revoke returned")
	}
	for i, conn := range accepted {
		if err := conn.SetReadDeadline(time.Now().Add(2 * time.Second)); err != nil {
			t.Fatal(err)
		}
		if _, err := conn.Read(make([]byte, 1)); err == nil {
			t.Fatal("revoked stream still readable")
		}
		_ = conn.Close()
		_ = peers[i].Close()
		select {
		case <-forwarding[i]:
		case <-time.After(2 * time.Second):
			t.Fatal("forwarder not evicted")
		}
	}
	for _, client := range clients {
		eventually(t, func() bool { return client.Status() == "denied" })
	}
	if time.Since(start) >= 30*time.Second {
		t.Fatal("revoke exceeded idle timeout")
	}
}

func TestConformanceEmptyGrantsAreNotRevocation(t *testing.T) {
	m := server.NewManager()
	creds := identity(t)
	grant(t, m, creds, "alice.example.com")
	s, config, trust := startRestartable(t, m)
	addr := s.Addr()
	c := connected(t, s, trust, creds)
	old := listenRaw(t, c, "alice.example.com")
	grant(t, m, creds)
	eventually(t, func() bool { return len(c.Routes()) == 0 && len(c.Listening()) == 0 })
	if c.Status() != "connected" {
		t.Fatal("empty approval treated as revocation")
	}
	if _, err := old.Accept(); err == nil {
		t.Fatal("removed listener accepted")
	}
	_ = s.Close()
	eventually(t, func() bool { return c.Status() == "reconnecting" })
	restarted := reopenServer(t, addr, config, m)
	t.Cleanup(func() { _ = restarted.Close() })
	eventually(t, func() bool { return c.Status() == "connected" })
	grant(t, m, creds, "other.example.com")
	eventually(t, func() bool { return len(c.Routes()) == 1 })
	if _, err := c.ListenHTTP(context.Background(), "other.example.com"); err != nil {
		t.Fatal(err)
	}
}

func TestConformanceConcurrentListenAndDrain(t *testing.T) {
	for range 8 {
		s, m, trust := runningServer(t)
		creds := identity(t)
		grant(t, m, creds, "alice.example.com")
		c := connected(t, s, trust, creds)
		gate := make(chan struct{})
		var wg sync.WaitGroup
		wg.Add(2)
		go func() {
			defer wg.Done()
			<-gate
			l, err := c.ListenRaw(context.Background(), "alice.example.com")
			if err == nil {
				_ = l
			}
		}()
		go func() {
			defer wg.Done()
			<-gate
			ctx, cancel := context.WithTimeout(context.Background(), time.Second)
			defer cancel()
			if err := c.CloseGracefully(ctx); err != nil {
				t.Error(err)
			}
		}()
		close(gate)
		wg.Wait()
		if c.Status() != "closed" {
			t.Fatal("drain did not finish")
		}
		if _, ok := m.Select("alice.example.com", "tls"); ok {
			t.Fatal("listener raced back into drained pool")
		}
	}
}

func TestConformanceHTTPReconnectAndGracefulResponse(t *testing.T) {
	m := server.NewManager()
	creds := identity(t)
	grant(t, m, creds, "alice.example.com")
	s, config, trust := startRestartable(t, m)
	addr := s.Addr()
	c := connected(t, s, trust, creds)
	listener, err := c.ListenHTTP(context.Background(), "alice.example.com")
	if err != nil {
		t.Fatal(err)
	}
	_ = s.Close()
	eventually(t, func() bool { return c.Status() == "reconnecting" })
	restarted := reopenServer(t, addr, config, m)
	t.Cleanup(func() { _ = restarted.Close() })
	eventually(t, func() bool { return c.Status() == "connected" })
	edge, err := restarted.ListenHTTP("127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	peer := publicHTTP(t, edge)
	if _, err := io.WriteString(peer, "GET / HTTP/1.1\r\nHost: alice.example.com\r\n\r\n"); err != nil {
		t.Fatal(err)
	}
	backend := accept(t, listener)
	if _, err := io.ReadAll(backend); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- c.CloseGracefully(ctx) }()
	eventually(t, func() bool { _, ok := m.Select("alice.example.com", "http"); return !ok })
	if _, err := io.WriteString(backend, "HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok"); err != nil {
		t.Fatal(err)
	}
	if err := backend.Close(); err != nil {
		t.Fatal(err)
	}
	response, err := http.ReadResponse(bufio.NewReader(peer), nil)
	if err != nil {
		t.Fatal(err)
	}
	body, err := io.ReadAll(response.Body)
	if closeErr := response.Body.Close(); closeErr != nil {
		t.Fatal(closeErr)
	}
	if err != nil || string(body) != "ok" {
		t.Fatalf("drain response: %q %v", body, err)
	}
	if err := <-done; err != nil {
		t.Fatal(err)
	}
}

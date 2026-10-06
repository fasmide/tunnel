package tunnel

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"io"
	"math/big"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/fasmide/tunnel/internal/server"
)

func runningServer(t testing.TB) (*server.Server, *server.Manager, *tls.Config) {
	return runningManager(t, server.NewManager())
}
func runningManager(t testing.TB, m *server.Manager) (*server.Server, *server.Manager, *tls.Config) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "localhost"}, DNSNames: []string{"localhost"}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	der, err := x509.CreateCertificate(rand.Reader, template, template, pub, priv)
	if err != nil {
		t.Fatal(err)
	}
	leaf, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	roots := x509.NewCertPool()
	roots.AddCert(leaf)
	s, err := server.Listen("127.0.0.1:0", &tls.Config{Certificates: []tls.Certificate{{Certificate: [][]byte{der}, PrivateKey: priv}}}, m)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = s.Close() })
	return s, m, &tls.Config{ServerName: "localhost", RootCAs: roots}
}
func identity(t testing.TB) Credentials {
	t.Helper()
	c, err := loadOrCreateCredentials(MemoryStorage())
	if err != nil {
		t.Fatal(err)
	}
	return c
}
func connected(t testing.TB, s *server.Server, config *tls.Config, creds Credentials) *Client {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	c, err := Dial(ctx, s.Addr(), WithCredentials(creds), WithTLSConfig(config))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = c.Close() })
	return c
}
func grant(t testing.TB, m *server.Manager, c Credentials, names ...string) {
	t.Helper()
	if _, err := m.SetRoutes(c.PublicKey(), names); err != nil {
		t.Fatal(err)
	}
}
func listenRaw(t testing.TB, c *Client, name string) net.Listener {
	t.Helper()
	l, err := c.ListenRaw(context.Background(), name)
	if err != nil {
		t.Fatal(err)
	}
	return l
}

// routePublic bypasses SNI discovery, which is the next stage. It uses a real
// TCP peer and the production reservation/header/byte-forwarding path.
func routePublic(t *testing.T, s *server.Server, host string, prefix []byte) (*net.TCPConn, <-chan error) {
	t.Helper()
	edge, err := net.ListenTCP("tcp", &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	peer, err := net.DialTCP("tcp", nil, edge.Addr().(*net.TCPAddr))
	if err != nil {
		t.Fatal(err)
	}
	public, err := edge.AcceptTCP()
	_ = edge.Close()
	if err != nil {
		t.Fatal(err)
	}
	if err := peer.SetDeadline(time.Now().Add(5 * time.Second)); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = peer.Close() })
	done := make(chan error, 1)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	go func() { defer cancel(); done <- s.Forward(ctx, public, host, prefix) }()
	return peer, done
}
func accept(t testing.TB, l net.Listener) net.Conn {
	t.Helper()
	ch := make(chan net.Conn, 1)
	errs := make(chan error, 1)
	go func() {
		conn, err := l.Accept()
		if err != nil {
			errs <- err
		} else {
			ch <- conn
		}
	}()
	select {
	case conn := <-ch:
		if err := conn.SetDeadline(time.Now().Add(5 * time.Second)); err != nil {
			t.Fatal(err)
		}
		return conn
	case err := <-errs:
		t.Fatal(err)
	case <-time.After(3 * time.Second):
		t.Fatal("Accept deadline")
	}
	return nil
}
func TestRawEndToEndHalfCloseAndMetadata(t *testing.T) {
	s, m, config := runningServer(t)
	creds := identity(t)
	grant(t, m, creds, "alice.example.com")
	c := connected(t, s, config, creds)
	l := listenRaw(t, c, "Alice.Example.com.")
	peer, done := routePublic(t, s, "foo.alice.example.com", []byte("peeked:"))
	payload := bytes.Repeat([]byte{0, 1, 255, 42}, 32768)
	go func() {
		if _, err := peer.Write(payload); err != nil {
			return
		}
		_ = peer.CloseWrite()
	}()
	conn := accept(t, l)
	if conn.RemoteAddr().String() != peer.LocalAddr().String() || conn.LocalAddr().String() != "alice.example.com:443" {
		t.Fatalf("metadata: %s %s", conn.RemoteAddr(), conn.LocalAddr())
	}
	got, err := io.ReadAll(conn)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, append([]byte("peeked:"), payload...)) {
		t.Fatal("raw bytes altered or prefix replayed incorrectly")
	}
	if _, err := conn.Write([]byte("reply after EOF")); err != nil {
		t.Fatal(err)
	}
	if err := conn.(interface{ CloseWrite() error }).CloseWrite(); err != nil {
		t.Fatal(err)
	}
	response, err := io.ReadAll(peer)
	if err != nil || string(response) != "reply after EOF" {
		t.Fatalf("reply %q %v", response, err)
	}
	if err := conn.Close(); err != nil {
		t.Fatal(err)
	}
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	if len(c.Routes()) != 1 || len(c.Listening()) != 1 || c.Status() != "connected" {
		t.Fatal("introspection")
	}
}
func TestRawMultiInstanceAndSpecificListener(t *testing.T) {
	s, m, config := runningServer(t)
	creds := identity(t)
	grant(t, m, creds, "alice.example.com")
	a := connected(t, s, config, creds)
	b := connected(t, s, config, creds)
	la := listenRaw(t, a, "alice.example.com")
	lb := listenRaw(t, b, "alice.example.com")
	for i := range 6 {
		peer, done := routePublic(t, s, "foo.alice.example.com", nil)
		l := la
		if i%2 == 1 {
			l = lb
		}
		conn := accept(t, l)
		if _, err := peer.Write([]byte("request")); err != nil {
			t.Fatal(err)
		}
		if err := peer.CloseWrite(); err != nil {
			t.Fatal(err)
		}
		if _, err := io.ReadAll(conn); err != nil {
			t.Fatal(err)
		}
		if _, err := conn.Write([]byte("response")); err != nil {
			t.Fatal(err)
		}
		if err := conn.(interface{ CloseWrite() error }).CloseWrite(); err != nil {
			t.Fatal(err)
		}
		if _, err := io.ReadAll(peer); err != nil {
			t.Fatal(err)
		}
		if err := conn.Close(); err != nil {
			t.Fatal(err)
		}
		if err := <-done; err != nil {
			t.Fatal(err)
		}
	}
	specific := listenRaw(t, b, "api.alice.example.com")
	peer, done := routePublic(t, s, "v1.api.alice.example.com", nil)
	conn := accept(t, specific)
	if err := peer.CloseWrite(); err != nil {
		t.Fatal(err)
	}
	if _, err := io.ReadAll(conn); err != nil {
		t.Fatal(err)
	}
	if err := conn.(interface{ CloseWrite() error }).CloseWrite(); err != nil {
		t.Fatal(err)
	}
	if _, err := io.ReadAll(peer); err != nil {
		t.Fatal(err)
	}
	if err := conn.Close(); err != nil {
		t.Fatal(err)
	}
	if err := <-done; err != nil {
		t.Fatal(err)
	}
}
func TestListenerCloseDoesNotKillAcceptedStream(t *testing.T) {
	s, m, config := runningServer(t)
	creds := identity(t)
	grant(t, m, creds, "alice.example.com")
	c := connected(t, s, config, creds)
	l := listenRaw(t, c, "alice.example.com")
	peer, done := routePublic(t, s, "alice.example.com", nil)
	conn := accept(t, l)
	if err := l.Close(); err != nil {
		t.Fatal(err)
	}
	if _, ok := m.Select("alice.example.com", "tls"); ok {
		t.Fatal("unadvertise left pool")
	}
	if _, err := l.Accept(); !errors.Is(err, net.ErrClosed) {
		t.Fatalf("closed Accept: %v", err)
	}
	if _, err := peer.Write([]byte("still alive")); err != nil {
		t.Fatal(err)
	}
	if err := peer.CloseWrite(); err != nil {
		t.Fatal(err)
	}
	got, err := io.ReadAll(conn)
	if err != nil || string(got) != "still alive" {
		t.Fatalf("accepted stream killed: %q %v", got, err)
	}
	if err := conn.(interface{ CloseWrite() error }).CloseWrite(); err != nil {
		t.Fatal(err)
	}
	if _, err := io.ReadAll(peer); err != nil {
		t.Fatal(err)
	}
	if err := conn.Close(); err != nil {
		t.Fatal(err)
	}
	if err := <-done; err != nil {
		t.Fatal(err)
	}
}
func TestRouteEditAndRevocationAbortTraffic(t *testing.T) {
	for _, revoke := range []bool{false, true} {
		t.Run(map[bool]string{false: "edit", true: "revoke"}[revoke], func(t *testing.T) {
			s, m, config := runningServer(t)
			creds := identity(t)
			grant(t, m, creds, "alice.example.com")
			c := connected(t, s, config, creds)
			l := listenRaw(t, c, "alice.example.com")
			peer, done := routePublic(t, s, "alice.example.com", nil)
			conn := accept(t, l)
			if revoke {
				if err := m.Revoke(creds.PublicKey(), "test"); err != nil {
					t.Fatal(err)
				}
			} else {
				grant(t, m, creds, "other.example.com")
			}
			buf := make([]byte, 1)
			if _, err := peer.Read(buf); err == nil {
				t.Fatal("public stream stayed open")
			}
			if _, err := conn.Read(buf); err == nil {
				t.Fatal("client stream stayed open")
			}
			_ = conn.Close()
			<-done
			result := make(chan error, 1)
			go func() { _, err := l.Accept(); result <- err }()
			select {
			case err := <-result:
				if err == nil {
					t.Fatal("withdrawn listener accepted")
				}
			case <-time.After(3 * time.Second):
				t.Fatal("Accept not unblocked")
			}
		})
	}
}
func TestStreamDeadlinesAndCloseUnblock(t *testing.T) {
	s, m, config := runningServer(t)
	creds := identity(t)
	grant(t, m, creds, "alice.example.com")
	c := connected(t, s, config, creds)
	l := listenRaw(t, c, "alice.example.com")
	peer, done := routePublic(t, s, "alice.example.com", nil)
	conn := accept(t, l)
	if err := conn.SetReadDeadline(time.Now().Add(20 * time.Millisecond)); err != nil {
		t.Fatal(err)
	}
	var b [1]byte
	if _, err := conn.Read(b[:]); err == nil {
		t.Fatal("read deadline ignored")
	} else {
		var timeout net.Error
		if !errors.As(err, &timeout) || !timeout.Timeout() {
			t.Fatalf("not timeout: %v", err)
		}
	}
	if err := conn.SetReadDeadline(time.Time{}); err != nil {
		t.Fatal(err)
	}
	result := make(chan error, 1)
	go func() { _, err := conn.Read(b[:]); result <- err }()
	_ = conn.Close()
	select {
	case err := <-result:
		if err == nil {
			t.Fatal("Close did not fail Read")
		}
	case <-time.After(time.Second):
		t.Fatal("Close did not unblock Read")
	}
	_ = peer.Close()
	<-done
}

func TestDialTrustAndScopeFailures(t *testing.T) {
	s, m, config := runningServer(t)
	creds := identity(t)
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	if _, err := Dial(ctx, s.Addr(), WithCredentials(creds), WithTLSConfig(config)); err == nil {
		t.Fatal("unknown identity dial accepted")
	}
	grant(t, m, creds, "alice.example.com")
	if _, err := Dial(ctx, s.Addr(), WithCredentials(creds)); err == nil {
		t.Fatal("untrusted server accepted")
	}
	c := connected(t, s, config, creds)
	if _, err := c.ListenRaw(context.Background(), "outside.example.com"); err == nil {
		t.Fatal("scope expanded")
	}
	if _, err := c.ListenRaw(context.Background(), "*.alice.example.com"); err == nil {
		t.Fatal("wildcard accepted")
	}
	listenRaw(t, c, "alice.example.com")
	if _, err := c.ListenRaw(context.Background(), "alice.example.com"); err == nil {
		t.Fatal("duplicate listener accepted")
	}
	var wg sync.WaitGroup
	for range 8 {
		wg.Add(1)
		go func() { defer wg.Done(); c.Routes(); c.Listening(); c.Status() }()
	}
	wg.Wait()
}

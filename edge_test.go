package tunnel

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"io"
	"math/big"
	"net"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/fasmide/tunnel/internal/server"
)

func applicationCertificate(t testing.TB) (tls.Certificate, *x509.CertPool) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{SerialNumber: big.NewInt(2), Subject: pkix.Name{CommonName: "application"}, DNSNames: []string{"alice.example.com", "*.alice.example.com", "*.api.alice.example.com"}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
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
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: priv, Leaf: leaf}, roots
}
func serveApplication(t testing.TB, l net.Listener, cert tls.Certificate, label string) {
	t.Helper()
	app := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, err := io.ReadAll(r.Body)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		w.Header().Set("X-Application", label)
		if _, err := w.Write(append([]byte(label+":"), body...)); err != nil {
			return
		}
	}), ReadHeaderTimeout: 3 * time.Second}
	done := make(chan error, 1)
	go func() { done <- app.Serve(tls.NewListener(l, &tls.Config{Certificates: []tls.Certificate{cert}})) }()
	t.Cleanup(func() {
		_ = app.Close()
		select {
		case <-done:
		case <-time.After(3 * time.Second):
			t.Error("application shutdown stalled")
		}
	})
}
func edgeRequest(t *testing.T, edge *server.TLSEdge, roots *x509.CertPool, host string) string {
	t.Helper()
	transport := &http.Transport{TLSClientConfig: &tls.Config{RootCAs: roots}, DisableKeepAlives: true, DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, "tcp", edge.Addr().String())
	}}
	defer transport.CloseIdleConnections()
	client := &http.Client{Transport: transport, Timeout: 3 * time.Second}
	resp, err := client.Post("https://"+host+"/echo", "application/octet-stream", strings.NewReader("real HTTPS request"))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("HTTP status: %s", resp.Status)
	}
	return string(body)
}
func TestHTTPSThroughSNIEdge(t *testing.T) {
	s, m, config := runningServer(t)
	creds := identity(t)
	grant(t, m, creds, "alice.example.com")
	client := connected(t, s, config, creds)
	raw := listenRaw(t, client, "alice.example.com")
	cert, roots := applicationCertificate(t)
	serveApplication(t, raw, cert, "parent")
	edge, err := s.ListenTLS("127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = edge.Close() })
	for _, host := range []string{"alice.example.com", "foo.alice.example.com"} {
		if got := edgeRequest(t, edge, roots, host); got != "parent:real HTTPS request" {
			t.Fatalf("%s: %s", host, got)
		}
	}
	specific := listenRaw(t, client, "api.alice.example.com")
	serveApplication(t, specific, cert, "specific")
	if got := edgeRequest(t, edge, roots, "v1.api.alice.example.com"); got != "specific:real HTTPS request" {
		t.Fatalf("specific route: %s", got)
	}
	// The server knows only the QUIC transport certificate; this certificate and
	// its key are supplied exclusively to the application listener/client trust.
}
func TestSNIEdgeMultiInstanceAndOfflineChild(t *testing.T) {
	s, m, config := runningServer(t)
	creds := identity(t)
	grant(t, m, creds, "alice.example.com")
	a := connected(t, s, config, creds)
	b := connected(t, s, config, creds)
	cert, roots := applicationCertificate(t)
	serveApplication(t, listenRaw(t, a, "alice.example.com"), cert, "a")
	serveApplication(t, listenRaw(t, b, "alice.example.com"), cert, "b")
	edge, err := s.ListenTLS("127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = edge.Close() })
	for i := range 6 {
		want := "a:real HTTPS request"
		if i%2 == 1 {
			want = "b:real HTTPS request"
		}
		if got := edgeRequest(t, edge, roots, "foo.alice.example.com"); got != want {
			t.Fatalf("round-robin %d: %s", i, got)
		}
	}
	child := identity(t)
	grant(t, m, child, "api.alice.example.com")
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	dialer := tls.Dialer{Config: &tls.Config{RootCAs: roots, ServerName: "api.alice.example.com"}}
	if conn, err := dialer.DialContext(ctx, "tcp", edge.Addr().String()); err == nil {
		_ = conn.Close()
		t.Fatal("offline child fell back to parent")
	}
	if got := edgeRequest(t, edge, roots, "foo.alice.example.com"); got == "" {
		t.Fatal("unrelated parent traffic blocked")
	}
}
func TestSNIEdgeALPNPassthrough(t *testing.T) {
	s, m, config := runningServer(t)
	creds := identity(t)
	grant(t, m, creds, "alice.example.com")
	c := connected(t, s, config, creds)
	raw := listenRaw(t, c, "alice.example.com")
	cert, roots := applicationCertificate(t)
	edge, err := s.ListenTLS("127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = edge.Close() })
	completed := make(chan error, 1)
	go func() {
		conn, err := raw.Accept()
		if err != nil {
			completed <- err
			return
		}
		defer func() { _ = conn.Close() }()
		local := tls.Server(conn, &tls.Config{Certificates: []tls.Certificate{cert}, NextProtos: []string{"acme-tls/1"}})
		if err := local.SetDeadline(time.Now().Add(3 * time.Second)); err != nil {
			completed <- err
			return
		}
		err = local.Handshake()
		if err == nil && local.ConnectionState().NegotiatedProtocol != "acme-tls/1" {
			err = io.ErrUnexpectedEOF
		}
		completed <- err
	}()
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	dialer := tls.Dialer{Config: &tls.Config{RootCAs: roots, ServerName: "alice.example.com", NextProtos: []string{"acme-tls/1"}}}
	conn, err := dialer.DialContext(ctx, "tcp", edge.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = conn.Close() }()
	if conn.(*tls.Conn).ConnectionState().NegotiatedProtocol != "acme-tls/1" {
		t.Fatal("ALPN was altered")
	}
	if err := <-completed; err != nil {
		t.Fatal(err)
	}
	// This proves ALPN transparency, not ACME issuance/validation or HA reliability.
}
func TestSNIEdgeRejectsMissingUnknownAndPlaintext(t *testing.T) {
	s, _, _ := runningServer(t)
	edge, err := s.ListenTLS("127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = edge.Close() })
	for _, name := range []string{"", "unknown.example.com"} {
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		// Verification is disabled only in this negative test; without visible
		// SNI / an eligible pool the edge must close before any certificate.
		config := &tls.Config{ServerName: name, InsecureSkipVerify: true}
		dialer := tls.Dialer{Config: config}
		if conn, err := dialer.DialContext(ctx, "tcp", edge.Addr().String()); err == nil {
			_ = conn.Close()
			t.Fatal("unroutable TLS admitted")
		}
		cancel()
	}
	conn, err := net.Dial("tcp", edge.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = conn.Close() }()
	if err := conn.SetDeadline(time.Now().Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	if _, err := conn.Write([]byte("GET / HTTP/1.1\r\nHost: unknown.example.com\r\n\r\n")); err != nil {
		t.Fatal(err)
	}
	var b [1]byte
	if _, err := conn.Read(b[:]); err == nil {
		t.Fatal("plaintext accepted on TLS edge")
	}
}
func TestSNIEdgeShutdownClosesPartialHello(t *testing.T) {
	s, _, _ := runningServer(t)
	edge, err := s.ListenTLS("127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	conn, err := net.Dial("tcp", edge.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = conn.Close() }()
	if _, err := conn.Write([]byte{22, 3}); err != nil {
		t.Fatal(err)
	}
	done := make(chan struct{})
	go func() { _ = edge.Close(); close(done) }()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("edge Close blocked on partial ClientHello")
	}
	if conn, err := net.DialTimeout("tcp", edge.Addr().String(), time.Second); err == nil {
		_ = conn.Close()
		t.Fatal("closed edge still listening")
	}
}

func TestServerShutdownOwnsEdges(t *testing.T) {
	s, _, _ := runningServer(t)
	edge, err := s.ListenTLS("127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	conn, err := net.Dial("tcp", edge.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = conn.Close() }()
	if _, err := conn.Write([]byte{22, 3}); err != nil {
		t.Fatal(err)
	}
	done := make(chan struct{})
	go func() { _ = s.Close(); close(done) }()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("server Close left edge blocked")
	}
	if edge, err := s.ListenTLS("127.0.0.1:0"); err == nil {
		_ = edge.Close()
		t.Fatal("edge started after shutdown")
	}
}

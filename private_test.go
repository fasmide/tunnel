package tunnel

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"io"
	"net"
	"net/http"
	"testing"
	"time"

	"github.com/fasmide/tunnel/internal/server"
	"github.com/fasmide/tunnel/internal/transportpki"
	"github.com/fasmide/tunnel/internal/wire"
)

func privateClient(t *testing.T) (*Client, *server.Server, *server.Manager, *transportpki.Authority, Storage) {
	t.Helper()
	a, err := transportpki.Open(MemoryStorage(), "alice.example.com", time.Now().Add(-10*24*time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	m := server.NewManager()
	s, err := server.ListenWithAuthority("127.0.0.1:0", a.Config(), m, a)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = s.Close() })
	storage := MemoryStorage()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_, err = BootstrapTrust(ctx, s.Addr(), TrustRequest{Storage: storage, ServerName: "alice.example.com", Fingerprint: a.Fingerprint()})
	if err != nil {
		t.Fatal(err)
	}
	trust, err := LoadTransportTLS(storage, s.Addr(), "alice.example.com")
	if err != nil {
		t.Fatal(err)
	}
	creds, err := RequestJoin(ctx, s.Addr(), JoinRequest{Storage: storage, Routes: []string{"alice.example.com"}, TLSConfig: trust})
	if err != nil {
		t.Fatal(err)
	}
	grant(t, m, creds, "alice.example.com")
	c := connected(t, s, trust, creds)
	return c, s, m, a, storage
}
func TestListenPrivateHTTPSDescendantsAndCarveout(t *testing.T) {
	c, s, m, a, storage := privateClient(t)
	l, err := c.ListenPrivate(context.Background(), "alice.example.com")
	if err != nil {
		t.Fatal(err)
	}
	servePlainApplication(t, l)
	block, _ := pem.Decode(a.PEM())
	ca, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	roots := x509.NewCertPool()
	roots.AddCert(ca)
	edge, err := s.ListenTLS("127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"alice.example.com", "deep.foo.alice.example.com"} {
		tr := &http.Transport{TLSClientConfig: &tls.Config{RootCAs: roots, ServerName: name}, DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			return (&net.Dialer{}).DialContext(ctx, network, edge.Addr().String())
		}}
		resp, err := (&http.Client{Transport: tr, Timeout: 3 * time.Second}).Get("https://" + name + "/")
		if err != nil {
			t.Fatal(err)
		}
		body, err := io.ReadAll(resp.Body)
		_ = resp.Body.Close()
		tr.CloseIdleConnections()
		if err != nil || string(body) != "client-side TLS" {
			t.Fatalf("body %s %v", body, err)
		}
		if len(resp.TLS.PeerCertificates[0].DNSNames) != 1 || resp.TLS.PeerCertificates[0].DNSNames[0] != name {
			t.Fatal("non-exact leaf")
		}
	}
	first, err := storage.Get("private/cert/alice.example.com")
	if err != nil {
		t.Fatal(err)
	}
	if err := l.Close(); err != nil {
		t.Fatal(err)
	}
	next, err := c.ListenPrivate(context.Background(), "alice.example.com")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = next.Close() }()
	second, err := storage.Get("private/cert/alice.example.com")
	if err != nil || !bytes.Equal(first, second) {
		t.Fatal("cached certificate changed")
	}
	bob := identity(t)
	grant(t, m, bob, "foo.alice.example.com")
	eventually(t, func() bool { c.mu.Lock(); defer c.mu.Unlock(); return !allowed(c.routes, "deep.foo.alice.example.com") })
	manager := &privateManager{client: c, cache: map[string]*tls.Certificate{}}
	if _, err := manager.certificate(context.Background(), "deep.foo.alice.example.com"); err == nil {
		t.Fatal("cached carved-out name allowed")
	}
	if err := m.Revoke(c.options.credentials.PublicKey(), "test"); err != nil {
		t.Fatal(err)
	}
	eventually(t, func() bool { return c.Status() == "denied" })
	if _, err := manager.certificate(context.Background(), "alice.example.com"); err == nil {
		t.Fatal("revoked certificate accepted")
	}
}
func TestPrivateDualAlgorithms(t *testing.T) {
	c, _, _, a, storage := privateClient(t)
	l, err := c.ListenPrivate(context.Background(), "alice.example.com")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = l.Close() }()
	block, _ := pem.Decode(a.PEM())
	ca, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	if ca.PublicKeyAlgorithm != x509.ECDSA || ca.SignatureAlgorithm != x509.ECDSAWithSHA256 {
		t.Fatal("new CA is not browser-compatible P-256")
	}
	config := l.(*rawListener).tlsConfig
	for _, tc := range []struct {
		scheme    tls.SignatureScheme
		algorithm x509.PublicKeyAlgorithm
		prefix    string
	}{{tls.Ed25519, x509.Ed25519, "private/cert/"}, {tls.ECDSAWithP256AndSHA256, x509.ECDSA, "private/cert-p256/"}} {
		cert, err := config.GetCertificate(&tls.ClientHelloInfo{ServerName: "alice.example.com", SupportedVersions: []uint16{tls.VersionTLS13}, SignatureSchemes: []tls.SignatureScheme{tc.scheme}})
		if err != nil {
			t.Fatal(err)
		}
		if cert.Leaf.PublicKeyAlgorithm != tc.algorithm || cert.Leaf.SignatureAlgorithm != x509.ECDSAWithSHA256 {
			t.Fatal("wrong leaf/issuer algorithm")
		}
		if _, err := storage.Get(tc.prefix + "alice.example.com"); err != nil {
			t.Fatal("dual key not persisted", err)
		}
	}
	if _, err := config.GetCertificate(&tls.ClientHelloInfo{ServerName: "alice.example.com", SupportedVersions: []uint16{tls.VersionTLS13}, SignatureSchemes: []tls.SignatureScheme{tls.PSSWithSHA256}}); err == nil {
		t.Fatal("unsupported client selected a certificate")
	}
}

func TestPrivatePersistenceAndRenewal(t *testing.T) {
	c, _, _, a, storage := privateClient(t)
	_, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	csr, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{DNSNames: []string{"alice.example.com"}}, key)
	if err != nil {
		t.Fatal(err)
	}
	chain, err := a.Issue("alice.example.com", csr, time.Now().Add(-6*24*time.Hour-time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	encoded, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	old, err := json.Marshal(privateCertificate{Key: encoded, Chain: chain})
	if err != nil {
		t.Fatal(err)
	}
	if err := storage.Put("private/cert/alice.example.com", old); err != nil {
		t.Fatal(err)
	}
	manager := &privateManager{client: c, cache: map[string]*tls.Certificate{}}
	renewed, err := manager.certificate(context.Background(), "alice.example.com")
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(renewed.Certificate[0], chain[0]) {
		t.Fatal("near-expiry leaf not renewed")
	}
	c.storage = brokenState{storage}
	manager = &privateManager{client: c, cache: map[string]*tls.Certificate{}}
	if _, err := manager.certificate(context.Background(), "new.alice.example.com"); err == nil {
		t.Fatal("certificate used despite persistence failure")
	}
	c.storage = storage
	if err := storage.Put("private/cert/alice.example.com", []byte("corrupt")); err != nil {
		t.Fatal(err)
	}
	manager = &privateManager{client: c, cache: map[string]*tls.Certificate{}}
	if _, err := manager.certificate(context.Background(), "alice.example.com"); err == nil {
		t.Fatal("corrupt private state replaced")
	}
}
func TestPrivateUnavailableInExternalMode(t *testing.T) {
	s, m, trust := runningServer(t)
	creds := identity(t)
	grant(t, m, creds, "alice.example.com")
	c := connected(t, s, trust, creds)
	if _, err := c.ListenPrivate(context.Background(), "alice.example.com"); err == nil {
		t.Fatal("external leaf used as CA")
	}
}
func TestPrivateIssuerDeniesOutsideNamespace(t *testing.T) {
	c, _, m, _, _ := privateClient(t)
	grant(t, m, c.options.credentials, "outside.example.com")
	eventually(t, func() bool { return len(c.Routes()) == 1 && c.Routes()[0] == "outside.example.com" })
	_, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	csr, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{DNSNames: []string{"outside.example.com"}}, key)
	if err != nil {
		t.Fatal(err)
	}
	data, err := c.rpc(context.Background(), &wire.IssueCertificate{Envelope: wire.Envelope{Type: "IssueCertificate"}, Name: "outside.example.com", CSR: base64.StdEncoding.EncodeToString(csr)})
	if err != nil {
		t.Fatal(err)
	}
	var result wire.CertificateResult
	if err := wire.Decode(data, &result, "code"); err != nil {
		t.Fatal(err)
	}
	if result.Code == "ok" || len(result.Chain) != 0 {
		t.Fatal("outside namespace signed")
	}
}

package tunnel

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/fasmide/tunnel/internal/wire"
	"golang.org/x/crypto/acme"
	"golang.org/x/crypto/acme/autocert"
)

func servePlainApplication(t *testing.T, l net.Listener) {
	t.Helper()
	app := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, "client-side TLS")
	}), ReadHeaderTimeout: 3 * time.Second}
	done := make(chan error, 1)
	go func() { done <- app.Serve(l) }()
	t.Cleanup(func() {
		_ = app.Close()
		select {
		case <-done:
		case <-time.After(time.Second):
			t.Error("application did not close")
		}
	})
}
func TestListenTLSHTTPS(t *testing.T) {
	s, m, trust := runningServer(t)
	creds := identity(t)
	grant(t, m, creds, "alice.example.com")
	c := connected(t, s, trust, creds)
	cert, roots := applicationCertificate(t)
	config := &tls.Config{Certificates: []tls.Certificate{cert}}
	l, err := c.ListenTLS(context.Background(), "alice.example.com", config)
	if err != nil {
		t.Fatal(err)
	}
	config.Certificates = nil // listener owns a cloned configuration
	servePlainApplication(t, l)
	edge, err := s.ListenTLS("127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	transport := &http.Transport{TLSClientConfig: &tls.Config{RootCAs: roots}, DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, "tcp", edge.Addr().String())
	}}
	defer transport.CloseIdleConnections()
	resp, err := (&http.Client{Transport: transport, Timeout: 3 * time.Second}).Get("https://foo.alice.example.com/")
	if err != nil {
		t.Fatal(err)
	}
	body, err := io.ReadAll(resp.Body)
	if closeErr := resp.Body.Close(); closeErr != nil {
		t.Fatal(closeErr)
	}
	if err != nil || string(body) != "client-side TLS" {
		t.Fatalf("body %q %v", body, err)
	}
	other := connected(t, s, trust, creds)
	if _, err := other.ListenRaw(context.Background(), "alice.example.com"); err == nil {
		t.Fatal("mixed TLS modes pooled")
	}
	if _, err := c.ListenTLS(context.Background(), "bad.example.com", nil); err == nil {
		t.Fatal("nil TLS config accepted")
	}
}
func TestListenTLSClosePreservesAcceptedConnection(t *testing.T) {
	s, m, trust := runningServer(t)
	creds := identity(t)
	grant(t, m, creds, "alice.example.com")
	c := connected(t, s, trust, creds)
	cert, roots := applicationCertificate(t)
	l, err := c.ListenTLS(context.Background(), "alice.example.com", &tls.Config{Certificates: []tls.Certificate{cert}})
	if err != nil {
		t.Fatal(err)
	}
	edge, err := s.ListenTLS("127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	peer, err := tls.Dial("tcp", edge.Addr().String(), &tls.Config{RootCAs: roots, ServerName: "alice.example.com"})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = peer.Close() }()
	conn := accept(t, l)
	defer func() { _ = conn.Close() }()
	if _, ok := conn.(*tls.Conn); !ok {
		t.Fatal("Accept did not return TLS connection")
	}
	if err := l.Close(); err != nil {
		t.Fatal(err)
	}
	if err := peer.SetDeadline(time.Now().Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	if _, err := peer.Write([]byte("alive")); err != nil {
		t.Fatal(err)
	}
	var data [5]byte
	if _, err := io.ReadFull(conn, data[:]); err != nil || string(data[:]) != "alive" {
		t.Fatalf("accepted TLS connection killed: %v", err)
	}
}

func TestACMEAccountPersistence(t *testing.T) {
	store := MemoryStorage()
	first, err := loadACMEAccount(store)
	if err != nil {
		t.Fatal(err)
	}
	second, err := loadACMEAccount(store)
	if err != nil || first.D.Cmp(second.D) != 0 {
		t.Fatal("account changed on reload")
	}
	if _, err := loadACMEAccount(brokenState{MemoryStorage()}); err == nil {
		t.Fatal("account used after failed persistence")
	}
	if err := store.Put("acme/account", []byte("corrupt")); err != nil {
		t.Fatal(err)
	}
	if _, err := loadACMEAccount(store); err == nil {
		t.Fatal("corrupt account silently replaced")
	}
}

func TestACMECacheAndPolicy(t *testing.T) {
	storage := MemoryStorage()
	cache := acmeCache{storage}
	ctx := context.Background()
	for key, want := range map[string]string{"acme_account+key": "acme/account", "alice.example.com": "acme/cert/alice.example.com", "alice.example.com+token": "acme/challenge/alice.example.com", "alice.example.com+rsa": "acme/cert-rsa/alice.example.com"} {
		if err := cache.Put(ctx, key, []byte("value")); err != nil {
			t.Fatal(err)
		}
		if data, err := storage.Get(want); err != nil || string(data) != "value" {
			t.Fatalf("mapping %s: %v", key, err)
		}
		if err := cache.Delete(ctx, key); err != nil {
			t.Fatal(err)
		}
		if _, err := cache.Get(ctx, key); !errors.Is(err, autocert.ErrCacheMiss) {
			t.Fatal("cache miss not mapped")
		}
	}
	if err := cache.Put(ctx, "../escape", nil); err == nil {
		t.Fatal("unsafe cache key accepted")
	}
	s, m, trust := runningServer(t)
	creds := identity(t)
	grant(t, m, creds, "alice.example.com")
	c := connected(t, s, trust, creds)
	if err := c.acmeHostPolicy(ctx, "foo.alice.example.com"); err != nil {
		t.Fatal(err)
	}
	if err := c.acmeHostPolicy(ctx, "evilalice.example.com"); err == nil {
		t.Fatal("scope policy expanded")
	}
	child := identity(t)
	grant(t, m, child, "api.alice.example.com")
	_, err := c.rpc(ctx, &wire.Envelope{Type: "RouteList"})
	if err != nil {
		t.Fatal(err)
	}
	if err := c.acmeHostPolicy(ctx, "api.alice.example.com"); err == nil {
		t.Fatal("carve-out allowed ACME")
	}
}

func TestACMECertificateErrorReporting(t *testing.T) {
	ctx := context.Background()
	s, m, trust := runningServer(t)
	creds := identity(t)
	grant(t, m, creds, "alice.example.com")
	c := connected(t, s, trust, creds)

	want := x509.UnknownAuthorityError{}
	var reportedHost string
	var reportedErr error
	if err := WithACMEErrorHandler(func(host string, err error) {
		reportedHost, reportedErr = host, err
	})(&c.options); err != nil {
		t.Fatal(err)
	}
	get := c.acmeGetCertificate(ctx, func(*tls.ClientHelloInfo) (*tls.Certificate, error) {
		return nil, want
	})
	if _, err := get(&tls.ClientHelloInfo{ServerName: "alice.example.com"}); !errors.Is(err, want) {
		t.Fatalf("certificate error lost: %v", err)
	}
	if reportedHost != "alice.example.com" || !errors.Is(reportedErr, want) {
		t.Fatalf("error not reported: host=%q err=%v", reportedHost, reportedErr)
	}

	reportedErr = nil
	cert := &tls.Certificate{}
	get = c.acmeGetCertificate(ctx, func(*tls.ClientHelloInfo) (*tls.Certificate, error) {
		return cert, nil
	})
	if got, err := get(&tls.ClientHelloInfo{ServerName: "alice.example.com"}); got != cert || err != nil || reportedErr != nil {
		t.Fatalf("successful certificate acquisition: cert=%p err=%v reported=%v", got, err, reportedErr)
	}
	if err := WithACMEErrorHandler(nil)(&c.options); err != nil {
		t.Fatal(err)
	}
	get = c.acmeGetCertificate(ctx, func(*tls.ClientHelloInfo) (*tls.Certificate, error) {
		return nil, want
	})
	if _, err := get(&tls.ClientHelloInfo{ServerName: "alice.example.com"}); !errors.Is(err, want) {
		t.Fatalf("nil handler changed certificate error: %v", err)
	}
}

// Local RFC8555 test CA. It validates the real TLS-ALPN challenge through the
// public edge, then signs the CSR. No external network / Let's Encrypt calls.
func TestACMEIssuanceThroughTunnelAndCachedRestart(t *testing.T) {
	s, m, trust := runningServer(t)
	creds := identity(t)
	grant(t, m, creds, "alice.example.com")
	edge, err := s.ListenTLS("127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{SerialNumber: big.NewInt(99), Subject: pkix.Name{CommonName: "local test CA"}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(365 * 24 * time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign}
	caDER, err := x509.CreateCertificate(rand.Reader, template, template, &caKey.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	ca, err := x509.ParseCertificate(caDER)
	if err != nil {
		t.Fatal(err)
	}
	roots := x509.NewCertPool()
	roots.AddCert(ca)
	var base string
	var nonce atomic.Uint64
	var orders atomic.Int32
	var validated atomic.Bool
	var certPEM []byte
	var mu sync.Mutex
	domain := "foo.alice.example.com"
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Replay-Nonce", base64.RawURLEncoding.EncodeToString([]byte(time.Now().String()+string(rune(nonce.Add(1))))))
		w.Header().Set("Content-Type", "application/json")
		send := func(status int, value any) {
			w.WriteHeader(status)
			if err := json.NewEncoder(w).Encode(value); err != nil {
				t.Error(err)
			}
		}
		order := func(status string) map[string]any {
			return map[string]any{"status": status, "identifiers": []map[string]string{{"type": "dns", "value": domain}}, "authorizations": []string{base + "/auth"}, "finalize": base + "/finalize", "certificate": base + "/cert"}
		}
		switch r.URL.Path {
		case "/directory":
			send(http.StatusOK, map[string]string{"newNonce": base + "/nonce", "newAccount": base + "/account", "newOrder": base + "/new-order"})
		case "/nonce":
			w.WriteHeader(http.StatusOK)
		case "/account":
			w.Header().Set("Location", base+"/account/1")
			send(201, map[string]string{"status": "valid", "orders": base + "/orders"})
		case "/new-order":
			orders.Add(1)
			w.Header().Set("Location", base+"/order")
			send(201, order("pending"))
		case "/auth":
			status := "pending"
			if validated.Load() {
				status = "valid"
			}
			send(200, map[string]any{"status": status, "identifier": map[string]string{"type": "dns", "value": domain}, "challenges": []map[string]string{{"type": "http-01", "url": base + "/http-challenge", "token": "unused"}, {"type": "tls-alpn-01", "url": base + "/challenge", "token": "local-token"}}})
		case "/challenge":
			var jws struct {
				Protected string `json:"protected"`
			}
			if err := json.NewDecoder(r.Body).Decode(&jws); err != nil {
				t.Error(err)
				return
			}
			protected, _ := base64.RawURLEncoding.DecodeString(jws.Protected)
			_ = protected // Account key is checked below via its persisted PEM.
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			dialer := tls.Dialer{Config: &tls.Config{ServerName: domain, InsecureSkipVerify: true, NextProtos: []string{acme.ALPNProto}}}
			conn, err := dialer.DialContext(ctx, "tcp", edge.Addr().String())
			if err != nil {
				t.Error(err)
				send(400, map[string]string{"type": "urn:ietf:params:acme:error:unauthorized"})
				return
			}
			state := conn.(*tls.Conn).ConnectionState()
			_ = conn.Close()
			accountPEM, err := creds.storage.Get("acme/account")
			if err != nil {
				t.Error(err)
				send(400, map[string]string{"detail": "missing account"})
				return
			}
			block, _ := pem.Decode(accountPEM)
			accountKey, err := x509.ParseECPrivateKey(block.Bytes)
			if err != nil {
				t.Error(err)
				return
			}
			thumb, err := acme.JWKThumbprint(&accountKey.PublicKey)
			if err != nil {
				t.Error(err)
				return
			}
			want := sha256.Sum256([]byte("local-token." + thumb))
			found := false
			for _, ext := range state.PeerCertificates[0].Extensions {
				if ext.Id.Equal(asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 1, 31}) && ext.Critical {
					var value []byte
					_, err := asn1.Unmarshal(ext.Value, &value)
					found = err == nil && string(value) == string(want[:])
				}
			}
			if state.NegotiatedProtocol != acme.ALPNProto || !found {
				t.Error("invalid TLS-ALPN challenge certificate")
				send(400, map[string]string{"detail": "invalid challenge"})
				return
			}
			validated.Store(true)
			send(200, map[string]string{"status": "valid", "type": "tls-alpn-01", "url": base + "/challenge", "token": "local-token"})
		case "/order":
			status := "ready"
			mu.Lock()
			if len(certPEM) > 0 {
				status = "valid"
			}
			mu.Unlock()
			send(200, order(status))
		case "/finalize":
			var jws struct {
				Payload string `json:"payload"`
			}
			if err := json.NewDecoder(r.Body).Decode(&jws); err != nil {
				t.Error(err)
				return
			}
			payload, _ := base64.RawURLEncoding.DecodeString(jws.Payload)
			var request struct {
				CSR string `json:"csr"`
			}
			if err := json.Unmarshal(payload, &request); err != nil {
				t.Error(err)
				return
			}
			der, _ := base64.RawURLEncoding.DecodeString(request.CSR)
			csr, err := x509.ParseCertificateRequest(der)
			if err != nil || csr.CheckSignature() != nil {
				t.Error("invalid CSR")
				return
			}
			leaf := &x509.Certificate{SerialNumber: big.NewInt(100), DNSNames: csr.DNSNames, NotBefore: time.Now().Add(-time.Minute), NotAfter: time.Now().Add(90 * 24 * time.Hour), KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
			der, err = x509.CreateCertificate(rand.Reader, leaf, ca, csr.PublicKey, caKey)
			if err != nil {
				t.Error(err)
				return
			}
			mu.Lock()
			certPEM = append(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caDER})...)
			mu.Unlock()
			send(200, order("valid"))
		case "/cert":
			w.Header().Set("Content-Type", "application/pem-certificate-chain")
			mu.Lock()
			_, _ = w.Write(certPEM)
			mu.Unlock()
		default:
			t.Errorf("unexpected CA endpoint %s", r.URL.Path)
			http.Error(w, "unsupported", http.StatusBadRequest)
		}
	})
	caServer := httptest.NewServer(handler)
	defer caServer.Close()
	base = caServer.URL
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	c, err := Dial(ctx, s.Addr(), WithCredentials(creds), WithTLSConfig(trust), WithACMEClient(&acme.Client{DirectoryURL: base + "/directory", HTTPClient: caServer.Client()}))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = c.Close() })
	setup, stopSetup := context.WithCancel(ctx)
	clientCert, _ := applicationCertificate(t)
	clientPin := sha256.Sum256(clientCert.Certificate[0])
	auth := &ClientAuthConfig{ClientAuth: tls.RequireAnyClientCert, VerifyConnection: func(state tls.ConnectionState) error {
		if len(state.PeerCertificates) == 0 || sha256.Sum256(state.PeerCertificates[0].Raw) != clientPin {
			return errors.New("unauthorized client")
		}
		return nil
	}}
	l, err := c.ListenWithClientAuth(setup, "alice.example.com", auth)
	stopSetup() // Issuance must survive cancellation of the listener setup context.
	if err != nil {
		t.Fatal(err)
	}
	servePlainApplication(t, l)
	transport := &http.Transport{TLSClientConfig: &tls.Config{RootCAs: roots, Certificates: []tls.Certificate{clientCert}}, DisableKeepAlives: true, DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, "tcp", edge.Addr().String())
	}}
	defer transport.CloseIdleConnections()
	browser := &http.Client{Transport: transport, Timeout: 10 * time.Second}
	get := func() {
		resp, err := browser.Get("https://" + domain + "/")
		if err != nil {
			t.Fatal(err)
		}
		body, _ := io.ReadAll(resp.Body)
		_ = resp.Body.Close()
		if string(body) != "client-side TLS" {
			t.Fatalf("body %s", body)
		}
	}
	get()
	deniedTransport := transport.Clone()
	deniedTransport.TLSClientConfig.Certificates = nil
	defer deniedTransport.CloseIdleConnections()
	if resp, err := (&http.Client{Transport: deniedTransport, Timeout: 3 * time.Second}).Get("https://" + domain + "/"); err == nil {
		_ = resp.Body.Close()
		t.Fatal("ACME application accepted a missing client certificate")
	}
	if !validated.Load() || orders.Load() != 1 {
		t.Fatal("ACME challenge did not run")
	}
	if _, err := creds.storage.Get("acme/cert/" + domain); err != nil {
		t.Fatal("certificate not persisted")
	}
	if err := c.Close(); err != nil {
		t.Fatal(err)
	}
	reloaded, err := LoadCredentials(creds.storage)
	if err != nil {
		t.Fatal(err)
	}
	c2, err := Dial(ctx, s.Addr(), WithCredentials(reloaded), WithTLSConfig(trust), WithACMEClient(&acme.Client{DirectoryURL: base + "/directory", HTTPClient: caServer.Client()}))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := c2.Close(); err != nil {
			t.Error(err)
		}
	})
	setup2, stopSetup2 := context.WithCancel(ctx)
	l2, err := c2.ListenWithClientAuth(setup2, "alice.example.com", auth)
	stopSetup2() // Cached certificates must also survive setup cancellation.
	if err != nil {
		t.Fatal(err)
	}
	servePlainApplication(t, l2)
	get()
	if orders.Load() != 1 {
		t.Fatal("cached restart unexpectedly issued again")
	}
}

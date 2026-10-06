package tunnel

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"net"
	"sync"
	"time"

	"tunnel/internal/names"
	"tunnel/internal/transportpki"
	"tunnel/internal/wire"
)

type privateCertificate struct {
	Key   []byte
	Chain [][]byte
}
type privateManager struct {
	client *Client
	name   string
	mu     sync.Mutex
	cache  map[string]*tls.Certificate
}

// ListenPrivate terminates public TLS locally using certificates issued by the
// daemon's constrained CA. Browsers must separately trust that CA. Local keys
// never leave credential storage. Each authorized descendant is issued an exact
// name certificate on demand; renewal happens at subsequent handshakes with
// less than 24 hours remaining. No wildcard certificates or ACME are used.
func (c *Client) ListenPrivate(ctx context.Context, name string) (net.Listener, error) {
	name, err := canonicalName(name)
	if err != nil {
		return nil, err
	}
	if c.storage == nil {
		return nil, errors.New("private TLS requires durable credential storage")
	}
	if _, _, err := c.privateSession(name); err != nil {
		return nil, fmt.Errorf("validate private TLS listener state: %w", err)
	}
	manager := &privateManager{client: c, name: name, cache: map[string]*tls.Certificate{}}
	// Preflight exact root issuance before installing a listener. This surfaces
	// missing signing authority immediately rather than on a browser handshake.
	preflightCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	for _, algorithm := range []string{"ed25519", "p256"} {
		if _, err := manager.certificateAlgorithm(preflightCtx, name, algorithm); err != nil {
			return nil, fmt.Errorf("preflight private %s certificate issuance: %w", algorithm, err)
		}
	}
	config := &tls.Config{MinVersion: tls.VersionTLS12, NextProtos: []string{"h2", "http/1.1"}}
	config.GetCertificate = manager.getCertificate(ctx, name)
	return c.listen(ctx, name, "private", config)
}
func (c *Client) privateSession(name string) (*clientSession, *x509.Certificate, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.terminal != nil {
		return nil, nil, c.terminal
	}
	if c.status != "connected" && c.status != "draining" {
		return nil, nil, errors.New("private issuer is disconnected")
	}
	if !allowed(c.routes, name) {
		return nil, nil, errors.New("private certificate name not authorized")
	}
	s := c.session
	chain := s.conn.ConnectionState().TLS.PeerCertificates
	if len(chain) != 2 {
		return nil, nil, errors.New("private TLS requires a generated daemon CA")
	}
	ca := chain[1]
	if err := transportpki.ValidateCA(ca); err != nil {
		return nil, nil, fmt.Errorf("validate daemon private TLS CA: %w", err)
	}
	if !names.Covers(name, ca.PermittedDNSDomains[0]) {
		return nil, nil, errors.New("private TLS name outside daemon CA namespace")
	}
	return s, ca, nil
}
func validatePrivate(saved privateCertificate, name string, ca *x509.Certificate) (*tls.Certificate, error) {
	parsed, err := x509.ParsePKCS8PrivateKey(saved.Key)
	if err != nil {
		return nil, fmt.Errorf("parse private key: %w", err)
	}
	key, ok := parsed.(crypto.Signer)
	switch k := parsed.(type) {
	case ed25519.PrivateKey:
	case *ecdsa.PrivateKey:
		if k.Curve != elliptic.P256() {
			return nil, errors.New("private ECDSA key must use P-256")
		}
	default:
		return nil, errors.New("private key must be Ed25519 or ECDSA P-256")
	}
	if !ok {
		return nil, errors.New("private key is not a signer")
	}
	if len(saved.Chain) != 2 || !bytes.Equal(saved.Chain[1], ca.Raw) {
		return nil, errors.New("private certificate CA mismatch")
	}
	leaf, err := x509.ParseCertificate(saved.Chain[0])
	if err != nil {
		return nil, fmt.Errorf("parse private leaf certificate: %w", err)
	}
	pubDER, err := x509.MarshalPKIXPublicKey(leaf.PublicKey)
	if err != nil {
		return nil, fmt.Errorf("marshal private leaf public key: %w", err)
	}
	keyDER, err := x509.MarshalPKIXPublicKey(key.Public())
	if err != nil {
		return nil, fmt.Errorf("marshal private signer public key: %w", err)
	}
	if !bytes.Equal(pubDER, keyDER) {
		return nil, errors.New("private certificate key mismatch")
	}
	if leaf.IsCA || len(leaf.DNSNames) != 1 || leaf.DNSNames[0] != name || len(leaf.IPAddresses) != 0 || len(leaf.EmailAddresses) != 0 || len(leaf.URIs) != 0 || len(leaf.ExtKeyUsage) != 1 || leaf.ExtKeyUsage[0] != x509.ExtKeyUsageServerAuth {
		return nil, errors.New("unexpected private leaf attributes")
	}
	if err := leaf.CheckSignatureFrom(ca); err != nil {
		return nil, fmt.Errorf("verify private leaf signature: %w", err)
	}
	return &tls.Certificate{PrivateKey: key, Certificate: saved.Chain, Leaf: leaf}, nil
}
func (m *privateManager) getCertificate(ctx context.Context, name string) func(*tls.ClientHelloInfo) (*tls.Certificate, error) {
	return func(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
		host, err := canonicalName(hello.ServerName)
		if err != nil {
			return nil, fmt.Errorf("canonicalize private TLS server name: %w", err)
		}
		if !names.Covers(host, name) {
			return nil, errors.New("private TLS name outside listener subtree")
		}
		for _, algorithm := range []string{"ed25519", "p256"} {
			cert, err := m.certificateAlgorithm(ctx, host, algorithm)
			if err != nil {
				return nil, fmt.Errorf("load private %s certificate for %s: %w", algorithm, host, err)
			}
			if hello.SupportsCertificate(cert) == nil {
				return cert, nil
			}
		}
		return nil, errors.New("client supports neither Ed25519 nor ECDSA P-256 certificate")
	}
}
func (m *privateManager) certificate(ctx context.Context, name string) (*tls.Certificate, error) {
	return m.certificateAlgorithm(ctx, name, "ed25519")
}
func (m *privateManager) certificateAlgorithm(ctx context.Context, name, algorithm string) (*tls.Certificate, error) {
	storageKey := "private/cert/" + name
	if algorithm == "p256" {
		storageKey = "private/cert-p256/" + name
	} else if algorithm != "ed25519" {
		return nil, errors.New("invalid private certificate algorithm")
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	s, ca, err := m.client.privateSession(name)
	if err != nil {
		return nil, fmt.Errorf("refresh private session for %s: %w", name, err)
	}
	cert := m.cache[storageKey]
	if cert == nil {
		if len(m.cache) >= 512 {
			return nil, errors.New("private listener certificate cache limit reached")
		}
		data, err := m.client.storage.Get(storageKey)
		if err == nil {
			var saved privateCertificate
			if err = json.Unmarshal(data, &saved); err != nil {
				return nil, fmt.Errorf("decode cached private certificate %q: %w", storageKey, err)
			}
			cert, err = validatePrivate(saved, name, ca)
			if err != nil {
				return nil, fmt.Errorf("validate cached private certificate %q: %w", storageKey, err)
			}
		} else if !errors.Is(err, fs.ErrNotExist) {
			return nil, fmt.Errorf("load cached private certificate %q: %w", storageKey, err)
		}
	}
	if cert != nil {
		_, isEd := cert.PrivateKey.(ed25519.PrivateKey)
		if isEd != (algorithm == "ed25519") {
			return nil, errors.New("cached private certificate algorithm mismatch")
		}
		if !bytes.Equal(cert.Certificate[1], ca.Raw) {
			return nil, errors.New("private certificate CA changed")
		}
		if time.Now().Before(cert.Leaf.NotAfter.Add(-24*time.Hour)) && !time.Now().Before(cert.Leaf.NotBefore) {
			roots := x509.NewCertPool()
			roots.AddCert(ca)
			if _, err := cert.Leaf.Verify(x509.VerifyOptions{DNSName: name, Roots: roots}); err != nil {
				return nil, fmt.Errorf("verify cached private certificate for %s: %w", name, err)
			}
			m.cache[storageKey] = cert
			return cert, nil
		}
	}
	var key crypto.Signer
	if algorithm == "ed25519" {
		_, key, err = ed25519.GenerateKey(rand.Reader)
	} else {
		key, err = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	}
	if err != nil {
		return nil, fmt.Errorf("generate private %s key for %s: %w", algorithm, name, err)
	}
	csr, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{DNSNames: []string{name}}, key)
	if err != nil {
		return nil, fmt.Errorf("create private CSR for %s: %w", name, err)
	}
	deadline, stop := context.WithTimeout(ctx, 10*time.Second)
	defer stop()
	data, err := m.client.rpcSession(deadline, s, &wire.IssueCertificate{Envelope: wire.Envelope{Type: "IssueCertificate"}, Name: name, CSR: base64.StdEncoding.EncodeToString(csr)})
	if err != nil {
		return nil, err
	}
	var result wire.CertificateResult
	if err = wire.DecodeFrame(data, &result, "type", "id", "name", "code", "error", "chain"); err != nil {
		return nil, fmt.Errorf("decode private certificate response: %w", err)
	}
	if result.Name != name {
		return nil, errors.New("private issuance name mismatch")
	}
	if result.Code != "ok" {
		return nil, fmt.Errorf("private issuance %s: %s", result.Code, result.Error)
	}
	encoded, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return nil, fmt.Errorf("marshal private key for %s: %w", name, err)
	}
	saved := privateCertificate{Key: encoded}
	for _, item := range result.Chain {
		der, err := base64.StdEncoding.Strict().DecodeString(item)
		if err != nil {
			return nil, fmt.Errorf("decode issued private certificate chain for %s: %w", name, err)
		}
		saved.Chain = append(saved.Chain, der)
	}
	cert, err = validatePrivate(saved, name, ca)
	if err != nil {
		return nil, fmt.Errorf("validate issued private certificate for %s: %w", name, err)
	}
	roots := x509.NewCertPool()
	roots.AddCert(ca)
	if _, err = cert.Leaf.Verify(x509.VerifyOptions{DNSName: name, Roots: roots}); err != nil {
		return nil, fmt.Errorf("verify issued private certificate for %s: %w", name, err)
	}
	if cert.Leaf.NotAfter.After(time.Now().Add(7*24*time.Hour+time.Minute)) || !cert.Leaf.NotAfter.After(time.Now().Add(24*time.Hour)) {
		return nil, errors.New("unexpected private certificate lifetime")
	}
	// Recheck authorization/session after the RPC before publishing or caching.
	current, currentCA, err := m.client.privateSession(name)
	if err != nil {
		return nil, fmt.Errorf("revalidate private session for %s: %w", name, err)
	}
	if current != s || !bytes.Equal(currentCA.Raw, ca.Raw) {
		return nil, errors.New("private issuance session changed")
	}
	payload, err := json.Marshal(saved)
	if err != nil {
		return nil, fmt.Errorf("marshal private certificate for %s: %w", name, err)
	}
	if err = m.client.storage.Put(storageKey, payload); err != nil {
		return nil, fmt.Errorf("persist private certificate: %w", err)
	}
	check, err := m.client.storage.Get(storageKey)
	if err != nil {
		return nil, fmt.Errorf("reload private certificate %q: %w", storageKey, err)
	}
	if !bytes.Equal(check, payload) {
		return nil, errors.New("private certificate changed during persistence")
	}
	m.cache[storageKey] = cert
	return cert, nil
}

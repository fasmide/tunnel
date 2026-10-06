// Package transportpki manages the daemon's private transport PKI, not public TLS.
package transportpki

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io/fs"
	"math/big"
	"net"
	"strings"
	"sync"
	"time"

	"tunnel/internal/names"
)

type Storage interface {
	Get(string) ([]byte, error)
	Put(string, []byte) error
}

const StateKey = "server/transport-ca"

type state struct {
	Domain           string
	Certificate, Key []byte
}

// Fingerprint is SHA-256 over the CA certificate DER, not its PEM encoding.
func Fingerprint(c *x509.Certificate) string {
	sum := sha256.Sum256(c.Raw)
	return hex.EncodeToString(sum[:])
}
func serial() (*big.Int, error) {
	n, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return nil, fmt.Errorf("generate certificate serial: %w", err)
	}
	return n.Add(n, big.NewInt(1)), nil
}

// ValidateCA restricts generated/bootstrap trust to DNS server certificates in
// exactly one namespace. IP names and subordinate CAs are not supported.
func ValidateCA(c *x509.Certificate) error {
	if !c.IsCA || !c.BasicConstraintsValid || !c.MaxPathLenZero || c.MaxPathLen != 0 || c.KeyUsage&x509.KeyUsageCertSign == 0 || !c.PermittedDNSDomainsCritical || len(c.PermittedDNSDomains) != 1 || !names.Valid(c.PermittedDNSDomains[0]) || len(c.ExcludedDNSDomains) != 0 {
		return errors.New("expected a constrained transport CA")
	}
	if len(c.PermittedIPRanges) != 0 || len(c.ExcludedIPRanges) != 2 || len(c.PermittedEmailAddresses) != 0 || len(c.ExcludedEmailAddresses) != 0 || len(c.PermittedURIDomains) != 0 || len(c.ExcludedURIDomains) != 0 {
		return errors.New("unexpected CA name constraints")
	}
	for i, s := range []string{"0.0.0.0/0", "::/0"} {
		_, want, _ := net.ParseCIDR(s)
		got := c.ExcludedIPRanges[i]
		if got == nil || !got.IP.Equal(want.IP) || !bytes.Equal(got.Mask, want.Mask) {
			return errors.New("CA must exclude all IP names")
		}
	}
	if len(c.ExtKeyUsage) != 1 || c.ExtKeyUsage[0] != x509.ExtKeyUsageServerAuth || len(c.UnhandledCriticalExtensions) != 0 {
		return errors.New("CA must be restricted to server authentication")
	}
	if !bytes.Equal(c.RawIssuer, c.RawSubject) {
		return errors.New("transport CA must be self-signed")
	}
	if err := c.CheckSignature(c.SignatureAlgorithm, c.RawTBSCertificate, c.Signature); err != nil {
		return fmt.Errorf("verify transport CA self-signature: %w", err)
	}
	return nil
}

// Issue signs an exact DNS server leaf. CSR extensions are never copied.
// Caller must hold authorization stable until issuance completes.
func (a *Authority) Issue(name string, der []byte, now time.Time) ([][]byte, error) {
	if !names.Valid(name) || !names.Covers(name, a.domain) {
		return nil, errors.New("name outside transport CA namespace")
	}
	if len(der) > 4096 {
		return nil, errors.New("CSR too large")
	}
	csr, err := x509.ParseCertificateRequest(der)
	if err != nil {
		return nil, fmt.Errorf("parse transport CSR: %w", err)
	}
	if err = csr.CheckSignature(); err != nil {
		return nil, fmt.Errorf("verify transport CSR signature: %w", err)
	}
	pub := csr.PublicKey
	switch key := pub.(type) {
	case ed25519.PublicKey:
	case *ecdsa.PublicKey:
		if key.Curve != elliptic.P256() {
			return nil, errors.New("ECDSA CSR must use P-256")
		}
	default:
		return nil, errors.New("Ed25519 or ECDSA P-256 CSR required")
	}
	if len(csr.DNSNames) != 1 || csr.DNSNames[0] != name || len(csr.IPAddresses) != 0 || len(csr.EmailAddresses) != 0 || len(csr.URIs) != 0 || len(csr.Extensions) != 1 || !csr.Extensions[0].Id.Equal([]int{2, 5, 29, 17}) {
		return nil, errors.New("CSR must request exactly one DNS SAN and no other extensions")
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	if now.Before(a.ca.NotBefore) || !now.Before(a.ca.NotAfter.Add(-24*time.Hour)) {
		return nil, errors.New("CA expired or nearing expiry")
	}
	n, err := serial()
	if err != nil {
		return nil, fmt.Errorf("allocate transport leaf serial for %s: %w", name, err)
	}
	end := now.Add(7 * 24 * time.Hour)
	if end.After(a.ca.NotAfter) {
		end = a.ca.NotAfter
	}
	leaf := &x509.Certificate{SerialNumber: n, DNSNames: []string{name}, NotBefore: now.Add(-5 * time.Minute), NotAfter: end, KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}, BasicConstraintsValid: true}
	signed, err := x509.CreateCertificate(rand.Reader, leaf, a.ca, pub, a.key)
	if err != nil {
		return nil, fmt.Errorf("sign transport certificate for %s: %w", name, err)
	}
	return [][]byte{signed, append([]byte(nil), a.ca.Raw...)}, nil
}

// Open loads or atomically creates a CA under the daemon's exclusive state lock.
// The CA is never silently replaced. Leaves are short-lived and renewed locally
// during TLS handshakes; the CA itself requires explicit operator rotation.
func Open(storage Storage, domain string, now time.Time) (*Authority, error) {
	domain = strings.ToLower(strings.TrimSuffix(domain, "."))
	if storage == nil || !names.Valid(domain) || !strings.Contains(domain, ".") {
		return nil, errors.New("-domain must be a DNS base name (not a wildcard or IP)")
	}
	data, err := storage.Get(StateKey)
	if errors.Is(err, fs.ErrNotExist) {
		key, e := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if e != nil {
			return nil, fmt.Errorf("generate transport CA key: %w", e)
		}
		n, e := serial()
		if e != nil {
			return nil, fmt.Errorf("allocate transport CA serial: %w", e)
		}
		_, v4, _ := net.ParseCIDR("0.0.0.0/0")
		_, v6, _ := net.ParseCIDR("::/0")
		template := &x509.Certificate{SerialNumber: n, Subject: pkix.Name{CommonName: "tunneld transport CA for " + domain}, NotBefore: now.Add(-5 * time.Minute), NotAfter: now.AddDate(25, 0, 0), IsCA: true, BasicConstraintsValid: true, MaxPathLen: 0, MaxPathLenZero: true, KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageCRLSign, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}, PermittedDNSDomainsCritical: true, PermittedDNSDomains: []string{domain}, ExcludedIPRanges: []*net.IPNet{v4, v6}}
		der, e := x509.CreateCertificate(rand.Reader, template, template, key.Public(), key)
		if e != nil {
			return nil, fmt.Errorf("create transport CA certificate: %w", e)
		}
		encoded, e := x509.MarshalPKCS8PrivateKey(key)
		if e != nil {
			return nil, fmt.Errorf("marshal transport CA key: %w", e)
		}
		data, e = json.Marshal(state{domain, der, encoded})
		if e != nil {
			return nil, fmt.Errorf("marshal transport CA state: %w", e)
		}
		if e = storage.Put(StateKey, data); e != nil {
			return nil, fmt.Errorf("persist transport CA: %w", e)
		}
		saved, e := storage.Get(StateKey)
		if e != nil {
			return nil, fmt.Errorf("reload persisted transport CA: %w", e)
		}
		if !bytes.Equal(saved, data) {
			return nil, errors.New("transport CA changed during initialization")
		}
		data = saved
	} else if err != nil {
		return nil, fmt.Errorf("load persisted transport CA: %w", err)
	}
	var s state
	if err = json.Unmarshal(data, &s); err != nil {
		return nil, fmt.Errorf("decode transport CA state: %w", err)
	}
	if s.Domain != domain {
		return nil, errors.New("transport domain differs from saved CA; explicit migration required")
	}
	ca, err := x509.ParseCertificate(s.Certificate)
	if err != nil {
		return nil, fmt.Errorf("parse persisted transport CA certificate: %w", err)
	}
	if err = ValidateCA(ca); err != nil {
		return nil, fmt.Errorf("validate persisted transport CA: %w", err)
	}
	if ca.PermittedDNSDomains[0] != domain {
		return nil, errors.New("saved CA domain mismatch")
	}
	parsed, err := x509.ParsePKCS8PrivateKey(s.Key)
	if err != nil {
		return nil, fmt.Errorf("parse persisted transport CA key: %w", err)
	}
	key, ok := parsed.(crypto.Signer)
	// Existing Ed25519 CA state remains loadable, never silently rotated. Newly
	// generated CAs use P-256 for broad browser interoperability.
	switch k := parsed.(type) {
	case ed25519.PrivateKey:
	case *ecdsa.PrivateKey:
		if k.Curve != elliptic.P256() {
			return nil, errors.New("CA must use P-256")
		}
	default:
		return nil, errors.New("unsupported CA key")
	}
	pubDER, err := x509.MarshalPKIXPublicKey(ca.PublicKey)
	if err != nil {
		return nil, fmt.Errorf("marshal persisted transport CA public key: %w", err)
	}
	keyDER, err := x509.MarshalPKIXPublicKey(key.Public())
	if err != nil {
		return nil, fmt.Errorf("marshal persisted transport signer public key: %w", err)
	}
	if !ok || !bytes.Equal(pubDER, keyDER) {
		return nil, errors.New("transport CA key mismatch")
	}
	a := &Authority{ca: ca, key: key, domain: domain}
	if _, err = a.certificate(now); err != nil {
		return nil, fmt.Errorf("initialize active transport certificate: %w", err)
	}
	return a, nil
}

type Authority struct {
	mu     sync.Mutex
	ca     *x509.Certificate
	key    crypto.Signer
	domain string
	leaf   *tls.Certificate
	edLeaf *tls.Certificate
}

func (a *Authority) PEM() []byte {
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: a.ca.Raw})
}
func (a *Authority) Fingerprint() string { return Fingerprint(a.ca) }
func (a *Authority) Config() *tls.Config {
	a.mu.Lock()
	initial := *a.leaf
	a.mu.Unlock()
	return &tls.Config{Certificates: []tls.Certificate{initial}, GetCertificate: func(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
		if hello.ServerName == "" {
			return nil, errors.New("generated transport TLS requires DNS SNI")
		}
		if err := initial.Leaf.VerifyHostname(hello.ServerName); err != nil {
			return nil, fmt.Errorf("verify transport SNI %q against cached certificate: %w", hello.ServerName, err)
		}
		for _, algorithm := range []string{"ed25519", "p256"} {
			cert, err := a.certificateAlgorithm(time.Now(), algorithm)
			if err != nil {
				return nil, fmt.Errorf("load transport %s certificate: %w", algorithm, err)
			}
			if hello.SupportsCertificate(cert) == nil {
				return cert, nil
			}
		}
		return nil, errors.New("no compatible transport certificate")
	}}
}
func (a *Authority) certificate(now time.Time) (*tls.Certificate, error) {
	return a.certificateAlgorithm(now, "p256")
}
func (a *Authority) certificateAlgorithm(now time.Time, algorithm string) (*tls.Certificate, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if now.Before(a.ca.NotBefore) || !now.Before(a.ca.NotAfter.Add(-time.Hour)) {
		return nil, errors.New("transport CA expired/not yet valid or near expiry; operator rotation required")
	}
	cached := a.leaf
	if algorithm == "ed25519" {
		cached = a.edLeaf
	}
	if cached != nil && now.Before(cached.Leaf.NotAfter.Add(-24*time.Hour)) {
		return cached, nil
	}
	var key crypto.Signer
	var err error
	if algorithm == "ed25519" {
		_, key, err = ed25519.GenerateKey(rand.Reader)
	} else {
		key, err = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	}
	if err != nil {
		return nil, fmt.Errorf("generate transport %s key: %w", algorithm, err)
	}
	n, err := serial()
	if err != nil {
		return nil, fmt.Errorf("allocate transport %s certificate serial: %w", algorithm, err)
	}
	end := now.Add(7 * 24 * time.Hour)
	if end.After(a.ca.NotAfter) {
		end = a.ca.NotAfter
	}
	template := &x509.Certificate{SerialNumber: n, DNSNames: []string{a.domain, "*." + a.domain}, NotBefore: now.Add(-5 * time.Minute), NotAfter: end, KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}, BasicConstraintsValid: true}
	der, err := x509.CreateCertificate(rand.Reader, template, a.ca, key.Public(), a.key)
	if err != nil {
		return nil, fmt.Errorf("create transport %s certificate: %w", algorithm, err)
	}
	leaf, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, fmt.Errorf("parse transport %s certificate: %w", algorithm, err)
	}
	cert := &tls.Certificate{Certificate: [][]byte{der, a.ca.Raw}, PrivateKey: key, Leaf: leaf}
	if algorithm == "ed25519" {
		a.edLeaf = cert
	} else {
		a.leaf = cert
	}
	return cert, nil
}

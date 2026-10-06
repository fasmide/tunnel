package tunnel

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"io/fs"
	"net"
	"strings"
	"sync"
	"time"

	quic "github.com/quic-go/quic-go"
	"tunnel/internal/transportpki"
	"tunnel/internal/wire"
)

// TrustRequest explicitly selects fingerprint verification or first-use trust.
// ServerName is required when addr is an IP but the certificate is DNS-only.
// Storage must be durable in real deployments. Do not bootstrap a shared store
// concurrently across processes: Storage does not support compare-and-swap.
type TrustRequest struct {
	Storage     Storage
	ServerName  string
	Fingerprint string // lowercase SHA-256 hex of CA DER, printed by tunneld
	TOFU        bool   // explicit acceptance of interception risk on first contact
}

// TransportTrust describes the saved CA without exposing any private material.
type TransportTrust struct {
	CA                  []byte
	Fingerprint, Domain string
	FirstUse            bool
}

var trustMu sync.Mutex

func trustKey(addr string) string {
	sum := sha256.Sum256([]byte(addr))
	return "creds/trust/" + hex.EncodeToString(sum[:])
}
func parseTransportCA(data []byte) (*x509.Certificate, error) {
	block, rest := pem.Decode(data)
	if block == nil || block.Type != "CERTIFICATE" || len(bytes.TrimSpace(rest)) != 0 {
		return nil, errors.New("invalid saved transport CA PEM")
	}
	ca, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parse saved transport CA: %w", err)
	}
	if err := transportpki.ValidateCA(ca); err != nil {
		return nil, fmt.Errorf("validate saved transport CA: %w", err)
	}
	return ca, nil
}
func nameFor(addr, name string) (string, error) {
	if name != "" {
		return canonicalName(name)
	}
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		return "", fmt.Errorf("split transport address: %w", err)
	}
	if net.ParseIP(host) != nil {
		return host, nil
	}
	return canonicalName(host)
}
func verifyTransport(cs tls.ConnectionState, ca *x509.Certificate, name string) error {
	if len(cs.PeerCertificates) == 0 {
		return errors.New("missing server certificate")
	}
	roots := x509.NewCertPool()
	roots.AddCert(ca)
	intermediates := x509.NewCertPool()
	for _, cert := range cs.PeerCertificates[1:] {
		if !bytes.Equal(cert.Raw, ca.Raw) {
			intermediates.AddCert(cert)
		}
	}
	_, err := cs.PeerCertificates[0].Verify(x509.VerifyOptions{DNSName: name, Roots: roots, Intermediates: intermediates, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}})
	if err != nil {
		return fmt.Errorf("verify transport certificate for %q: %w", name, err)
	}
	return nil
}

func validateFingerprint(fingerprint string) error {
	raw, err := hex.DecodeString(fingerprint)
	if err != nil || len(raw) != 32 || hex.EncodeToString(raw) != fingerprint {
		return errors.New("fingerprint must be lowercase SHA-256 hex")
	}
	return nil
}

func transportCAConfig(name string) (*tls.Config, error) {
	// An ephemeral identity is required by the existing authenticated QUIC
	// endpoint, but no persistent identity or signed application data is sent.
	creds, err := loadOrCreateCredentials(MemoryStorage())
	if err != nil {
		return nil, fmt.Errorf("load ephemeral transport credentials: %w", err)
	}
	cert, err := creds.identityCertificate(time.Now())
	if err != nil {
		return nil, fmt.Errorf("create ephemeral transport certificate: %w", err)
	}
	config := &tls.Config{ServerName: name, MinVersion: tls.VersionTLS13, MaxVersion: tls.VersionTLS13, NextProtos: []string{wire.ALPN}, Certificates: []tls.Certificate{cert}, InsecureSkipVerify: true}
	return config, nil
}

// FetchTransportTrust downloads the constrained transport CA from the QUIC TLS
// chain and returns its public metadata without persisting it.
func FetchTransportTrust(ctx context.Context, addr, serverName string) (TransportTrust, error) {
	var result TransportTrust
	name, err := nameFor(addr, serverName)
	if err != nil {
		return result, fmt.Errorf("resolve transport server name: %w", err)
	}
	config, err := transportCAConfig(name)
	if err != nil {
		return result, fmt.Errorf("build transport bootstrap config: %w", err)
	}
	var ca *x509.Certificate
	config.VerifyConnection = func(cs tls.ConnectionState) error {
		if ca == nil {
			if len(cs.PeerCertificates) != 2 {
				return errors.New("bootstrap requires leaf plus constrained self-signed CA")
			}
			candidate := cs.PeerCertificates[1]
			if err := transportpki.ValidateCA(candidate); err != nil {
				return fmt.Errorf("validate transport CA candidate: %w", err)
			}
			if err := verifyTransport(cs, candidate, name); err != nil {
				return err
			}
			ca = candidate
		}
		return verifyTransport(cs, ca, name)
	}
	attempt, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	conn, err := quic.DialAddr(attempt, addr, config, &quic.Config{Versions: []quic.Version{quic.Version1}, MaxIncomingStreams: -1, MaxIncomingUniStreams: -1})
	if err != nil {
		return result, fmt.Errorf("dial transport trust endpoint %s: %w", addr, err)
	}
	_ = conn.CloseWithError(0, "transport trust fetch complete")
	if ca == nil {
		return result, errors.New("no transport CA received")
	}
	data := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: ca.Raw})
	return TransportTrust{CA: append([]byte(nil), data...), Fingerprint: transportpki.Fingerprint(ca), Domain: ca.PermittedDNSDomains[0]}, nil
}

// BootstrapTrust downloads the constrained CA from the QUIC TLS certificate
// chain, verifies a supplied fingerprint or explicitly accepts TOFU, verifies
// hostname/chain, then persists the CA. It sends no Join or forwarding request.
// Existing trust is never overwritten, including when TOFU is selected again.
func BootstrapTrust(ctx context.Context, addr string, request TrustRequest) (TransportTrust, error) {
	trustMu.Lock()
	defer trustMu.Unlock()
	var result TransportTrust
	if request.Storage == nil {
		return result, errors.New("trust storage required")
	}
	if request.TOFU == (request.Fingerprint != "") {
		return result, errors.New("select exactly one of Fingerprint or TOFU")
	}
	if request.Fingerprint != "" {
		if err := validateFingerprint(request.Fingerprint); err != nil {
			return result, fmt.Errorf("validate transport fingerprint: %w", err)
		}
	}
	name, err := nameFor(addr, request.ServerName)
	if err != nil {
		return result, fmt.Errorf("resolve bootstrap server name: %w", err)
	}
	saved, err := request.Storage.Get(trustKey(addr))
	var ca *x509.Certificate
	first := errors.Is(err, fs.ErrNotExist)
	if err != nil && !first {
		return result, fmt.Errorf("load saved transport trust: %w", err)
	}
	if !first {
		ca, err = parseTransportCA(saved)
		if err != nil {
			return result, fmt.Errorf("parse saved transport trust: %w", err)
		}
		if request.Fingerprint != "" && request.Fingerprint != transportpki.Fingerprint(ca) {
			return result, errors.New("fingerprint conflicts with saved trust")
		}
	}
	config, err := transportCAConfig(name)
	if err != nil {
		return result, fmt.Errorf("build bootstrap transport config: %w", err)
	}
	config.VerifyConnection = func(cs tls.ConnectionState) error {
		if ca == nil {
			if len(cs.PeerCertificates) != 2 {
				return errors.New("bootstrap requires leaf plus constrained self-signed CA")
			}
			candidate := cs.PeerCertificates[1]
			if err := transportpki.ValidateCA(candidate); err != nil {
				return fmt.Errorf("validate bootstrap transport CA: %w", err)
			}
			if !request.TOFU && transportpki.Fingerprint(candidate) != request.Fingerprint {
				return errors.New("transport CA fingerprint mismatch")
			}
			if err := verifyTransport(cs, candidate, name); err != nil {
				return err
			}
			ca = candidate
		}
		return verifyTransport(cs, ca, name)
	}
	attempt, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	conn, err := quic.DialAddr(attempt, addr, config, &quic.Config{Versions: []quic.Version{quic.Version1}, MaxIncomingStreams: -1, MaxIncomingUniStreams: -1})
	if err != nil {
		return result, fmt.Errorf("dial bootstrap endpoint %s: %w", addr, err)
	}
	_ = conn.CloseWithError(0, "trust bootstrap complete")
	if ca == nil {
		return result, errors.New("no transport CA received")
	}
	data := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: ca.Raw})
	if first {
		if err := request.Storage.Put(trustKey(addr), data); err != nil {
			return result, fmt.Errorf("persist transport trust: %w", err)
		}
		check, err := request.Storage.Get(trustKey(addr))
		if err != nil {
			return result, fmt.Errorf("reload persisted transport trust: %w", err)
		}
		if !bytes.Equal(check, data) {
			return result, errors.New("transport trust changed during initialization")
		}
	}
	return TransportTrust{CA: append([]byte(nil), data...), Fingerprint: transportpki.Fingerprint(ca), Domain: ca.PermittedDNSDomains[0], FirstUse: first}, nil
}

// LoadTransportTLS loads saved endpoint-local trust for JoinRequest.TLSConfig or
// WithTLSConfig. It does not fall back to system roots when a saved CA is used.
// For IP endpoints pass the certified DNS name as serverName.
func LoadTransportTLS(storage Storage, addr, serverName string) (*tls.Config, error) {
	if storage == nil {
		return nil, errors.New("trust storage required")
	}
	data, err := storage.Get(trustKey(addr))
	if err != nil {
		return nil, fmt.Errorf("load transport trust: %w", err)
	}
	ca, err := parseTransportCA(data)
	if err != nil {
		return nil, fmt.Errorf("parse transport trust: %w", err)
	}
	name, err := nameFor(addr, serverName)
	if err != nil {
		return nil, fmt.Errorf("resolve transport TLS server name: %w", err)
	}
	if !strings.HasSuffix(name, "."+ca.PermittedDNSDomains[0]) && name != ca.PermittedDNSDomains[0] {
		return nil, errors.New("server name outside saved CA namespace")
	}
	roots := x509.NewCertPool()
	roots.AddCert(ca)
	return &tls.Config{RootCAs: roots, ServerName: name, MinVersion: tls.VersionTLS13}, nil
}

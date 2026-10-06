package server

import (
	"bytes"
	"crypto/ed25519"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"time"

	"github.com/fasmide/tunnel/internal/wire"
)

// verifyIdentity validates the leaf independently of route approval. TLS itself
// verifies CertificateVerify, proving possession of the presented private key.
func verifyIdentity(rawCerts [][]byte, now time.Time) (ed25519.PublicKey, error) {
	if len(rawCerts) != 1 {
		return nil, errors.New("exactly one identity certificate required")
	}
	cert, err := x509.ParseCertificate(rawCerts[0])
	if err != nil {
		return nil, fmt.Errorf("parse identity certificate: %w", err)
	}
	pub, ok := cert.PublicKey.(ed25519.PublicKey)
	if !ok || len(pub) != ed25519.PublicKeySize || cert.SignatureAlgorithm != x509.PureEd25519 {
		return nil, errors.New("Ed25519 identity certificate required")
	}
	if cert.IsCA || !bytes.Equal(cert.RawIssuer, cert.RawSubject) {
		return nil, errors.New("self-signed leaf required")
	}
	if now.Before(cert.NotBefore) || now.After(cert.NotAfter) {
		return nil, errors.New("identity certificate is not currently valid")
	}
	if cert.KeyUsage&x509.KeyUsageDigitalSignature == 0 {
		return nil, errors.New("digital signature key usage required")
	}
	clientAuth := false
	for _, usage := range cert.ExtKeyUsage {
		if usage == x509.ExtKeyUsageClientAuth {
			clientAuth = true
		}
	}
	if !clientAuth || len(cert.UnhandledCriticalExtensions) > 0 {
		return nil, errors.New("invalid identity certificate usages or extensions")
	}
	if err := cert.CheckSignature(cert.SignatureAlgorithm, cert.RawTBSCertificate, cert.Signature); err != nil {
		return nil, fmt.Errorf("verify identity self-signature: %w", err)
	}
	return append(ed25519.PublicKey(nil), pub...), nil
}

func serverTLS(config *tls.Config) (*tls.Config, error) {
	if config == nil || len(config.Certificates) == 0 {
		return nil, errors.New("server transport certificate is required")
	}
	result := config.Clone()
	// Caller-provided dynamic configs/verifiers cannot bypass identity validation.
	result.GetConfigForClient = nil
	result.VerifyConnection = nil
	result.ClientCAs = nil
	result.ClientAuth = tls.RequireAnyClientCert
	result.MinVersion = tls.VersionTLS13
	result.MaxVersion = tls.VersionTLS13
	result.NextProtos = []string{wire.ALPN}
	result.SessionTicketsDisabled = true
	result.VerifyPeerCertificate = func(raw [][]byte, _ [][]*x509.Certificate) error {
		_, err := verifyIdentity(raw, time.Now())
		if err != nil {
			return fmt.Errorf("verify peer identity: %w", err)
		}
		return nil
	}
	return result, nil
}

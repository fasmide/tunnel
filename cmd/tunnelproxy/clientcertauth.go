package main

import (
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/fasmide/tunnel"
)

// Pins cover the entire leaf certificate DER, not just its public key.
func parseClientCertFingerprint(value string) ([sha256.Size]byte, error) {
	var pin [sha256.Size]byte
	decoded, err := hex.DecodeString(strings.ReplaceAll(strings.TrimSpace(value), ":", ""))
	if err != nil || len(decoded) != len(pin) {
		return pin, errors.New("--clientcertauth requires a SHA-256 certificate fingerprint: 64 hexadecimal digits, optionally colon-separated (openssl x509 -in client.crt -noout -fingerprint -sha256)")
	}
	copy(pin[:], decoded)
	return pin, nil
}

func prepareClientCertAuth(c config) (*tunnel.ClientAuthConfig, error) {
	if len(c.clientCertAuth) == 0 && c.clientCertAuthCA == "" {
		return nil, nil
	}
	if c.mode == "raw" || c.mode == "http" {
		return nil, errors.New("client certificate authentication requires a TLS-terminating mode")
	}
	if c.clientCertAuthCA != "" {
		if len(c.clientCertAuth) > 0 {
			return nil, errors.New("client certificate pins and CA trust are mutually exclusive")
		}
		data, err := os.ReadFile(c.clientCertAuthCA)
		if err != nil {
			return nil, fmt.Errorf("read client CA bundle: %w", err)
		}
		roots := x509.NewCertPool()
		count := 0
		for len(strings.TrimSpace(string(data))) > 0 {
			// Reject stray text rather than silently skipping malformed PEM entries.
			data = []byte(strings.TrimSpace(string(data)))
			if !strings.HasPrefix(string(data), "-----BEGIN CERTIFICATE-----") {
				return nil, errors.New("client CA bundle must contain only PEM certificates")
			}
			block, rest := pem.Decode(data)
			if block == nil || block.Type != "CERTIFICATE" {
				return nil, errors.New("invalid client CA PEM certificate")
			}
			cert, err := x509.ParseCertificate(block.Bytes)
			if err != nil {
				return nil, fmt.Errorf("parse client CA: %w", err)
			}
			if !cert.IsCA || !cert.BasicConstraintsValid || cert.KeyUsage&x509.KeyUsageCertSign == 0 {
				return nil, errors.New("client CA bundle contains a certificate without CA signing constraints")
			}
			roots.AddCert(cert)
			count++
			data = rest
		}
		if count == 0 {
			return nil, errors.New("client CA bundle contains no certificates")
		}
		return &tunnel.ClientAuthConfig{ClientAuth: tls.RequireAndVerifyClientCert, ClientCAs: roots}, nil
	}
	pins := make(map[[sha256.Size]byte]bool, len(c.clientCertAuth))
	for _, value := range c.clientCertAuth {
		pin, err := parseClientCertFingerprint(value)
		if err != nil {
			return nil, err
		}
		pins[pin] = true
	}
	return &tunnel.ClientAuthConfig{
		ClientAuth: tls.RequireAnyClientCert,
		VerifyConnection: func(state tls.ConnectionState) error {
			if len(state.PeerCertificates) == 0 {
				return errors.New("client certificate required")
			}
			leaf := state.PeerCertificates[0]
			if !pins[sha256.Sum256(leaf.Raw)] {
				return errors.New("client certificate fingerprint not allowed")
			}
			// An enrolled leaf is its own explicit trust anchor, including when
			// self-signed. Verify enforces dates, critical extensions and client EKU.
			roots := x509.NewCertPool()
			roots.AddCert(leaf)
			_, err := leaf.Verify(x509.VerifyOptions{Roots: roots, CurrentTime: time.Now(), KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}})
			return err
		},
	}, nil
}

package main

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/fasmide/tunnel"
	"github.com/fasmide/tunnel/internal/server"
	"github.com/fasmide/tunnel/internal/transportpki"
)

func TestExtractPublicCAParse(t *testing.T) {
	cfg, err := parse([]string{"--socket", "/custom/admin.sock", "extract-public-ca"})
	if err != nil || cfg.request.Command != "extract-public-ca" || cfg.socket != "/custom/admin.sock" {
		t.Fatalf("config: %+v %v", cfg, err)
	}
	for _, args := range [][]string{
		{"extract-public-ca", "extra"},
		{"extract-public-ca", "--json"},
		{"extract-public-ca", "--server", "example.com"},
		{"extract-public-ca", "--server-name", "example.com"},
		{"extract-public-ca", "--replace"},
		{"extract-public-ca", "--all"},
	} {
		if _, err := parse(args); err == nil {
			t.Fatalf("accepted %v", args)
		}
	}
}

func TestExtractPublicCAFromRunningDaemon(t *testing.T) {
	store := tunnel.MemoryStorage()
	authority, err := transportpki.Open(store, "tunnel.example.com", time.Now())
	if err != nil {
		t.Fatal(err)
	}
	manager, err := server.OpenManager(store)
	if err != nil {
		t.Fatal(err)
	}
	socket := filepath.Join(t.TempDir(), "admin.sock")
	admin, err := server.ListenAdmin(socket, manager, authority.Fingerprint(), "tunnel.example.com", string(authority.PEM()))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = admin.Close() }()
	out, err := os.CreateTemp(t.TempDir(), "ca-*.crt")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = out.Close() }()
	if err := run([]string{"--socket", socket, "extract-public-ca"}, out, os.Stderr, strings.NewReader("")); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(out.Name())
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(data, authority.PEM()) || bytes.Contains(data, []byte("PRIVATE KEY")) {
		t.Fatalf("export is not exactly the original public CA: %s", data)
	}
	block, rest := pem.Decode(data)
	if block == nil || len(rest) != 0 {
		t.Fatal("expected one PEM certificate")
	}
	ca, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	if err := transportpki.ValidateCA(ca); err != nil {
		t.Fatal(err)
	}
	// Verify the exported root still enforces its DNS namespace, excludes all
	// IP addresses, and cannot issue subordinate CAs.
	if !ca.PermittedDNSDomainsCritical || !ca.MaxPathLenZero || len(ca.ExcludedIPRanges) != 2 {
		t.Fatal("lost critical constraints")
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	roots := x509.NewCertPool()
	roots.AddCert(ca)
	// Sign matching SANs with the real key to exercise root constraints, not
	// just hostname mismatch checking. Private state is used only in this test.
	raw, err := store.Get(transportpki.StateKey)
	if err != nil {
		t.Fatal(err)
	}
	var saved struct{ Key []byte }
	if err := json.Unmarshal(raw, &saved); err != nil {
		t.Fatal(err)
	}
	caKey, err := x509.ParsePKCS8PrivateKey(saved.Key)
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"tunnel.example.com", "deep.app.tunnel.example.com", "outside.example.com", "eviltunnel.example.com", "127.0.0.1", "::1"} {
		template := &x509.Certificate{SerialNumber: big.NewInt(2), NotBefore: time.Now().Add(-time.Minute), NotAfter: time.Now().Add(time.Hour), ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
		if ip := net.ParseIP(name); ip != nil {
			template.IPAddresses = []net.IP{ip}
		} else {
			template.DNSNames = []string{name}
		}
		der, err := x509.CreateCertificate(rand.Reader, template, ca, key.Public(), caKey)
		if err != nil {
			t.Fatal(err)
		}
		leaf, err := x509.ParseCertificate(der)
		if err != nil {
			t.Fatal(err)
		}
		_, err = leaf.Verify(x509.VerifyOptions{Roots: roots, DNSName: name})
		allowed := name == "tunnel.example.com" || name == "deep.app.tunnel.example.com"
		if (err == nil) != allowed {
			t.Fatalf("verify %s: %v", name, err)
		}
	}
	// Other admin commands must not incidentally return the certificate.
	result, err := server.AdminCall(context.Background(), socket, server.AdminRequest{Command: "fingerprint"})
	if err != nil || result.PublicCA != "" || result.Fingerprint != authority.Fingerprint() {
		t.Fatalf("fingerprint: %+v %v", result, err)
	}
}

func TestWritePublicCARejectsInvalidOrUnconstrained(t *testing.T) {
	authority, err := transportpki.Open(tunnel.MemoryStorage(), "tunnel.example.com", time.Now())
	if err != nil {
		t.Fatal(err)
	}
	valid := server.AdminResult{PublicCA: string(authority.PEM()), Fingerprint: authority.Fingerprint(), Domain: "tunnel.example.com"}
	manager, err := server.OpenManager(tunnel.MemoryStorage())
	if err != nil {
		t.Fatal(err)
	}
	block, _ := pem.Decode(authority.PEM())
	ca, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	ca.PublicKey = key.Public()
	ca.PermittedDNSDomains = nil
	ca.PermittedDNSDomainsCritical = false
	der, err := x509.CreateCertificate(rand.Reader, ca, ca, key.Public(), key)
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct{ name, cert, domain, fingerprint string }{
		{"missing", "", valid.Domain, valid.Fingerprint},
		{"malformed", "not PEM", valid.Domain, valid.Fingerprint},
		{"multiple", valid.PublicCA + valid.PublicCA, valid.Domain, valid.Fingerprint},
		{"private key", valid.PublicCA + string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: []byte("secret")})), valid.Domain, valid.Fingerprint},
		{"wrong domain", valid.PublicCA, "other.example.com", valid.Fingerprint},
		{"wrong fingerprint", valid.PublicCA, valid.Domain, "bad"},
		{"unconstrained", string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})), valid.Domain, valid.Fingerprint},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var out bytes.Buffer
			if err := writePublicCA(&out, server.AdminResult{PublicCA: tc.cert, Domain: tc.domain, Fingerprint: tc.fingerprint}); err == nil || out.Len() != 0 {
				t.Fatalf("err=%v output=%q", err, out.String())
			}
			if tc.cert != "" {
				admin, err := server.ListenAdmin(filepath.Join(t.TempDir(), "admin.sock"), manager, tc.fingerprint, tc.domain, tc.cert)
				if err == nil {
					_ = admin.Close()
					t.Fatal("admin socket accepted invalid CA")
				}
			}
		})
	}
}

func TestExtractPublicCAUnavailable(t *testing.T) {
	manager, err := server.OpenManager(tunnel.MemoryStorage())
	if err != nil {
		t.Fatal(err)
	}
	socket := filepath.Join(t.TempDir(), "admin.sock")
	admin, err := server.ListenAdmin(socket, manager, "", "", "")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = admin.Close() }()
	_, err = server.AdminCall(context.Background(), socket, server.AdminRequest{Command: "extract-public-ca"})
	if err == nil || !strings.Contains(err.Error(), "requires tunneld --domain") {
		t.Fatalf("got %v", err)
	}
}

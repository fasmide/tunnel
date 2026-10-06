package tunnel

import (
	"context"
	"crypto/x509"
	"encoding/pem"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// Exercise a TLS implementation independent of Go with restricted signature
// algorithms. This is not a real browser or OS trust-store test.
func TestConformancePrivateTLSAlgorithms(t *testing.T) {
	openssl, err := exec.LookPath("openssl")
	if err != nil {
		t.Skip("OpenSSL is required for independent TLS algorithm conformance")
	}
	c, s, _, authority, _ := privateClient(t)
	listener, err := c.ListenPrivate(context.Background(), "alice.example.com")
	if err != nil {
		t.Fatal(err)
	}
	servePlainApplication(t, listener)
	edge, err := s.ListenTLS("127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	caPath := filepath.Join(t.TempDir(), "ca.pem")
	if err := os.WriteFile(caPath, authority.PEM(), 0600); err != nil {
		t.Fatal(err)
	}
	for _, version := range []string{"tls1_2", "tls1_3"} {
		for _, algorithm := range []struct {
			name, schemes string
			want          x509.PublicKeyAlgorithm
		}{
			{"p256_only", "ecdsa_secp256r1_sha256", x509.ECDSA},
			// Permit P-256 signatures for the CA while offering Ed25519 for
			// the handshake. The listener prefers Ed25519 when supported.
			{"ed25519_capable", "ed25519:ecdsa_secp256r1_sha256", x509.Ed25519},
		} {
			t.Run(version+"/"+algorithm.name, func(t *testing.T) {
				ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
				defer cancel()
				cmd := exec.CommandContext(ctx, openssl, "s_client",
					"-connect", edge.Addr().String(), "-servername", "alice.example.com",
					"-"+version, "-sigalgs", algorithm.schemes, "-showcerts",
					"-CAfile", caPath, "-verify_return_error", "-verify_hostname", "alice.example.com",
					"-ign_eof")
				cmd.Stdin = strings.NewReader("GET / HTTP/1.1\r\nHost: alice.example.com\r\nConnection: close\r\n\r\n")
				output, err := cmd.CombinedOutput()
				if err != nil {
					t.Fatalf("OpenSSL handshake/request: %v\n%s", err, output)
				}
				block, _ := pem.Decode(output)
				if block == nil || block.Type != "CERTIFICATE" {
					t.Fatalf("missing peer certificate:\n%s", output)
				}
				leaf, err := x509.ParseCertificate(block.Bytes)
				if err != nil {
					t.Fatal(err)
				}
				if leaf.PublicKeyAlgorithm != algorithm.want || leaf.SignatureAlgorithm != x509.ECDSAWithSHA256 {
					t.Fatalf("unexpected leaf key/signature: %s/%s", leaf.PublicKeyAlgorithm, leaf.SignatureAlgorithm)
				}
				if len(leaf.DNSNames) != 1 || leaf.DNSNames[0] != "alice.example.com" || !strings.Contains(string(output), "client-side TLS") {
					t.Fatalf("unexpected certificate or HTTP response:\n%s", output)
				}
			})
		}
	}
}

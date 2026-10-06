package transportpki_test

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/json"
	"math/big"
	"net"
	"testing"
	"time"

	"tunnel"
	"tunnel/internal/transportpki"
)

func TestConstrainedCAAndRenewal(t *testing.T) {
	storage := tunnel.MemoryStorage()
	now := time.Now()
	a, err := transportpki.Open(storage, "tunnel.example.com", now)
	if err != nil {
		t.Fatal(err)
	}
	config := a.Config()
	ca, err := x509.ParseCertificate(config.Certificates[0].Certificate[1])
	if err != nil {
		t.Fatal(err)
	}
	if err := transportpki.ValidateCA(ca); err != nil {
		t.Fatal(err)
	}
	if !ca.NotAfter.Equal(now.AddDate(25, 0, 0).Truncate(time.Second)) {
		t.Fatalf("CA expiry %v, want 25 years", ca.NotAfter)
	}
	if !config.Certificates[0].Leaf.NotAfter.Equal(now.Add(7 * 24 * time.Hour).Truncate(time.Second)) {
		t.Fatal("leaf lifetime must remain seven days")
	}
	if _, err := transportpki.Open(storage, "tunnel.example.com", now.AddDate(24, 0, 0)); err != nil {
		t.Fatalf("CA should still work after 24 years: %v", err)
	}
	roots := x509.NewCertPool()
	roots.AddCert(ca)
	for _, host := range []string{"tunnel.example.com", "node.tunnel.example.com"} {
		if _, err := config.Certificates[0].Leaf.Verify(x509.VerifyOptions{DNSName: host, Roots: roots}); err != nil {
			t.Fatal(err)
		}
	}
	// Sign unauthorized names with the actual CA to test constraints rather than
	// merely checking the leaf SAN. Also test multi-level descendants.
	raw, err := storage.Get(transportpki.StateKey)
	if err != nil {
		t.Fatal(err)
	}
	var saved struct{ Key []byte }
	if err = json.Unmarshal(raw, &saved); err != nil {
		t.Fatal(err)
	}
	key, err := x509.ParsePKCS8PrivateKey(saved.Key)
	if err != nil {
		t.Fatal(err)
	}
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name    string
		ip      net.IP
		allowed bool
	}{{"deep.node.tunnel.example.com", nil, true}, {"example.com", nil, false}, {"eviltunnel.example.com", nil, false}, {"other.example.com", nil, false}, {"", net.ParseIP("127.0.0.1"), false}} {
		template := &x509.Certificate{SerialNumber: big.NewInt(2), NotBefore: now.Add(-time.Minute), NotAfter: now.Add(time.Hour), ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
		if tc.ip != nil {
			template.IPAddresses = []net.IP{tc.ip}
		} else {
			template.DNSNames = []string{tc.name}
		}
		der, err := x509.CreateCertificate(rand.Reader, template, ca, pub, key)
		if err != nil {
			t.Fatal(err)
		}
		leaf, err := x509.ParseCertificate(der)
		if err != nil {
			t.Fatal(err)
		}
		_, err = leaf.Verify(x509.VerifyOptions{Roots: roots})
		if (err == nil) != tc.allowed {
			t.Fatalf("name %s IP %v: %v", tc.name, tc.ip, err)
		}
	}
	renewed, err := transportpki.Open(storage, "tunnel.example.com", now.Add(8*24*time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(a.PEM(), renewed.PEM()) || a.Fingerprint() != renewed.Fingerprint() {
		t.Fatal("CA replaced on leaf renewal")
	}
	if bytes.Equal(config.Certificates[0].Certificate[0], renewed.Config().Certificates[0].Certificate[0]) {
		t.Fatal("leaf not renewed")
	}
	if _, err := transportpki.Open(storage, "other.example.com", now); err == nil {
		t.Fatal("domain silently changed")
	}
	if _, err := transportpki.Open(storage, "tunnel.example.com", now.AddDate(26, 0, 0)); err == nil {
		t.Fatal("expired CA silently replaced")
	}
	if err := storage.Put(transportpki.StateKey, []byte("corrupt")); err != nil {
		t.Fatal(err)
	}
	if _, err := transportpki.Open(storage, "tunnel.example.com", now); err == nil {
		t.Fatal("corrupt state replaced")
	}
}
func TestInvalidDomains(t *testing.T) {
	for _, domain := range []string{"", "*.example.com", ".example.com", "localhost", "127.0.0.1"} {
		if _, err := transportpki.Open(tunnel.MemoryStorage(), domain, time.Now()); err == nil {
			t.Fatalf("accepted %s", domain)
		}
	}
}

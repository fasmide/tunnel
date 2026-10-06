package transportpki

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"io/fs"
	"testing"
	"time"
)

type compatStore struct{ data []byte }

func (s *compatStore) Get(string) ([]byte, error) {
	if s.data == nil {
		return nil, fs.ErrNotExist
	}
	return s.data, nil
}
func (s *compatStore) Put(_ string, b []byte) error { s.data = append([]byte(nil), b...); return nil }
func TestExistingEd25519CARetainedAndDualTransportLeaves(t *testing.T) {
	store := &compatStore{}
	now := time.Now()
	a, err := Open(store, "tunnel.example.com", now)
	if err != nil {
		t.Fatal(err)
	}
	// Recreate the old CA algorithm with the exact same constrained template.
	pub, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := *a.ca
	template.SignatureAlgorithm = x509.PureEd25519
	template.PublicKey = nil
	template.PublicKeyAlgorithm = x509.Ed25519
	der, err := x509.CreateCertificate(rand.Reader, &template, &template, pub, key)
	if err != nil {
		t.Fatal(err)
	}
	encoded, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	store.data, err = json.Marshal(state{Domain: "tunnel.example.com", Certificate: der, Key: encoded})
	if err != nil {
		t.Fatal(err)
	}
	old := append([]byte(nil), store.data...)
	loaded, err := Open(store, "tunnel.example.com", now)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(old, store.data) || loaded.ca.PublicKeyAlgorithm != x509.Ed25519 {
		t.Fatal("old CA silently replaced")
	}
	for _, tc := range []struct {
		scheme    tls.SignatureScheme
		algorithm x509.PublicKeyAlgorithm
	}{{tls.Ed25519, x509.Ed25519}, {tls.ECDSAWithP256AndSHA256, x509.ECDSA}} {
		cert, err := loaded.Config().GetCertificate(&tls.ClientHelloInfo{ServerName: "tunnel.example.com", SupportedVersions: []uint16{tls.VersionTLS13}, SignatureSchemes: []tls.SignatureScheme{tc.scheme}})
		if err != nil {
			t.Fatal(err)
		}
		if cert.Leaf.PublicKeyAlgorithm != tc.algorithm {
			t.Fatal("wrong transport leaf selected")
		}
	}
}

package server

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/base64"
	"testing"
	"time"

	"github.com/fasmide/tunnel"
	"github.com/fasmide/tunnel/internal/transportpki"
	"github.com/fasmide/tunnel/internal/wire"
)

func TestPrivateIssuanceAuthorizationCSRAndRate(t *testing.T) {
	a, err := transportpki.Open(tunnel.MemoryStorage(), "example.com", time.Now())
	if err != nil {
		t.Fatal(err)
	}
	m := NewManager()
	pub := key(t)
	approve(t, m, pub, "alice.example.com")
	id, _ := m.connect(pub, func() {})
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	request := func(name string, template *x509.CertificateRequest) wire.IssueCertificate {
		der, err := x509.CreateCertificateRequest(rand.Reader, template, priv)
		if err != nil {
			t.Fatal(err)
		}
		return wire.IssueCertificate{Envelope: wire.Envelope{Type: "IssueCertificate", ID: "1"}, Name: name, CSR: base64.StdEncoding.EncodeToString(der)}
	}
	valid := request("alice.example.com", &x509.CertificateRequest{DNSNames: []string{"alice.example.com"}})
	if result := m.issueCertificate(id, valid, nil); result.Code != "unavailable" {
		t.Fatal(result)
	}
	unknown, _ := m.connect(key(t), func() {})
	if result := m.issueCertificate(unknown, valid, a); result.Code != "not_authorized" {
		t.Fatal(result)
	}
	if result := m.issueCertificate(id, request("bob.example.com", &x509.CertificateRequest{DNSNames: []string{"bob.example.com"}}), a); result.Code != "not_authorized" {
		t.Fatal(result)
	}
	if result := m.issueCertificate(id, valid, a); result.Code != "ok" {
		t.Fatal(result)
	}
	for _, template := range []*x509.CertificateRequest{
		{DNSNames: []string{"*.alice.example.com"}},
		{DNSNames: []string{"alice.example.com", "bob.example.com"}},
		{DNSNames: []string{"alice.example.com"}, ExtraExtensions: []pkix.Extension{{Id: asn1.ObjectIdentifier{2, 5, 29, 19}, Critical: true, Value: []byte{48, 3, 1, 1, 255}}}},
	} {
		result := m.issueCertificate(id, request("alice.example.com", template), a)
		if result.Code != "invalid_request" || len(result.Chain) != 0 {
			t.Fatal("unsafe CSR issued", result)
		}
	}
	damaged := valid
	der, err := base64.StdEncoding.DecodeString(valid.CSR)
	if err != nil {
		t.Fatal(err)
	}
	der[len(der)-1] ^= 1
	damaged.CSR = base64.StdEncoding.EncodeToString(der)
	if result := m.issueCertificate(id, damaged, a); result.Code != "invalid_request" {
		t.Fatal("invalid signature accepted", result)
	}
	approve(t, m, key(t), "api.alice.example.com")
	child := request("api.alice.example.com", &x509.CertificateRequest{DNSNames: []string{"api.alice.example.com"}})
	if result := m.issueCertificate(id, child, a); result.Code != "not_authorized" {
		t.Fatal("carveout signed", result)
	}
	for range 30 {
		m.issueCertificate(id, valid, a)
	}
	if result := m.issueCertificate(id, valid, a); result.Code != "rate_limited" {
		t.Fatal("rate limit missing", result)
	}
	m.Disconnect(id)
	next, _ := m.connect(pub, func() {})
	if result := m.issueCertificate(next, valid, a); result.Code != "rate_limited" {
		t.Fatal("reconnect bypassed rate", result)
	}
	if err := m.Revoke(pub, "test"); err != nil {
		t.Fatal(err)
	}
	if result := m.issueCertificate(next, valid, a); result.Code != "not_authorized" {
		t.Fatal("revoked key signed", result)
	}
}

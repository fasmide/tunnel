package tunnel

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"errors"
	"fmt"
	"io/fs"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestCredentialsPersistence(t *testing.T) {
	for name, s := range stores(t) {
		t.Run(name, func(t *testing.T) {
			if _, err := LoadCredentials(s); !errors.Is(err, fs.ErrNotExist) {
				t.Fatalf("missing = %v", err)
			}
			first, err := loadOrCreateCredentials(s)
			if err != nil {
				t.Fatal(err)
			}
			second, err := loadOrCreateCredentials(s)
			if err != nil {
				t.Fatal(err)
			}
			loaded, err := LoadCredentials(s)
			if err != nil {
				t.Fatal(err)
			}
			if len(first.Identity()) != 64 || first.Identity() != second.Identity() || first.Identity() != loaded.Identity() {
				t.Fatal("identity not persisted")
			}
			pub := first.PublicKey()
			pub[0] ^= 0xff
			if bytes.Equal(pub, first.PublicKey()) {
				t.Fatal("public key alias")
			}
			message := []byte("test identity")
			if !ed25519.Verify(loaded.PublicKey(), message, ed25519.Sign(first.privateKey, message)) {
				t.Fatal("key mismatch")
			}
			for _, format := range []string{"%v", "%+v", "%#v"} {
				if got := fmt.Sprintf(format, first); !strings.Contains(got, first.Identity()) || strings.Contains(got, "privateKey") {
					t.Fatalf("not redacted: %s", got)
				}
			}
		})
	}
}

func TestCredentialsMalformedNotReplaced(t *testing.T) {
	other, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	otherDER, err := x509.MarshalPKCS8PrivateKey(other)
	if err != nil {
		t.Fatal(err)
	}
	for _, data := range [][]byte{nil, []byte("garbage"), make([]byte, 64), otherDER} {
		s := MemoryStorage()
		if err := s.Put(privateKeyStorageKey, data); err != nil {
			t.Fatal(err)
		}
		if _, err := loadOrCreateCredentials(s); err == nil {
			t.Fatal("accepted malformed key")
		}
		got, err := s.Get(privateKeyStorageKey)
		if err != nil || !bytes.Equal(got, data) {
			t.Fatal("replaced malformed key")
		}
	}
	if _, err := LoadCredentials(nil); err == nil {
		t.Fatal("accepted nil storage")
	}
	if (Credentials{}).PublicKey() != nil || (Credentials{}).Identity() != "" {
		t.Fatal("valid zero credentials")
	}
	if _, err := (Credentials{}).identityCertificate(time.Now()); err == nil {
		t.Fatal("zero credential certificate")
	}
}

func TestCredentialsConcurrentInitialization(t *testing.T) {
	s := MemoryStorage()
	identities := make(chan string, 24)
	var wg sync.WaitGroup
	for range 24 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			c, err := loadOrCreateCredentials(s)
			if err != nil {
				t.Error(err)
				return
			}
			identities <- c.Identity()
		}()
	}
	wg.Wait()
	close(identities)
	var first string
	for id := range identities {
		if first == "" {
			first = id
		}
		if id != first {
			t.Fatal("concurrent initialization changed identity")
		}
	}
}

type failPutStorage struct {
	Storage
	err error
}

func (s failPutStorage) Put(string, []byte) error { return s.err }

func TestCredentialsPersistBeforeUse(t *testing.T) {
	failure := errors.New("cannot persist")
	c, err := loadOrCreateCredentials(failPutStorage{MemoryStorage(), failure})
	if !errors.Is(err, failure) || c.PublicKey() != nil {
		t.Fatalf("credentials escaped failed save: %v", err)
	}
}

func TestIdentityCertificate(t *testing.T) {
	c, err := loadOrCreateCredentials(MemoryStorage())
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	cert, err := c.identityCertificate(now)
	if err != nil {
		t.Fatal(err)
	}
	leaf := cert.Leaf
	if len(cert.Certificate) != 1 || leaf.IsCA || len(leaf.DNSNames) != 0 {
		t.Fatal("unexpected certificate shape")
	}
	if leaf.PublicKeyAlgorithm != x509.Ed25519 || leaf.SignatureAlgorithm != x509.PureEd25519 {
		t.Fatal("wrong certificate algorithms")
	}
	if !bytes.Equal(leaf.PublicKey.(ed25519.PublicKey), c.PublicKey()) {
		t.Fatal("wrong certificate identity")
	}
	if err := leaf.CheckSignature(leaf.SignatureAlgorithm, leaf.RawTBSCertificate, leaf.Signature); err != nil {
		t.Fatal(err)
	}
	if now.Before(leaf.NotBefore) || now.After(leaf.NotAfter) {
		t.Fatal("invalid validity")
	}
	if leaf.KeyUsage != x509.KeyUsageDigitalSignature || len(leaf.ExtKeyUsage) != 1 || leaf.ExtKeyUsage[0] != x509.ExtKeyUsageClientAuth {
		t.Fatal("wrong usages")
	}
	renewed, err := c.identityCertificate(now.Add(48 * time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(cert.Certificate[0], renewed.Certificate[0]) || !bytes.Equal(renewed.Leaf.PublicKey.(ed25519.PublicKey), c.PublicKey()) {
		t.Fatal("renewal changed identity or retained expired certificate")
	}
}

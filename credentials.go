package tunnel

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"errors"
	"fmt"
	"io/fs"
	"math/big"
	"sync"
	"time"
)

const privateKeyStorageKey = "creds/privkey"

// Credentials holds an Ed25519 identity, not proof of route approval. Its
// private key is intentionally unexported; it never goes to the daemon.
// Credentials must not be logged or serialized. A zero value is invalid.
type Credentials struct {
	privateKey ed25519.PrivateKey
	storage    Storage
}

// String and GoString redact private material in ordinary formatted output.
func (c Credentials) String() string   { return "tunnel.Credentials{identity:" + c.Identity() + "}" }
func (c Credentials) GoString() string { return c.String() }

// PublicKey returns a copy of the identity's public key, or nil for invalid
// credentials. Renewing a transport certificate does not change this identity.
func (c Credentials) PublicKey() ed25519.PublicKey {
	if len(c.privateKey) != ed25519.PrivateKeySize {
		return nil
	}
	return append(ed25519.PublicKey(nil), c.privateKey[ed25519.SeedSize:]...)
}

// Identity returns the full lowercase SHA-256 public-key identifier, or an
// empty string for invalid credentials.
func (c Credentials) Identity() string {
	pub := c.PublicKey()
	if pub == nil {
		return ""
	}
	digest := sha256.Sum256(pub)
	return hex.EncodeToString(digest[:])
}

// LoadCredentials loads an existing identity without creating a new one.
// Missing keys return an error wrapping fs.ErrNotExist. Malformed keys return
// an ordinary error and are never silently replaced. Keys are persisted as
// PKCS#8 DER, unencrypted; storage access controls protect the private key.
func LoadCredentials(storage Storage) (Credentials, error) {
	if storage == nil {
		return Credentials{}, errors.New("nil credential storage")
	}
	der, err := storage.Get(privateKeyStorageKey)
	if err != nil {
		return Credentials{}, fmt.Errorf("load credentials: %w", err)
	}
	key, err := x509.ParsePKCS8PrivateKey(der)
	if err != nil {
		return Credentials{}, fmt.Errorf("parse credentials: %w", err)
	}
	priv, ok := key.(ed25519.PrivateKey)
	if !ok || len(priv) != ed25519.PrivateKeySize {
		return Credentials{}, errors.New("credentials are not an Ed25519 private key")
	}
	expected := ed25519.NewKeyFromSeed(priv.Seed())
	if !bytes.Equal(expected, priv) {
		return Credentials{}, errors.New("inconsistent Ed25519 private key")
	}
	return Credentials{privateKey: append(ed25519.PrivateKey(nil), priv...), storage: storage}, nil
}

// Serialize bootstrap within this process; Storage cannot provide atomic
// create-if-absent across processes. Future RequestJoin calls this helper.
var credentialInitMu sync.Mutex

func loadOrCreateCredentials(storage Storage) (Credentials, error) {
	credentialInitMu.Lock()
	defer credentialInitMu.Unlock()
	creds, err := LoadCredentials(storage)
	if err == nil {
		return creds, nil
	}
	if !errors.Is(err, fs.ErrNotExist) {
		return Credentials{}, err
	}
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return Credentials{}, fmt.Errorf("generate identity: %w", err)
	}
	der, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		return Credentials{}, fmt.Errorf("encode identity: %w", err)
	}
	if err := storage.Put(privateKeyStorageKey, der); err != nil {
		return Credentials{}, fmt.Errorf("persist identity: %w", err)
	}
	// Reload and verify before using the persisted identity for a join.
	saved, err := LoadCredentials(storage)
	if err != nil {
		return Credentials{}, err
	}
	if !bytes.Equal(saved.privateKey, priv) {
		return Credentials{}, errors.New("identity changed during initialization; initialize storage before sharing it")
	}
	return saved, nil
}

// identityCertificate creates the client-auth leaf for the future QUIC layer.
// The server separately authorizes its public key; DNS subjects grant nothing.
func (c Credentials) identityCertificate(now time.Time) (tls.Certificate, error) {
	if c.PublicKey() == nil {
		return tls.Certificate{}, errors.New("invalid credentials")
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("generate certificate serial: %w", err)
	}
	serial.Add(serial, big.NewInt(1))
	template := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: c.Identity()},
		NotBefore:             now.Add(-5 * time.Minute),
		NotAfter:              now.Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, c.PublicKey(), c.privateKey)
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("create identity certificate: %w", err)
	}
	leaf, err := x509.ParseCertificate(der)
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("parse identity certificate: %w", err)
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: append(ed25519.PrivateKey(nil), c.privateKey...), Leaf: leaf}, nil
}

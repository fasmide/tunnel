package tunnel

import (
	"bytes"
	"context"
	"crypto/tls"
	"errors"
	"io/fs"
	"strings"
	"testing"
	"time"

	"tunnel/internal/server"
	"tunnel/internal/transportpki"
)

func TestGeneratedCATrustBootstrapJoinAndDial(t *testing.T) {
	for _, tofu := range []bool{false, true} {
		t.Run(map[bool]string{false: "fingerprint", true: "explicit_TOFU"}[tofu], func(t *testing.T) {
			a, err := transportpki.Open(MemoryStorage(), "tunnel.example.com", time.Now())
			if err != nil {
				t.Fatal(err)
			}
			m := server.NewManager()
			s, err := server.Listen("127.0.0.1:0", a.Config(), m)
			if err != nil {
				t.Fatal(err)
			}
			defer func() { _ = s.Close() }()
			storage := MemoryStorage()
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			request := TrustRequest{Storage: storage, ServerName: "tunnel.example.com", TOFU: tofu}
			if !tofu {
				request.Fingerprint = a.Fingerprint()
			}
			trust, err := BootstrapTrust(ctx, s.Addr(), request)
			if err != nil {
				t.Fatal(err)
			}
			if !trust.FirstUse || trust.Fingerprint != a.Fingerprint() || !bytes.Equal(trust.CA, a.PEM()) {
				t.Fatal("unexpected trust result")
			}
			again, err := BootstrapTrust(ctx, s.Addr(), request)
			if err != nil || again.FirstUse {
				t.Fatalf("saved trust %v", err)
			}
			config, err := LoadTransportTLS(storage, s.Addr(), "node.tunnel.example.com")
			if err != nil {
				t.Fatal(err)
			}
			creds, err := RequestJoin(ctx, s.Addr(), JoinRequest{Storage: storage, Routes: []string{"app.example.com"}, TLSConfig: config})
			if err != nil {
				t.Fatal(err)
			}
			grant(t, m, creds, "app.example.com")
			c, err := Dial(ctx, s.Addr(), WithCredentials(creds), WithTLSConfig(config))
			if err != nil {
				t.Fatal(err)
			}
			if err := c.Close(); err != nil {
				t.Fatal(err)
			}
			// Replacing the daemon's CA at the same endpoint must fail, even with TOFU.
			addr := s.Addr()
			if err := s.Close(); err != nil {
				t.Fatal(err)
			}
			other, err := transportpki.Open(MemoryStorage(), "tunnel.example.com", time.Now())
			if err != nil {
				t.Fatal(err)
			}
			next := reopenServer(t, addr, other.Config(), m)
			defer func() { _ = next.Close() }()
			if _, err := BootstrapTrust(ctx, addr, request); err == nil {
				t.Fatal("TOFU/pin overwrote established trust")
			}
			if _, err := Dial(ctx, addr, WithCredentials(creds), WithTLSConfig(config)); err == nil {
				t.Fatal("saved CA trusted replacement")
			}
		})
	}
}

type failingTrustStorage struct {
	Storage
	fail bool
}

func (s *failingTrustStorage) Put(key string, data []byte) error {
	if s.fail {
		return errors.New("trust write failed")
	}
	return s.Storage.Put(key, data)
}

func TestTrustPersistenceFailureAndLiveLeafRenewal(t *testing.T) {
	// Initial leaf has expired, but CA is valid: live handshakes must renew
	// through GetCertificate rather than use Config's initial certificate.
	a, err := transportpki.Open(MemoryStorage(), "tunnel.example.com", time.Now().Add(-8*24*time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	initial := a.Config().Certificates[0].Certificate[0]
	s, err := server.Listen("127.0.0.1:0", a.Config(), server.NewManager())
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = s.Close() }()
	storage := &failingTrustStorage{Storage: MemoryStorage(), fail: true}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	request := TrustRequest{Storage: storage, ServerName: "tunnel.example.com", Fingerprint: a.Fingerprint()}
	if _, err := BootstrapTrust(ctx, s.Addr(), request); err == nil {
		t.Fatal("bootstrap succeeded despite persistence failure")
	}
	// Explicitly exercise P-256 renewal too: Go clients may select Ed25519,
	// leaving the other cached algorithm untouched until it is requested.
	renewed, err := a.Config().GetCertificate(&tls.ClientHelloInfo{ServerName: "tunnel.example.com", SupportedVersions: []uint16{tls.VersionTLS13}, SignatureSchemes: []tls.SignatureScheme{tls.ECDSAWithP256AndSHA256}})
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(initial, renewed.Certificate[0]) {
		t.Fatal("live leaf not renewed")
	}
	storage.fail = false
	if _, err := BootstrapTrust(ctx, s.Addr(), request); err != nil {
		t.Fatal(err)
	}
	if err := storage.Put(trustKey(s.Addr()), []byte("corrupt")); err != nil {
		t.Fatal(err)
	}
	if _, err := BootstrapTrust(ctx, s.Addr(), request); err == nil {
		t.Fatal("corrupt trust replaced")
	}
}

func TestBootstrapRejectsWrongFingerprintNameAndImplicitTrust(t *testing.T) {
	a, err := transportpki.Open(MemoryStorage(), "tunnel.example.com", time.Now())
	if err != nil {
		t.Fatal(err)
	}
	s, err := server.Listen("127.0.0.1:0", a.Config(), server.NewManager())
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = s.Close() }()
	for _, r := range []TrustRequest{{ServerName: "tunnel.example.com"}, {ServerName: "tunnel.example.com", TOFU: true, Fingerprint: a.Fingerprint()}, {ServerName: "tunnel.example.com", Fingerprint: strings.Repeat("0", 64)}, {ServerName: "outside.example.com", TOFU: true}, {TOFU: true}} {
		storage := MemoryStorage()
		r.Storage = storage
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		_, err := BootstrapTrust(ctx, s.Addr(), r)
		cancel()
		if err == nil {
			t.Fatal("invalid bootstrap accepted")
		}
		if _, err := storage.Get(trustKey(s.Addr())); !errors.Is(err, fs.ErrNotExist) {
			t.Fatal("failed bootstrap persisted trust")
		}
	}
}
func TestBootstrapDoesNotAcceptUnconstrainedPublicCertificate(t *testing.T) {
	s, _, _ := runningServer(t)
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	if _, err := BootstrapTrust(ctx, s.Addr(), TrustRequest{Storage: MemoryStorage(), ServerName: "localhost", TOFU: true}); err == nil {
		t.Fatal("unconstrained CA accepted")
	}
}

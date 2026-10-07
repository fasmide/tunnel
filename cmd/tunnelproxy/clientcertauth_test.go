package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/pem"
	"math/big"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func makeClientCertificate(t *testing.T, parent *x509.Certificate, signer *ecdsa.PrivateKey, usage x509.ExtKeyUsage, expired bool) (tls.Certificate, *x509.Certificate, *ecdsa.PrivateKey) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 120))
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{SerialNumber: serial, Subject: pkix.Name{CommonName: "client"}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{usage}}
	if expired {
		template.NotAfter = time.Now().Add(-time.Minute)
	}
	if parent == nil {
		parent, signer = template, key
	}
	der, err := x509.CreateCertificate(rand.Reader, template, parent, &key.PublicKey, signer)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key, Leaf: cert}, cert, key
}
func certPin(cert *x509.Certificate) string {
	digest := sha256.Sum256(cert.Raw)
	return hex.EncodeToString(digest[:])
}

func TestClientCertAuthCLI(t *testing.T) {
	pin := strings.Repeat("ab", 32)
	for _, command := range []string{"serve", "joinserve"} {
		base := []string{command, "-s", "tunnel.example.com", "-n", "app.example.com", "-t", "127.0.0.1:8080"}
		c, err := parse(append(append([]string{}, base...), "--clientcertauth="+pin, "--clientcertauth="+strings.ToUpper(pin)))
		if err != nil || len(c.clientCertAuth) != 2 {
			t.Fatalf("pins %+v %v", c, err)
		}
		for _, extra := range [][]string{{"--clientcertauth="}, {"--clientcertauth=bad"}, {"--clientcertauth=" + pin, "--basicauth"}, {"--clientcertauth=" + pin, "--cookieauth"}, {"--clientcertauth=" + pin, "--clientcertauth-ca=ca.pem"}, {"--clientcertauth=" + pin, "--mode=http"}, {"--clientcertauth=" + pin, "--mode=raw"}, {"--clientcertauth-ca="}, {"--clientcertauth-ca=ca.pem", "--cookieauth"}} {
			if _, err := parse(append(append([]string{}, base...), extra...)); err == nil {
				t.Fatalf("accepted %v", extra)
			}
		}
	}
	colon := strings.TrimSuffix(strings.Repeat("AB:", 32), ":")
	if _, err := parseClientCertFingerprint(colon); err != nil {
		t.Fatal(err)
	}
	if _, err := parseClientCertFingerprint("SHA256 Fingerprint=" + colon); err == nil {
		t.Fatal("accepted label")
	}
}

func TestPinnedClientCertificatePolicy(t *testing.T) {
	_, good, _ := makeClientCertificate(t, nil, nil, x509.ExtKeyUsageClientAuth, false)
	_, expired, _ := makeClientCertificate(t, nil, nil, x509.ExtKeyUsageClientAuth, true)
	_, wrongUsage, _ := makeClientCertificate(t, nil, nil, x509.ExtKeyUsageServerAuth, false)
	_, unknown, _ := makeClientCertificate(t, nil, nil, x509.ExtKeyUsageClientAuth, false)
	auth, err := prepareClientCertAuth(config{mode: "byo", clientCertAuth: []string{certPin(good), certPin(expired), certPin(wrongUsage)}})
	if err != nil {
		t.Fatal(err)
	}
	for _, test := range []struct {
		cert    *x509.Certificate
		allowed bool
	}{{good, true}, {expired, false}, {wrongUsage, false}, {unknown, false}, {nil, false}} {
		state := tls.ConnectionState{DidResume: true}
		if test.cert != nil {
			state.PeerCertificates = []*x509.Certificate{test.cert}
		}
		if got := auth.VerifyConnection(state) == nil; got != test.allowed {
			t.Fatalf("allowed=%v want %v", got, test.allowed)
		}
	}
}

func TestClientCertAuthTLS(t *testing.T) {
	// A dedicated CA, unrelated to the public server's certificate authority.
	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	caTemplate := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "test client CA"}, IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour)}
	caDER, err := x509.CreateCertificate(rand.Reader, caTemplate, caTemplate, &caKey.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	ca, err := x509.ParseCertificate(caDER)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "ca.pem")
	if err := os.WriteFile(path, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caDER}), 0600); err != nil {
		t.Fatal(err)
	}
	good, leaf, _ := makeClientCertificate(t, ca, caKey, x509.ExtKeyUsageClientAuth, false)
	unknown, _, _ := makeClientCertificate(t, nil, nil, x509.ExtKeyUsageClientAuth, false)
	wrong, wrongLeaf, _ := makeClientCertificate(t, ca, caKey, x509.ExtKeyUsageServerAuth, false)
	expired, expiredLeaf, _ := makeClientCertificate(t, ca, caKey, x509.ExtKeyUsageClientAuth, true)
	for _, policy := range []config{{mode: "byo", clientCertAuth: []string{certPin(leaf), certPin(wrongLeaf), certPin(expiredLeaf)}}, {mode: "byo", clientCertAuthCA: path}} {
		auth, err := prepareClientCertAuth(policy)
		if err != nil {
			t.Fatal(err)
		}
		front := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(204) }))
		front.EnableHTTP2 = true
		front.TLS = &tls.Config{ClientAuth: auth.ClientAuth, ClientCAs: auth.ClientCAs, VerifyConnection: auth.VerifyConnection, MinVersion: tls.VersionTLS12}
		front.StartTLS()
		roots := x509.NewCertPool()
		roots.AddCert(front.Certificate())
		for _, cert := range []*tls.Certificate{&good, nil, &unknown, &wrong, &expired} {
			cfg := &tls.Config{RootCAs: roots, ClientSessionCache: tls.NewLRUClientSessionCache(8)}
			if cert != nil {
				cfg.Certificates = []tls.Certificate{*cert}
			}
			tr := &http.Transport{TLSClientConfig: cfg, ForceAttemptHTTP2: true}
			client := &http.Client{Transport: tr, Timeout: 3 * time.Second}
			for i := 0; i < 2; i++ {
				resp, err := client.Get(front.URL)
				if cert == &good {
					if err != nil {
						t.Fatal(err)
					}
					if resp.StatusCode != 204 || resp.ProtoMajor != 2 {
						t.Fatalf("response %v", resp)
					}
					if i == 1 && !resp.TLS.DidResume {
						t.Fatal("session did not resume")
					}
				} else if err == nil {
					t.Fatal("unauthorized client accepted")
				}
				if resp != nil {
					_ = resp.Body.Close()
				}
				tr.CloseIdleConnections()
			}
		}
		front.Close()
	}
	for _, data := range []string{"", "not PEM", string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: leaf.Raw})), string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caDER})) + "junk"} {
		badPath := filepath.Join(t.TempDir(), "bad.pem")
		if err := os.WriteFile(badPath, []byte(data), 0600); err != nil {
			t.Fatal(err)
		}
		if _, err := prepareClientCertAuth(config{mode: "byo", clientCertAuthCA: badPath}); err == nil {
			t.Fatal("invalid CA accepted")
		}
	}
}

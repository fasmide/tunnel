package main

import (
	"context"
	"crypto/tls"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// This interoperability test intentionally requires curl and openssl on PATH.
// It exercises real certificate generation, OpenSSL fingerprint formatting,
// and curl's TLS client authentication without disabling server verification.
func TestClientCertAuthCurlOpenSSL(t *testing.T) {
	for _, tool := range []string{"curl", "openssl"} {
		if _, err := exec.LookPath(tool); err != nil {
			t.Fatalf("interop test requires %s on PATH: %v", tool, err)
		}
	}
	dir := t.TempDir()
	run := func(program string, args ...string) (string, error) {
		t.Helper()
		ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		defer cancel()
		cmd := exec.CommandContext(ctx, program, args...)
		cmd.Dir = dir
		output, err := cmd.CombinedOutput()
		return string(output), err
	}
	openssl := func(args ...string) string {
		t.Helper()
		output, err := run("openssl", args...)
		if err != nil {
			t.Fatalf("openssl %v: %v\n%s", args, err, output)
		}
		return output
	}
	// Self-signed certificates allow enrollment without a client CA file.
	for _, name := range []string{"alice", "unknown"} {
		openssl("req", "-x509", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:P-256",
			"-noenc", "-keyout", name+".key", "-out", name+".crt", "-days", "1", "-subj", "/CN="+name,
			"-addext", "basicConstraints=critical,CA:FALSE",
			"-addext", "keyUsage=critical,digitalSignature", "-addext", "extendedKeyUsage=clientAuth")
	}
	fingerprintOutput := openssl("x509", "-in", "alice.crt", "-noout", "-fingerprint", "-sha256")
	_, fingerprint, ok := strings.Cut(strings.TrimSpace(fingerprintOutput), "=")
	if !ok {
		t.Fatalf("unexpected OpenSSL fingerprint output: %q", fingerprintOutput)
	}
	// A dedicated CA and signed leaf exercise normal chain verification.
	openssl("req", "-x509", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:P-256",
		"-noenc", "-keyout", "ca.key", "-out", "ca.crt", "-days", "1", "-subj", "/CN=Interop Client CA",
		"-addext", "basicConstraints=critical,CA:TRUE", "-addext", "keyUsage=critical,keyCertSign,cRLSign")
	openssl("req", "-new", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:P-256",
		"-noenc", "-keyout", "bob.key", "-out", "bob.csr", "-subj", "/CN=Bob")
	extensions := filepath.Join(dir, "client.ext")
	if err := os.WriteFile(extensions, []byte("basicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature\nextendedKeyUsage=clientAuth\n"), 0600); err != nil {
		t.Fatal(err)
	}
	openssl("x509", "-req", "-in", "bob.csr", "-CA", "ca.crt", "-CAkey", "ca.key",
		"-set_serial", "2", "-out", "bob.crt", "-days", "1", "-extfile", extensions)

	for _, policy := range []struct {
		name     string
		config   config
		allowed  string
		rejected string
	}{
		{"fingerprint", config{mode: "byo", clientCertAuth: []string{fingerprint}}, "alice", "bob"},
		{"ca", config{mode: "byo", clientCertAuthCA: filepath.Join(dir, "ca.crt")}, "bob", "alice"},
	} {
		t.Run(policy.name, func(t *testing.T) {
			auth, err := prepareClientCertAuth(policy.config)
			if err != nil {
				t.Fatal(err)
			}
			front := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				_, _ = w.Write([]byte("authenticated\n"))
			}))
			front.TLS = &tls.Config{MinVersion: tls.VersionTLS12, ClientAuth: auth.ClientAuth,
				ClientCAs: auth.ClientCAs, VerifyConnection: auth.VerifyConnection}
			front.StartTLS()
			defer front.Close()
			serverCA := filepath.Join(dir, policy.name+"-server.crt")
			if err := os.WriteFile(serverCA, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: front.Certificate().Raw}), 0600); err != nil {
				t.Fatal(err)
			}
			for _, identity := range []string{policy.allowed, "", "unknown", policy.rejected} {
				args := []string{"--disable", "--silent", "--show-error", "--fail", "--noproxy", "*",
					"--max-time", "5", "--cacert", serverCA}
				if identity != "" {
					args = append(args, "--cert", filepath.Join(dir, identity+".crt"), "--key", filepath.Join(dir, identity+".key"))
				}
				args = append(args, front.URL)
				output, err := run("curl", args...)
				if identity == policy.allowed {
					if err != nil || output != "authenticated\n" {
						t.Fatalf("allowed client %s: %v\n%s", identity, err, output)
					}
				} else if err == nil || strings.Contains(output, "authenticated") {
					t.Fatalf("unauthorized client %q accepted: %v\n%s", identity, err, output)
				}
			}
		})
	}
}

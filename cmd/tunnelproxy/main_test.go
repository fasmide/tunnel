package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/fasmide/tunnel"
	"github.com/fasmide/tunnel/internal/server"
	"github.com/fasmide/tunnel/internal/transportpki"
)

func TestParseAndLoopbackPolicy(t *testing.T) {
	base := []string{"serve", "-s", "tunnel.example.com:7443", "-n", "app.example.com", "-t", "127.0.0.1:8080"}
	c, err := parse(base)
	if err != nil || c.mode != "acme" {
		t.Fatalf("default: %+v %v", c, err)
	}
	for _, extra := range [][]string{{"-m", "unknown"}, {"-m", "byo"}, {"--cert", "x"}, {"--setup-timeout", "0s"}, {"-m", "http", "--acme-email", "x"}} {
		if _, err := parse(append(append([]string{}, base...), extra...)); err == nil {
			t.Fatalf("accepted %v", extra)
		}
	}
	for _, args := range [][]string{{}, {"join"}, {"joinserve"}, {"join", "-s", "a:7443", "-n", "a", "-t", "127.0.0.1:80"}} {
		if _, err := parse(args); err == nil {
			t.Fatalf("accepted %v", args)
		}
	}
	for _, target := range []string{"127.0.0.1:80", "[::1]:80", "localhost:8080"} {
		addresses, err := targets(context.Background(), target)
		if err != nil || len(addresses) == 0 {
			t.Fatalf("%s: %v", target, err)
		}
	}
	for _, target := range []string{"0.0.0.0:80", "192.168.1.1:80", "example.com:80", "[::]:80", "127.0.0.1:0", "127.0.0.1:http"} {
		if _, err := targets(context.Background(), target); err == nil {
			t.Fatalf("accepted non-loopback/invalid %s", target)
		}
	}
}
func TestServerAddressDefaults(t *testing.T) {
	for input, want := range map[string]string{"tunnel.example.net": "tunnel.example.net:7443", "tunnel.example.net:7443": "tunnel.example.net:7443", "localhost:8443": "localhost:8443", "127.0.0.1": "127.0.0.1:7443", "::1": "[::1]:7443", "[::1]": "[::1]:7443", "[::1]:8443": "[::1]:8443"} {
		c, err := parse([]string{"join", "-s", input, "-n", "hello.tunnel.example.net"})
		if err != nil || c.server != want {
			t.Fatalf("%s: %s %v want %s", input, c.server, err, want)
		}
	}
	for _, input := range []string{":7443", "host:", "host:0", "host:65536", "host:abc", "https://host", "host/path", "[host]", "host:123:456"} {
		if _, err := serverAddress(input); err == nil {
			t.Fatalf("accepted %s", input)
		}
	}
}
func TestReadConfirmation(t *testing.T) {
	ok, err := readConfirmation(strings.NewReader("yes\n"))
	if err != nil || !ok {
		t.Fatalf("yes: %v %v", ok, err)
	}
	ok, err = readConfirmation(strings.NewReader("n\n"))
	if err != nil || ok {
		t.Fatalf("no: %v %v", ok, err)
	}
}

func TestStateDirectoryDefaults(t *testing.T) {
	// UserConfigDir follows XDG_CONFIG_HOME on Linux; HOME supplies fallback.
	t.Setenv("XDG_CONFIG_HOME", t.TempDir())
	args := []string{"join", "-s", "tunnel.example.net", "-n", "hello.tunnel.example.net"}
	c, err := parse(args)
	if err != nil {
		t.Fatal(err)
	}
	dir, err := os.UserConfigDir()
	if err != nil {
		t.Fatal(err)
	}
	if c.state != filepath.Join(dir, "tunnelproxy") {
		t.Fatalf("state %s", c.state)
	}
	t.Setenv("XDG_CONFIG_HOME", "")
	t.Setenv("HOME", t.TempDir())
	c, err = parse(args)
	if err != nil {
		t.Fatal(err)
	}
	dir, err = os.UserConfigDir()
	if err != nil {
		t.Fatal(err)
	}
	if c.state != filepath.Join(dir, "tunnelproxy") {
		t.Fatalf("fallback state %s", c.state)
	}
	c, err = parse(append(args, "--state", "./custom-state"))
	if err != nil || c.state != "./custom-state" {
		t.Fatalf("override %+v %v", c, err)
	}
}

func tcpPair(t *testing.T) (*net.TCPConn, *net.TCPConn) {
	t.Helper()
	l, err := net.ListenTCP("tcp", &net.TCPAddr{IP: net.ParseIP("127.0.0.1")})
	if err != nil {
		t.Fatal(err)
	}
	peer, err := net.DialTCP("tcp", nil, l.Addr().(*net.TCPAddr))
	if err != nil {
		t.Fatal(err)
	}
	conn, err := l.AcceptTCP()
	if err != nil {
		t.Fatal(err)
	}
	_ = l.Close()
	t.Cleanup(func() { _ = peer.Close(); _ = conn.Close() })
	_ = peer.SetDeadline(time.Now().Add(5 * time.Second))
	_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
	return peer, conn
}
func TestRelayDirectionalEOFAndBinaryResponse(t *testing.T) {
	public, incoming := tcpPair(t)
	backend, local := tcpPair(t)
	done := make(chan error, 1)
	go func() { done <- relay(incoming, local) }()
	payload := []byte{0, 255, 1, 2}
	if _, err := public.Write(payload); err != nil {
		t.Fatal(err)
	}
	if err := public.CloseWrite(); err != nil {
		t.Fatal(err)
	}
	data, err := io.ReadAll(backend)
	if err != nil || !bytes.Equal(data, payload) {
		t.Fatalf("request %x %v", data, err)
	}
	if _, err := backend.Write([]byte("after EOF")); err != nil {
		t.Fatal(err)
	}
	if err := backend.CloseWrite(); err != nil {
		t.Fatal(err)
	}
	data, err = io.ReadAll(public)
	if err != nil || string(data) != "after EOF" {
		t.Fatalf("response %s %v", data, err)
	}
	if err := <-done; err != nil {
		t.Fatal(err)
	}
}
func wait(t *testing.T, condition func() bool) {
	t.Helper()
	until := time.Now().Add(5 * time.Second)
	for !condition() {
		if time.Now().After(until) {
			t.Fatal("condition not reached")
		}
		time.Sleep(5 * time.Millisecond)
	}
}
func appCertificate(t *testing.T, dir string) (tls.Certificate, *x509.CertPool) {
	t.Helper()
	pub, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(1), DNSNames: []string{"app.example.com"}, NotBefore: now.Add(-time.Hour), NotAfter: now.Add(time.Hour), ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}, KeyUsage: x509.KeyUsageDigitalSignature}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, pub, key)
	if err != nil {
		t.Fatal(err)
	}
	encoded, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(filepath.Join(dir, "cert.pem"), pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0600); err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(filepath.Join(dir, "key.pem"), pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: encoded}), 0600); err != nil {
		t.Fatal(err)
	}
	cert, err := tls.LoadX509KeyPair(filepath.Join(dir, "cert.pem"), filepath.Join(dir, "key.pem"))
	if err != nil {
		t.Fatal(err)
	}
	leaf, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	roots := x509.NewCertPool()
	roots.AddCert(leaf)
	return cert, roots
}
func TestJoinServeModesAndSignalDrain(t *testing.T) {
	for _, variant := range []string{"http", "byo", "raw", "private", "http-auth", "byo-auth", "raw-auth", "private-auth", "http-cookie", "byo-cookie", "raw-cookie", "private-cookie"} {
		t.Run(variant, func(t *testing.T) {
			mode := strings.TrimSuffix(strings.TrimSuffix(variant, "-auth"), "-cookie")
			withAuth := strings.HasSuffix(variant, "-auth")
			withCookie := strings.HasSuffix(variant, "-cookie")
			a, err := transportpki.Open(tunnel.MemoryStorage(), "example.com", time.Now())
			if err != nil {
				t.Fatal(err)
			}
			m := server.NewManager()
			s, err := server.ListenWithAuthority("127.0.0.1:0", a.Config(), m, a)
			if err != nil {
				t.Fatal(err)
			}
			defer func() { _ = s.Close() }()
			dir := t.TempDir()
			cert, roots := appCertificate(t, dir)
			if mode == "private" {
				block, _ := pem.Decode(a.PEM())
				ca, err := x509.ParseCertificate(block.Bytes)
				if err != nil {
					t.Fatal(err)
				}
				roots = x509.NewCertPool()
				roots.AddCert(ca)
			}
			backend, err := net.Listen("tcp", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			defer func() { _ = backend.Close() }()
			target := backend.Addr().String()
			service := backend
			if mode == "raw" {
				service = tls.NewListener(backend, &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS12})
			}
			backendDone := make(chan struct{})
			go func() {
				defer close(backendDone)
				_ = http.Serve(service, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { _, _ = io.WriteString(w, "existing service") }))
			}()
			// Full CLI join path, using fingerprint-verified generated transport trust.
			common := []string{"-s", s.Addr(), "--server-name", "tunnel.example.com", "-n", "app.example.com", "--state", dir}
			joinArgs := append([]string{"join"}, common...)
			joinArgs = append(joinArgs, "-f", a.Fingerprint())
			var output bytes.Buffer
			ctx, cancelSetup := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancelSetup()
			if err := run(ctx, joinArgs, &output); err != nil {
				t.Fatal(err)
			}
			if !strings.Contains(output.String(), "administrator approval") {
				t.Fatal(output.String())
			}
			invites := m.Invites()
			if len(invites) != 1 {
				t.Fatalf("invites %d", len(invites))
			}
			if _, err := m.DecideInvite(invites[0].ID, true); err != nil {
				t.Fatal(err)
			}
			args := append([]string{"serve"}, common...)
			args = append(args, "-t", target, "-m", mode, "--drain-timeout", "2s")
			if withAuth {
				args = append(args, "--basicauth=user:secret", "--basicauth=colleague:another-secret")
			}
			if withCookie {
				args = append(args, "--cookieauth=user:secret", "--cookieauth=colleague:another-secret")
			}
			if mode == "byo" {
				args = append(args, "--cert", filepath.Join(dir, "cert.pem"), "--key", filepath.Join(dir, "key.pem"))
			}
			serving, cancel := context.WithCancel(context.Background())
			defer cancel()
			done := make(chan error, 1)
			go func() { done <- run(serving, args, io.Discard) }()
			class := "tls"
			if mode == "http" {
				class = "http"
			}
			wait(t, func() bool { _, ok := m.Select("app.example.com", class); return ok })
			var edge *server.TLSEdge
			if mode == "http" {
				edge, err = s.ListenHTTP("127.0.0.1:0")
			} else {
				edge, err = s.ListenTLS("127.0.0.1:0")
			}
			if err != nil {
				t.Fatal(err)
			}
			tr := &http.Transport{ForceAttemptHTTP2: true, DisableKeepAlives: mode != "byo", TLSClientConfig: &tls.Config{RootCAs: roots, ServerName: "app.example.com"}, DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
				return (&net.Dialer{}).DialContext(ctx, network, edge.Addr().String())
			}}
			defer tr.CloseIdleConnections()
			scheme := "https"
			if mode == "http" {
				scheme = "http"
			}
			client := &http.Client{Transport: tr, Timeout: 3 * time.Second}
			resp, err := client.Get(scheme + "://app.example.com/")
			if err != nil {
				t.Fatal(err)
			}
			if withAuth && mode != "raw" {
				_, _ = io.Copy(io.Discard, resp.Body)
				_ = resp.Body.Close()
				if resp.StatusCode != http.StatusUnauthorized {
					t.Fatalf("unauthenticated status %d", resp.StatusCode)
				}
				request, err := http.NewRequest(http.MethodGet, scheme+"://app.example.com/", nil)
				if err != nil {
					t.Fatal(err)
				}
				for _, pair := range [][2]string{{"user", "secret"}, {"colleague", "another-secret"}} {
					request.SetBasicAuth(pair[0], pair[1])
					resp, err = client.Do(request)
					if err != nil {
						t.Fatal(err)
					}
					if resp.StatusCode != http.StatusOK {
						t.Fatalf("identity %s: status %d", pair[0], resp.StatusCode)
					}
					if pair[0] == "user" {
						_, _ = io.Copy(io.Discard, resp.Body)
						_ = resp.Body.Close()
					}
				}
			}
			if withCookie && mode != "raw" {
				_ = resp.Body.Close()
				if resp.StatusCode != http.StatusUnauthorized {
					t.Fatalf("unauthenticated cookie status %d", resp.StatusCode)
				}
				jar, err := cookiejar.New(nil)
				if err != nil {
					t.Fatal(err)
				}
				client.Jar = jar
				baseURL := scheme + "://app.example.com"
				for _, pair := range [][2]string{{"user", "secret"}, {"colleague", "another-secret"}} {
					page, err := client.Get(baseURL + authLoginPath)
					if err != nil {
						t.Fatal(err)
					}
					_, _ = io.Copy(io.Discard, page.Body)
					_ = page.Body.Close()
					csrf := ""
					loginURL, err := url.Parse(baseURL + authLoginPath)
					if err != nil {
						t.Fatal(err)
					}
					for _, c := range jar.Cookies(loginURL) {
						if strings.HasSuffix(c.Name, "-csrf") {
							csrf = c.Value
						}
					}
					resp, err = client.PostForm(baseURL+authLoginPath, url.Values{"csrf": {csrf}, "username": {pair[0]}, "password": {pair[1]}, "return": {"/"}})
					if err != nil {
						t.Fatal(err)
					}
					if resp.StatusCode != http.StatusOK {
						t.Fatalf("cookie login %s: %d", pair[0], resp.StatusCode)
					}
					if pair[0] == "user" {
						_, _ = io.Copy(io.Discard, resp.Body)
						_ = resp.Body.Close()
					}
				}
			}
			if mode == "byo" && resp.ProtoMajor != 2 {
				t.Fatalf("browser should negotiate HTTP/2, got %s", resp.Proto)
			}
			body, err := io.ReadAll(resp.Body)
			_ = resp.Body.Close()
			if err != nil || string(body) != "existing service" {
				t.Fatalf("response %s %v", body, err)
			}
			cancel()
			select {
			case err := <-done:
				if err != nil {
					t.Fatal(err)
				}
			case <-time.After(4 * time.Second):
				t.Fatal("proxy did not drain")
			}
			_ = service.Close()
			<-backendDone
		})
	}
}
func TestJoinServeWaitsForApproval(t *testing.T) {
	a, err := transportpki.Open(tunnel.MemoryStorage(), "example.com", time.Now())
	if err != nil {
		t.Fatal(err)
	}
	m := server.NewManager()
	s, err := server.ListenWithAuthority("127.0.0.1:0", a.Config(), m, a)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = s.Close() }()
	ctx, cancel := context.WithTimeout(context.Background(), 150*time.Millisecond)
	defer cancel()
	var out bytes.Buffer
	err = run(ctx, []string{"joinserve", "-s", s.Addr(), "--server-name", "tunnel.example.com", "-n", "app.example.com", "--state", t.TempDir(), "-t", "127.0.0.1:80", "-f", a.Fingerprint()}, &out)
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("got %v", err)
	}
	if len(m.Invites()) != 1 {
		t.Fatalf("invites %d", len(m.Invites()))
	}
	if !strings.Contains(out.String(), "join request submitted") {
		t.Fatal(out.String())
	}
}

package main

import (
	"bufio"
	"bytes"
	"crypto/sha256"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestBearerAuthCLI(t *testing.T) {
	for _, command := range []string{"serve", "joinserve"} {
		base := []string{command, "-s", "tunnel.example.com", "-n", "app.example.com", "-t", "127.0.0.1:8080"}
		c, err := parse(append(append([]string{}, base...), "--bearerauth", "--bearerauth=", "--bearerauth=generate", "--bearerauth=other"))
		if err != nil {
			t.Fatal(err)
		}
		if !c.bearerAuthEnabled || strings.Join(c.bearerAuth, ",") != ",,generate,other" {
			t.Fatalf("tokens: %q", c.bearerAuth)
		}
		for _, flags := range [][]string{
			{"--bearerauth=bad token"}, {"--bearerauth=bad\ttoken"}, {"--bearerauth=bad,token"},
			{"--bearerauth=bad=token"}, {"--bearerauth=="}, {"--bearerauth=good", "--bearerauth=bad:token"},
			{"--bearerauth", "--mode=raw"},
			{"--bearerauth", "--basicauth"}, {"--bearerauth", "--cookieauth"},
			{"--bearerauth", "--clientcertauth=" + strings.Repeat("a", 64)}, {"--bearerauth", "--clientcertauth-ca=ca.pem"},
		} {
			if _, err := parse(append(append([]string{}, base...), flags...)); err == nil {
				t.Fatalf("accepted %q", flags)
			}
		}
	}
	if _, err := parse([]string{"join", "-s", "example.com", "-n", "app.example.com", "--bearerauth"}); err == nil {
		t.Fatal("join accepted authentication")
	}
}

func TestBearerAuthHelp(t *testing.T) {
	var c config
	cmd := newCommand(&c, func(config) error { return nil })
	var out bytes.Buffer
	cmd.SetOut(&out)
	cmd.SetArgs([]string{"serve", "--help"})
	if err := cmd.Execute(); err != nil {
		t.Fatal(err)
	}
	if strings.ContainsRune(out.String(), '\x00') || !strings.Contains(out.String(), "--bearerauth") {
		t.Fatal("invalid help output")
	}
}

func TestPrepareBearerAuth(t *testing.T) {
	var out bytes.Buffer
	auth, err := prepareBearerAuth(config{mode: "http", bearerAuthEnabled: true, bearerAuth: []string{"", "", "supplied-secret"}}, &out)
	if err != nil {
		t.Fatal(err)
	}
	if len(auth) != 3 || strings.Contains(out.String(), "supplied-secret") || !strings.Contains(out.String(), "plain HTTP exposes tokens") {
		t.Fatalf("preparation: %s", out.String())
	}
	var tokens []string
	for _, line := range strings.Split(out.String(), "\n") {
		if token, ok := strings.CutPrefix(line, "Token: "); ok {
			tokens = append(tokens, token)
		}
	}
	if len(tokens) != 2 || tokens[0] == tokens[1] {
		t.Fatalf("generated: %q", tokens)
	}
	for i, token := range tokens {
		if len(token) != 43 || !validBearerToken(token) || sha256.Sum256([]byte(token)) != auth[i] {
			t.Fatal("invalid generated token")
		}
	}
	if _, err := prepareBearerAuth(config{bearerAuthEnabled: true, bearerAuth: []string{"bad token"}}, io.Discard); err == nil {
		t.Fatal("accepted invalid token")
	}
	if _, err := prepareBearerAuth(config{bearerAuthEnabled: true}, failingBearerWriter{}); err == nil {
		t.Fatal("ignored output error")
	}
	auth, err = prepareBearerAuth(config{}, io.Discard)
	if err != nil || len(auth) != 0 {
		t.Fatal("authentication enabled without flag")
	}
}

func TestBearerAuthenticatedWebSocket(t *testing.T) {
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "" {
			t.Error("token reached WebSocket backend")
		}
		conn, rw, err := w.(http.Hijacker).Hijack()
		if err != nil {
			return
		}
		defer func() { _ = conn.Close() }()
		_, _ = rw.WriteString("HTTP/1.1 101 Switching Protocols\r\nConnection: Upgrade\r\nUpgrade: websocket\r\n\r\n")
		_ = rw.Flush()
		_, _ = io.Copy(conn, rw)
	}))
	defer backend.Close()
	proxy, transport := newHTTPProxy([]string{backend.Listener.Addr().String()}, time.Second)
	defer transport.CloseIdleConnections()
	auth, err := prepareBearerAuth(config{bearerAuthEnabled: true, bearerAuth: []string{"secret"}}, io.Discard)
	if err != nil {
		t.Fatal(err)
	}
	front := httptest.NewServer(auth.wrap(proxy))
	defer front.Close()
	for _, token := range []string{"wrong", "secret"} {
		conn, err := net.Dial("tcp", front.Listener.Addr().String())
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = conn.Close() }()
		_ = conn.SetDeadline(time.Now().Add(3 * time.Second))
		_, err = io.WriteString(conn, "GET / HTTP/1.1\r\nHost: app.example.com\r\nAuthorization: Bearer "+token+"\r\nConnection: Upgrade\r\nUpgrade: websocket\r\n\r\n")
		if err != nil {
			t.Fatal(err)
		}
		reader := bufio.NewReader(conn)
		resp, err := http.ReadResponse(reader, nil)
		if err != nil {
			t.Fatal(err)
		}
		if token == "wrong" {
			_ = resp.Body.Close()
			_ = conn.Close()
			if resp.StatusCode != http.StatusUnauthorized {
				t.Fatal("unauthorized upgrade accepted")
			}
			continue
		}
		if resp.StatusCode != http.StatusSwitchingProtocols {
			t.Fatalf("upgrade status %d", resp.StatusCode)
		}
		if _, err := conn.Write([]byte("echo")); err != nil {
			t.Fatal(err)
		}
		got := make([]byte, 4)
		if _, err := io.ReadFull(reader, got); err != nil || string(got) != "echo" {
			t.Fatalf("echo %q: %v", got, err)
		}
		_ = conn.Close()
		_ = resp.Body.Close()
	}
}

type failingBearerWriter struct{}

func (failingBearerWriter) Write([]byte) (int, error) { return 0, errors.New("output failed") }

func TestBearerAuthRequests(t *testing.T) {
	auth, err := prepareBearerAuth(config{bearerAuthEnabled: true, bearerAuth: []string{"first", "second", "a._~+/-=="}}, io.Discard)
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		headers []string
		allowed bool
	}{
		{nil, false}, {[]string{""}, false}, {[]string{"Bearer"}, false}, {[]string{"Bearer "}, false},
		{[]string{"Basic first"}, false}, {[]string{"Bearer wrong"}, false}, {[]string{"Bearer FIRST"}, false},
		{[]string{"Bearer first "}, false}, {[]string{"Bearer\tfirst"}, false}, {[]string{"Bearer first,second"}, false},
		{[]string{"Bearer first", "Bearer second"}, false}, {[]string{"Bearer first", ""}, false},
		{[]string{"Bearer first"}, true}, {[]string{"bEaReR second"}, true}, {[]string{"Bearer   first"}, true},
		{[]string{"Bearer a._~+/-=="}, true},
	} {
		for _, upgrade := range []bool{false, true} {
			called := false
			handler := auth.wrap(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				called = true
				if len(r.Header.Values("Authorization")) != 0 {
					t.Error("token reached backend")
				}
				if upgrade && r.Header.Get("Upgrade") != "websocket" {
					t.Error("upgrade lost")
				}
				w.WriteHeader(http.StatusNoContent)
			}))
			r := httptest.NewRequest("GET", "/", nil)
			for _, header := range tc.headers {
				r.Header.Add("Authorization", header)
			}
			if upgrade {
				r.Header.Set("Connection", "Upgrade")
				r.Header.Set("Upgrade", "websocket")
			}
			w := httptest.NewRecorder()
			handler.ServeHTTP(w, r)
			want := http.StatusUnauthorized
			if tc.allowed {
				want = http.StatusNoContent
			}
			if w.Code != want || called != tc.allowed {
				t.Fatalf("headers %q: status %d", tc.headers, w.Code)
			}
			if !tc.allowed && (w.Header().Get("WWW-Authenticate") != `Bearer realm="tunnelproxy"` || w.Header().Get("Cache-Control") != "no-store") {
				t.Fatal("missing challenge")
			}
			if len(tc.headers) > 0 && r.Header.Get("Authorization") != tc.headers[0] {
				t.Fatal("mutated original request")
			}
		}
	}
}

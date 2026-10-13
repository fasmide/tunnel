package main

import (
	"context"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/fasmide/tunnel"
	"github.com/fasmide/tunnel/internal/server"
	"github.com/fasmide/tunnel/internal/transportpki"
)

func TestFilesThroughTunnel(t *testing.T) {
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, "hello.txt"), []byte("tunneled file"), 0600); err != nil {
		t.Fatal(err)
	}
	files, closeFiles, err := newFileHandler(root, false, false)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = closeFiles() }()
	a, err := transportpki.Open(tunnel.MemoryStorage(), "tunnel.example.com", time.Now())
	if err != nil {
		t.Fatal(err)
	}
	m := server.NewManager()
	s, err := server.Listen("127.0.0.1:0", a.Config(), m)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = s.Close() }()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	store := tunnel.MemoryStorage()
	if _, err := tunnel.BootstrapTrust(ctx, s.Addr(), tunnel.TrustRequest{Storage: store, ServerName: "tunnel.example.com", Fingerprint: a.Fingerprint()}); err != nil {
		t.Fatal(err)
	}
	trust, err := tunnel.LoadTransportTLS(store, s.Addr(), "tunnel.example.com")
	if err != nil {
		t.Fatal(err)
	}
	creds, err := tunnel.RequestJoin(ctx, s.Addr(), tunnel.JoinRequest{Storage: store, Routes: []string{"files.example.com"}, TLSConfig: trust})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := m.SetRoutes(creds.PublicKey(), []string{"files.example.com"}); err != nil {
		t.Fatal(err)
	}
	client, err := tunnel.Dial(ctx, s.Addr(), tunnel.WithCredentials(creds), tunnel.WithTLSConfig(trust))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = client.Close() }()
	l, err := client.ListenHTTP(ctx, "files.example.com")
	if err != nil {
		t.Fatal(err)
	}
	serving, stop := context.WithCancel(ctx)
	defer stop()
	done := make(chan error, 1)
	go func() {
		done <- serveClientWithHandler(serving, config{command: "file-serve", name: "files.example.com", root: root, mode: "http", basicAuthEnabled: true, basicAuth: []string{"user:password"}, drainTimeout: time.Second}, client, l, nil, files, io.Discard)
	}()
	edge, err := s.ListenHTTP("127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	transport := &http.Transport{}
	defer transport.CloseIdleConnections()
	httpClient := &http.Client{Transport: transport, Timeout: 5 * time.Second}
	for _, authenticated := range []bool{false, true} {
		r, err := http.NewRequestWithContext(ctx, "GET", "http://"+edge.Addr().String()+"/hello.txt", nil)
		if err != nil {
			t.Fatal(err)
		}
		r.Host = "files.example.com"
		if authenticated {
			r.SetBasicAuth("user", "password")
		}
		response, err := httpClient.Do(r)
		if err != nil {
			t.Fatal(err)
		}
		body, err := io.ReadAll(response.Body)
		_ = response.Body.Close()
		if err != nil {
			t.Fatal(err)
		}
		if !authenticated && response.StatusCode != 401 || authenticated && (response.StatusCode != 200 || string(body) != "tunneled file") {
			t.Fatalf("authenticated=%v: %d %s", authenticated, response.StatusCode, body)
		}
	}
	stop()
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-ctx.Done():
		t.Fatal("file server did not drain")
	}
}

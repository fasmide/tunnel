package tunnel

import (
	"bufio"
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"testing"
	"time"

	"tunnel/internal/server"
)

func BenchmarkE2ETLSRequest(b *testing.B) {
	s, m, trust := runningServer(b)
	creds := identity(b)
	grant(b, m, creds, "alice.example.com")
	client := connected(b, s, trust, creds)
	raw := listenRaw(b, client, "alice.example.com")
	cert, roots := applicationCertificate(b)
	serveApplication(b, raw, cert, "bench")
	edge, err := s.ListenTLS("127.0.0.1:0")
	if err != nil {
		b.Fatal(err)
	}
	b.Cleanup(func() { _ = edge.Close() })
	transport := &http.Transport{
		TLSClientConfig:   &tls.Config{RootCAs: roots},
		DisableKeepAlives: true,
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			return (&net.Dialer{}).DialContext(ctx, "tcp", edge.Addr().String())
		},
	}
	defer transport.CloseIdleConnections()
	clientHTTP := &http.Client{Transport: transport, Timeout: 5 * time.Second}
	payload := "benchmark payload"
	url := "https://foo.alice.example.com/echo"
	b.ReportAllocs()
	b.ResetTimer()
	for b.Loop() {
		resp, err := clientHTTP.Post(url, "application/octet-stream", strings.NewReader(payload))
		if err != nil {
			b.Fatal(err)
		}
		body, err := io.ReadAll(resp.Body)
		_ = resp.Body.Close()
		if err != nil {
			b.Fatal(err)
		}
		if string(body) != "bench:"+payload {
			b.Fatalf("unexpected body %q", body)
		}
	}
}

func BenchmarkE2ETLSKeepAliveRequest(b *testing.B) {
	s, m, trust := runningServer(b)
	creds := identity(b)
	grant(b, m, creds, "alice.example.com")
	client := connected(b, s, trust, creds)
	raw := listenRaw(b, client, "alice.example.com")
	cert, roots := applicationCertificate(b)
	serveApplication(b, raw, cert, "bench")
	edge, err := s.ListenTLS("127.0.0.1:0")
	if err != nil {
		b.Fatal(err)
	}
	b.Cleanup(func() { _ = edge.Close() })
	transport := &http.Transport{
		TLSClientConfig: &tls.Config{RootCAs: roots},
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			return (&net.Dialer{}).DialContext(ctx, "tcp", edge.Addr().String())
		},
		MaxIdleConns:        1,
		MaxIdleConnsPerHost: 1,
		MaxConnsPerHost:     1,
	}
	defer transport.CloseIdleConnections()
	clientHTTP := &http.Client{Transport: transport, Timeout: 5 * time.Second}
	payload := "benchmark payload"
	url := "https://foo.alice.example.com/echo"
	resp, err := clientHTTP.Post(url, "application/octet-stream", strings.NewReader(payload))
	if err != nil {
		b.Fatal(err)
	}
	if _, err := io.Copy(io.Discard, resp.Body); err != nil {
		b.Fatal(err)
	}
	_ = resp.Body.Close()
	b.ReportAllocs()
	b.ResetTimer()
	for b.Loop() {
		resp, err := clientHTTP.Post(url, "application/octet-stream", strings.NewReader(payload))
		if err != nil {
			b.Fatal(err)
		}
		body, err := io.ReadAll(resp.Body)
		_ = resp.Body.Close()
		if err != nil {
			b.Fatal(err)
		}
		if string(body) != "bench:"+payload {
			b.Fatalf("unexpected body %q", body)
		}
	}
}

func BenchmarkE2EHTTPPlainRequest(b *testing.B) {
	s, m, trust := runningServer(b)
	creds := identity(b)
	grant(b, m, creds, "alice.example.com")
	client := connected(b, s, trust, creds)
	listener, err := client.ListenHTTP(context.Background(), "alice.example.com")
	if err != nil {
		b.Fatal(err)
	}
	app := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.Copy(io.Discard, r.Body)
		_ = r.Body.Close()
		w.Header().Set("Connection", "close")
		_, _ = io.WriteString(w, "ok")
	})}
	appDone := make(chan error, 1)
	go func() { appDone <- app.Serve(listener) }()
	edge, err := s.ListenHTTP("127.0.0.1:0")
	if err != nil {
		b.Fatal(err)
	}
	b.Cleanup(func() {
		_ = edge.Close()
		_ = app.Close()
		_ = listener.Close()
	})
	request := "POST /echo HTTP/1.1\r\nHost: foo.alice.example.com\r\nContent-Length: 17\r\n\r\nbenchmark payload"
	b.ReportAllocs()
	b.ResetTimer()
	for b.Loop() {
		conn := publicHTTP(b, edge)
		if _, err := io.WriteString(conn, request); err != nil {
			b.Fatal(err)
		}
		resp, err := http.ReadResponse(bufio.NewReader(conn), nil)
		if err != nil {
			b.Fatal(err)
		}
		body, err := io.ReadAll(resp.Body)
		_ = resp.Body.Close()
		if err != nil {
			b.Fatal(err)
		}
		if string(body) != "ok" {
			b.Fatalf("unexpected body %q", body)
		}
		_ = conn.Close()
	}
	b.StopTimer()
	_ = app.Close()
	_ = listener.Close()
	select {
	case err := <-appDone:
		if err != nil && !errors.Is(err, http.ErrServerClosed) && !strings.Contains(err.Error(), "closed") {
			b.Fatal(err)
		}
	case <-time.After(3 * time.Second):
		b.Fatal("plain app shutdown timeout")
	}
}

func BenchmarkE2ERawStreamRoundTrip(b *testing.B) {
	s, m, trust := runningServer(b)
	creds := identity(b)
	grant(b, m, creds, "alice.example.com")
	client := connected(b, s, trust, creds)
	listener := listenRaw(b, client, "alice.example.com")
	accepted := make(chan net.Conn, 1)
	errCh := make(chan error, 1)
	go func() {
		conn, err := listener.Accept()
		if err != nil {
			errCh <- err
			return
		}
		accepted <- conn
	}()
	peer, done := routePublicBench(b, s, "alice.example.com", nil)
	defer func() { _ = peer.Close() }()
	var app net.Conn
	select {
	case app = <-accepted:
	case err := <-errCh:
		b.Fatal(err)
	case <-time.After(3 * time.Second):
		b.Fatal("accept timeout")
	}
	defer func() { _ = app.Close() }()
	payload := []byte("ping over raw")
	buf := make([]byte, len(payload))
	b.ReportAllocs()
	b.ResetTimer()
	for b.Loop() {
		if _, err := peer.Write(payload); err != nil {
			b.Fatal(err)
		}
		if _, err := io.ReadFull(app, buf); err != nil {
			b.Fatal(err)
		}
		if string(buf) != string(payload) {
			b.Fatalf("app got %q", buf)
		}
		if _, err := app.Write(buf); err != nil {
			b.Fatal(err)
		}
		if _, err := io.ReadFull(peer, buf); err != nil {
			b.Fatal(err)
		}
		if string(buf) != string(payload) {
			b.Fatalf("peer got %q", buf)
		}
	}
	b.StopTimer()
	_ = peer.Close()
	_ = app.Close()
	select {
	case err := <-done:
		if err != nil {
			b.Fatal(err)
		}
	case <-time.After(3 * time.Second):
		b.Fatal("forwarder shutdown timeout")
	}
}

func BenchmarkE2EJoinApproveDial(b *testing.B) {
	ctx := context.Background()
	b.ReportAllocs()
	for b.Loop() {
		b.StopTimer()
		s, m, trust := runningServer(b)
		storage := FileStorage(b.TempDir())
		route := fmt.Sprintf("bench-%d.example.com", time.Now().UnixNano())
		b.StartTimer()
		creds, err := RequestJoin(ctx, s.Addr(), JoinRequest{Storage: storage, Routes: []string{route}, TLSConfig: trust})
		if err != nil {
			b.Fatal(err)
		}
		invites := m.Invites()
		if len(invites) != 1 {
			b.Fatalf("invites %d", len(invites))
		}
		invite := invites[0]
		if invite.Identity != creds.Identity() {
			b.Fatalf("invite identity %s want %s", invite.Identity, creds.Identity())
		}
		if _, err := m.DecideInvite(invite.ID, true); err != nil {
			b.Fatal(err)
		}
		client, err := Dial(ctx, s.Addr(), WithCredentials(creds), WithTLSConfig(trust))
		if err != nil {
			b.Fatal(err)
		}
		if err := client.Close(); err != nil {
			b.Fatal(err)
		}
		b.StopTimer()
		_ = s.Close()
		b.StartTimer()
	}
}

func BenchmarkDialApproved(b *testing.B) {
	s, m, trust := runningServer(b)
	creds := identity(b)
	grant(b, m, creds, "alice.example.com")
	ctx := context.Background()
	b.ReportAllocs()
	b.ResetTimer()
	for b.Loop() {
		client, err := Dial(ctx, s.Addr(), WithCredentials(creds), WithTLSConfig(trust))
		if err != nil {
			b.Fatal(err)
		}
		if err := client.Close(); err != nil {
			b.Fatal(err)
		}
	}
}

func routePublicBench(t testing.TB, s *server.Server, host string, prefix []byte) (*net.TCPConn, <-chan error) {
	t.Helper()
	edge, err := net.ListenTCP("tcp", &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	peer, err := net.DialTCP("tcp", nil, edge.Addr().(*net.TCPAddr))
	if err != nil {
		t.Fatal(err)
	}
	public, err := edge.AcceptTCP()
	_ = edge.Close()
	if err != nil {
		t.Fatal(err)
	}
	if err := peer.SetDeadline(time.Now().Add(30 * time.Second)); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = peer.Close() })
	done := make(chan error, 1)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	go func() { defer cancel(); done <- s.Forward(ctx, public, host, prefix) }()
	return peer, done
}

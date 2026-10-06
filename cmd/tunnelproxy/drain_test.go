package main

import (
	"bufio"
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"testing"
	"time"

	"tunnel"
	"tunnel/internal/server"
	"tunnel/internal/transportpki"
)

func TestForwardActiveDrainAndDeadline(t *testing.T) {
	for _, timeout := range []bool{false, true} {
		t.Run(map[bool]string{false: "finishes_allocated_request", true: "aborts_at_deadline"}[timeout], func(t *testing.T) {
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
			ctx, cancelSetup := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancelSetup()
			store := tunnel.MemoryStorage()
			_, err = tunnel.BootstrapTrust(ctx, s.Addr(), tunnel.TrustRequest{Storage: store, ServerName: "tunnel.example.com", Fingerprint: a.Fingerprint()})
			if err != nil {
				t.Fatal(err)
			}
			trust, err := tunnel.LoadTransportTLS(store, s.Addr(), "tunnel.example.com")
			if err != nil {
				t.Fatal(err)
			}
			creds, err := tunnel.RequestJoin(ctx, s.Addr(), tunnel.JoinRequest{Storage: store, Routes: []string{"app.example.com"}, TLSConfig: trust})
			if err != nil {
				t.Fatal(err)
			}
			if _, err := m.SetRoutes(creds.PublicKey(), []string{"app.example.com"}); err != nil {
				t.Fatal(err)
			}
			c, err := tunnel.Dial(ctx, s.Addr(), tunnel.WithCredentials(creds), tunnel.WithTLSConfig(trust))
			if err != nil {
				t.Fatal(err)
			}
			defer func() { _ = c.Close() }()
			l, err := c.ListenHTTP(ctx, "app.example.com")
			if err != nil {
				t.Fatal(err)
			}
			backend, err := net.Listen("tcp", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			defer func() { _ = backend.Close() }()
			localAccepted := make(chan net.Conn, 1)
			go func() {
				conn, err := backend.Accept()
				if err == nil {
					localAccepted <- conn
				}
			}()
			serving, cancel := context.WithCancel(context.Background())
			defer cancel()
			duration := 2 * time.Second
			if timeout {
				duration = 75 * time.Millisecond
			}
			done := make(chan error, 1)
			go func() {
				done <- forwardHTTP(serving, c, l, []string{backend.Addr().String()}, time.Second, duration, true, io.Discard)
			}()
			edge, err := s.ListenHTTP("127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			peer, err := net.Dial("tcp", edge.Addr().String())
			if err != nil {
				t.Fatal(err)
			}
			defer func() { _ = peer.Close() }()
			_ = peer.SetDeadline(time.Now().Add(4 * time.Second))
			if _, err := io.WriteString(peer, "GET / HTTP/1.1\r\nHost: app.example.com\r\n\r\n"); err != nil {
				t.Fatal(err)
			}
			var local net.Conn
			select {
			case local = <-localAccepted:
			case <-time.After(3 * time.Second):
				t.Fatal("no backend dial")
			}
			defer func() { _ = local.Close() }()
			_ = local.SetDeadline(time.Now().Add(3 * time.Second))
			request, err := http.ReadRequest(bufio.NewReader(local))
			if err != nil {
				t.Fatal(err)
			}
			_ = request.Body.Close()
			cancel()
			wait(t, func() bool { _, ok := m.Select("app.example.com", "http"); return !ok })
			if timeout {
				select {
				case err := <-done:
					if !errors.Is(err, context.DeadlineExceeded) {
						t.Fatalf("deadline: %v", err)
					}
				case <-time.After(3 * time.Second):
					t.Fatal("stalled drain")
				}
				// The stalled local read and public connection must be released too.
				if _, err := local.Read(make([]byte, 1)); err == nil {
					t.Fatal("backend not closed")
				}
			} else {
				select {
				case err := <-done:
					t.Fatalf("premature drain: %v", err)
				default:
				}
				if _, err := io.WriteString(local, "HTTP/1.1 200 OK\r\nContent-Length: 4\r\nConnection: close\r\n\r\ndone"); err != nil {
					t.Fatal(err)
				}
				_ = local.Close()
				resp, err := http.ReadResponse(bufio.NewReader(peer), nil)
				if err != nil {
					t.Fatal(err)
				}
				body, err := io.ReadAll(resp.Body)
				_ = resp.Body.Close()
				if err != nil || string(body) != "done" {
					t.Fatalf("response %s %v", body, err)
				}
				select {
				case err := <-done:
					if err != nil {
						t.Fatal(err)
					}
				case <-time.After(3 * time.Second):
					t.Fatal("drain stalled")
				}
			}
		})
	}
}

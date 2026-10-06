package tunnel

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"sync/atomic"
	"testing"
	"time"

	"github.com/fasmide/tunnel/internal/server"
)

func publicHTTP(t testing.TB, edge *server.TLSEdge) net.Conn {
	t.Helper()
	conn, err := net.Dial("tcp", edge.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	if err := conn.SetDeadline(time.Now().Add(3 * time.Second)); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	return conn
}
func TestHTTPDefaultRedirectAndValidation(t *testing.T) {
	s, _, _ := runningServer(t)
	edge, err := s.ListenHTTP("127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	conn := publicHTTP(t, edge)
	if _, err := fmt.Fprint(conn, "GET /path?q=one%20two HTTP/1.1\r\nHost: Alice.Example.com.:80\r\n\r\n"); err != nil {
		t.Fatal(err)
	}
	response, err := http.ReadResponse(bufio.NewReader(conn), nil)
	if err != nil {
		t.Fatal(err)
	}
	if response.StatusCode != http.StatusPermanentRedirect || response.Header.Get("Location") != "https://alice.example.com/path?q=one%20two" || !response.Close {
		t.Fatalf("redirect: %+v", response)
	}
	if err := response.Body.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := conn.Read(make([]byte, 1)); err == nil {
		t.Fatal("redirect kept alive")
	}
	for _, request := range []string{
		"GET / HTTP/1.1\r\nHost: a.example\r\nHost: b.example\r\n\r\n",
		"POST / HTTP/1.1\r\nHost: a.example\r\nContent-Length: 0\r\nTransfer-Encoding: chunked\r\n\r\n",
		"GET //evil.example/ HTTP/1.1\r\nHost: a.example\r\n\r\n",
		"GET http://evil.example/ HTTP/1.1\r\nHost: a.example\r\n\r\n",
		"CONNECT a.example:443 HTTP/1.1\r\nHost: a.example\r\n\r\n",
		"GET / HTTP/1.1\r\nHost: a.example\r\nConnection: Upgrade\r\nUpgrade: websocket\r\n\r\n",
		"GET / HTTP/1.0\r\n\r\n",
		"GET / HTTP/1.1\r\nHost: a.example:99999\r\n\r\n",
	} {
		conn := publicHTTP(t, edge)
		if _, err := io.WriteString(conn, request); err != nil {
			t.Fatal(err)
		}
		response, err := http.ReadResponse(bufio.NewReader(conn), nil)
		if err != nil {
			t.Fatal(err)
		}
		if response.StatusCode != http.StatusBadRequest {
			t.Fatalf("invalid accepted: %q status %d", request, response.StatusCode)
		}
		if err := response.Body.Close(); err != nil {
			t.Fatal(err)
		}
	}
}
func TestHTTPPipeliningNeverForwardsSecondRequest(t *testing.T) {
	for _, chunked := range []bool{false, true} {
		t.Run(fmt.Sprint(chunked), func(t *testing.T) {
			s, m, trust := runningServer(t)
			creds := identity(t)
			grant(t, m, creds, "alice.example.com", "bob.example.com")
			c := connected(t, s, trust, creds)
			l, err := c.ListenHTTP(context.Background(), "alice.example.com")
			if err != nil {
				t.Fatal(err)
			}
			if _, err := c.ListenRaw(context.Background(), "alice.example.com"); err != nil {
				t.Fatal("HTTP/TLS coexistence:", err)
			}
			if l.Addr().String() != "alice.example.com:80" {
				t.Fatal("HTTP local address")
			}
			edge, err := s.ListenHTTP("127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			body := "Content-Length: 5\r\n\r\nhello"
			if chunked {
				body = "Transfer-Encoding: chunked\r\nTrailer: X-Test\r\n\r\n5;tag=yes\r\nhello\r\n0\r\nX-Test: value\r\n\r\n"
			}
			first := "POST /one HTTP/1.1\r\nHost: foo.alice.example.com\r\n" + body
			second := "GET /two HTTP/1.1\r\nHost: bob.example.com\r\n\r\n"
			peer := publicHTTP(t, edge)
			if _, err := io.WriteString(peer, first+second); err != nil {
				t.Fatal(err)
			}
			conn := accept(t, l)
			got, err := io.ReadAll(conn)
			if err != nil {
				t.Fatal(err)
			}
			if string(got) != first {
				t.Fatalf("forwarded unexpected bytes: %q", got)
			}
			if _, err := io.WriteString(conn, "HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: keep-alive\r\n\r\nok"); err != nil {
				t.Fatal(err)
			}
			// Backend deliberately stays open: edge must stop at the final response.
			response, err := http.ReadResponse(bufio.NewReader(peer), nil)
			if err != nil {
				t.Fatal(err)
			}
			data, err := io.ReadAll(response.Body)
			if closeErr := response.Body.Close(); closeErr != nil {
				t.Fatal(closeErr)
			}
			if err != nil || string(data) != "ok" {
				t.Fatalf("response: %q %v", data, err)
			}
			if _, err := peer.Read(make([]byte, 1)); err == nil {
				t.Fatal("one-shot public connection kept alive")
			}
			_ = conn.Close()
		})
	}
}
func TestHTTPServeAndExpectContinue(t *testing.T) {
	s, m, trust := runningServer(t)
	creds := identity(t)
	grant(t, m, creds, "alice.example.com")
	c := connected(t, s, trust, creds)
	l, err := c.ListenHTTP(context.Background(), "alice.example.com")
	if err != nil {
		t.Fatal(err)
	}
	var count atomic.Int32
	app := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		count.Add(1)
		body, err := io.ReadAll(r.Body)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		if _, err := w.Write(body); err != nil {
			return
		}
	})}
	go func() {
		if err := app.Serve(l); err != nil && !errors.Is(err, http.ErrServerClosed) {
			panic(err)
		}
	}()
	t.Cleanup(func() {
		if err := app.Close(); err != nil {
			t.Error(err)
		}
	})
	edge, err := s.ListenHTTP("127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	peer := publicHTTP(t, edge)
	if _, err := io.WriteString(peer, "POST / HTTP/1.1\r\nHost: alice.example.com\r\nExpect: 100-continue\r\nContent-Length: 5\r\n\r\n"); err != nil {
		t.Fatal(err)
	}
	reader := bufio.NewReader(peer)
	interim, err := http.ReadResponse(reader, nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := interim.Body.Close(); err != nil {
		t.Fatal(err)
	}
	if interim.StatusCode != http.StatusContinue {
		t.Fatalf("continue: %v", interim)
	}
	if _, err := io.WriteString(peer, "helloGET / HTTP/1.1\r\nHost: other.example.com\r\n\r\n"); err != nil {
		t.Fatal(err)
	}
	response, err := http.ReadResponse(reader, nil)
	if err != nil {
		t.Fatal(err)
	}
	body, err := io.ReadAll(response.Body)
	if closeErr := response.Body.Close(); closeErr != nil {
		t.Fatal(closeErr)
	}
	if err != nil || string(body) != "hello" {
		t.Fatalf("response %q %v", body, err)
	}
	if count.Load() != 1 {
		t.Fatal("application served more than one request")
	}
}
func TestHTTPChunkedResponseAndHead(t *testing.T) {
	for _, head := range []bool{false, true} {
		t.Run(fmt.Sprint(head), func(t *testing.T) {
			s, m, trust := runningServer(t)
			creds := identity(t)
			grant(t, m, creds, "alice.example.com")
			c := connected(t, s, trust, creds)
			l, err := c.ListenHTTP(context.Background(), "alice.example.com")
			if err != nil {
				t.Fatal(err)
			}
			edge, err := s.ListenHTTP("127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			peer := publicHTTP(t, edge)
			method := "GET"
			if head {
				method = "HEAD"
			}
			if _, err := fmt.Fprintf(peer, "%s / HTTP/1.1\r\nHost: alice.example.com\r\n\r\n", method); err != nil {
				t.Fatal(err)
			}
			backend := accept(t, l)
			if _, err := io.ReadAll(backend); err != nil {
				t.Fatal(err)
			}
			reply := "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nTrailer: X-Test\r\n\r\n2\r\nok\r\n0\r\nX-Test: done\r\n\r\n"
			if head {
				reply = "HTTP/1.1 200 OK\r\nContent-Length: 999\r\n\r\n"
			}
			if _, err := io.WriteString(backend, reply); err != nil {
				t.Fatal(err)
			}
			response, err := http.ReadResponse(bufio.NewReader(peer), &http.Request{Method: method})
			if err != nil {
				t.Fatal(err)
			}
			body, err := io.ReadAll(response.Body)
			if closeErr := response.Body.Close(); closeErr != nil {
				t.Fatal(closeErr)
			}
			if err != nil {
				t.Fatal(err)
			}
			if !head && string(body) != "ok" {
				t.Fatal("chunked response altered")
			}
			if _, err := peer.Read(make([]byte, 1)); err == nil {
				t.Fatal("did not close at response boundary")
			}
			_ = backend.Close()
		})
	}
}
func TestHTTPShutdownClosesPartialHeader(t *testing.T) {
	s, _, _ := runningServer(t)
	edge, err := s.ListenHTTP("127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	conn := publicHTTP(t, edge)
	if _, err := io.WriteString(conn, "GET / HTTP/1.1\r\nHost:"); err != nil {
		t.Fatal(err)
	}
	done := make(chan struct{})
	go func() {
		_ = s.Close()
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("shutdown waited on incomplete HTTP header")
	}
}

func TestHTTPOfflineCarveoutRedirect(t *testing.T) {
	s, m, trust := runningServer(t)
	parent := identity(t)
	child := identity(t)
	grant(t, m, parent, "alice.example.com")
	grant(t, m, child, "api.alice.example.com")
	c := connected(t, s, trust, parent)
	if _, err := c.ListenHTTP(context.Background(), "alice.example.com"); err != nil {
		t.Fatal(err)
	}
	edge, err := s.ListenHTTP("127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	peer := publicHTTP(t, edge)
	if _, err := io.WriteString(peer, "GET / HTTP/1.1\r\nHost: api.alice.example.com\r\n\r\n"); err != nil {
		t.Fatal(err)
	}
	response, err := http.ReadResponse(bufio.NewReader(peer), nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := response.Body.Close(); err != nil {
		t.Fatal(err)
	}
	if response.StatusCode != http.StatusPermanentRedirect {
		t.Fatal("offline child leaked to ancestor HTTP pool")
	}
}

package main

import (
	"bufio"
	"context"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestHTTPTranslationHostAndTrustedForwarding(t *testing.T) {
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.ProtoMajor != 1 || r.ProtoMinor != 1 {
			t.Errorf("backend protocol %s", r.Proto)
		}
		if r.Host != "public.example.com" || r.URL.RequestURI() != "/path?q=1" {
			t.Errorf("host/url %s %s", r.Host, r.URL)
		}
		if r.Header.Get("Forwarded") != "" || r.Header.Get("X-Forwarded-For") != "192.0.2.1" || r.Header.Get("X-Forwarded-Host") != "public.example.com" || r.Header.Get("X-Forwarded-Proto") != "https" {
			t.Errorf("forwarding headers %v", r.Header)
		}
		if r.Header.Get("X-Hop") != "" {
			t.Error("hop-by-hop header forwarded")
		}
		body, err := io.ReadAll(r.Body)
		if err != nil || string(body) != "payload" {
			t.Errorf("body %s %v", body, err)
		}
		w.Header().Set("Trailer", "X-End")
		_, _ = io.WriteString(w, "translated")
		w.Header().Set("X-End", "done")
	}))
	defer backend.Close()
	proxy, transport := newHTTPProxy([]string{backend.Listener.Addr().String()}, time.Second)
	defer transport.CloseIdleConnections()
	request := httptest.NewRequest(http.MethodPost, "https://public.example.com/path?q=1", strings.NewReader("payload"))
	request.RemoteAddr = "192.0.2.1:1234"
	request.Header.Set("Forwarded", "for=spoof")
	request.Header.Set("X-Forwarded-For", "spoof")
	request.Header.Set("X-Forwarded-Host", "evil")
	request.Header.Set("X-Forwarded-Proto", "http")
	request.Header.Set("Connection", "X-Hop")
	request.Header.Set("X-Hop", "secret")
	result := httptest.NewRecorder()
	proxy.ServeHTTP(result, request)
	response := result.Result()
	defer func() { _ = response.Body.Close() }()
	body, err := io.ReadAll(response.Body)
	if err != nil || string(body) != "translated" || response.Trailer.Get("X-End") != "done" {
		t.Fatalf("response %s %v trailer %v", body, err, response.Trailer)
	}
}

func TestHTTPUpgradeBidirectionalRelay(t *testing.T) {
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Upgrade") != "websocket" {
			http.Error(w, "missing upgrade", http.StatusBadRequest)
			return
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
	front := httptest.NewServer(proxy)
	defer front.Close()
	conn, err := net.Dial("tcp", front.Listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = conn.Close() }()
	_ = conn.SetDeadline(time.Now().Add(3 * time.Second))
	_, err = io.WriteString(conn, "GET / HTTP/1.1\r\nHost: public.example.com\r\nConnection: Upgrade\r\nUpgrade: websocket\r\n\r\n")
	if err != nil {
		t.Fatal(err)
	}
	reader := bufio.NewReader(conn)
	response, err := http.ReadResponse(reader, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = response.Body.Close() }()
	if response.StatusCode != http.StatusSwitchingProtocols {
		t.Fatalf("upgrade %v", response)
	}
	if _, err := conn.Write([]byte("echo")); err != nil {
		t.Fatal(err)
	}
	got := make([]byte, 4)
	if _, err := io.ReadFull(reader, got); err != nil || string(got) != "echo" {
		t.Fatalf("upgrade data %s %v", got, err)
	}
}
func TestHTTPBackendFailureReturns502(t *testing.T) {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	address := l.Addr().String()
	_ = l.Close()
	proxy, transport := newHTTPProxy([]string{address}, time.Second)
	defer transport.CloseIdleConnections()
	result := httptest.NewRecorder()
	proxy.ServeHTTP(result, httptest.NewRequest(http.MethodGet, "http://public.example.com/", nil))
	if result.Code != 502 {
		t.Fatalf("backend failure status %d", result.Code)
	}
	// Dial addresses are pinned; request URL/Host cannot redirect the target.
	_, err = transport.DialContext(context.Background(), "tcp", "attacker.invalid:80")
	if err == nil {
		t.Fatal("unexpected backend connection")
	}
}

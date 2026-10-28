package main

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestHeaderFlags(t *testing.T) {
	base := []string{"serve", "-s", "tunnel.example.net", "-n", "app.example.net", "-t", "127.0.0.1:8080"}
	c, err := parse(append(base, "--header-host", "localhost", "--header-X-Test=first", "--header-x-test=last", "--header-x-empty=", "--header-x-list=a,b"))
	if err != nil {
		t.Fatal(err)
	}
	if c.headers.Get("Host") != "localhost" || c.headers.Get("X-Test") != "last" || c.headers.Get("X-List") != "a,b" {
		t.Fatalf("headers: %v", c.headers)
	}
	if values := c.headers.Values("X-Empty"); len(values) != 1 || values[0] != "" {
		t.Fatalf("empty value not preserved: %v", values)
	}
	for _, flags := range [][]string{
		{"--header-host"}, {"--header-host="}, {"--header-host=bad host"},
		{"--header-=value"}, {"--header-bad:name=value"},
		{"--header-x-test=bad\r\nInjected: yes"}, {"--header-x-test=bad\x00value"},
		{"--header-connection=close"}, {"--header-content-length=123"},
		{"--header-transfer-encoding=chunked"}, {"--header-upgrade=websocket"},
		{"--header-host=localhost", "--mode=raw"}, {"--unrelated=value"},
	} {
		if _, err := parse(append(append([]string{}, base...), flags...)); err == nil {
			t.Errorf("accepted %q", flags)
		}
	}
	for _, command := range []string{"join", "file-serve"} {
		if _, err := parse([]string{command, "-s", "tunnel.example.net", "-n", "app.example.net", "--header-host=localhost"}); err == nil {
			t.Errorf("%s accepted header flag", command)
		}
	}
}

func TestEnforcedHeadersReachBackendAfterAuthentication(t *testing.T) {
	calls := 0
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		if r.Host != "localhost" {
			t.Errorf("Host = %q", r.Host)
		}
		for name, want := range map[string]string{"X-Test": "enforced", "Authorization": "Bearer upstream", "X-Forwarded-Host": "public.example.com", "X-Forwarded-For": "configured"} {
			if values := r.Header.Values(name); len(values) != 1 || values[0] != want {
				t.Errorf("%s = %v, want %q", name, values, want)
			}
		}
		_, _ = io.WriteString(w, "ok")
	}))
	defer backend.Close()
	proxy, transport := newHTTPProxy("tcp", []string{backend.Listener.Addr().String()}, time.Second)
	defer transport.CloseIdleConnections()
	enforceHeaders(proxy, http.Header{"Host": {"localhost"}, "X-Test": {"enforced"}, "Authorization": {"Bearer upstream"}, "X-Forwarded-For": {"configured"}})
	auth, err := parseBasicAuth("user:secret")
	if err != nil {
		t.Fatal(err)
	}
	handler := auth.wrap(proxy)
	for _, authenticated := range []bool{false, true} {
		r := httptest.NewRequest("GET", "https://public.example.com/path", nil)
		r.Header.Add("X-Test", "spoofed")
		r.Header.Add("X-Test", "also-spoofed")
		r.Header.Set("Connection", "X-Test")
		r.Header.Set("X-Forwarded-For", "spoofed")
		if authenticated {
			r.SetBasicAuth("user", "secret")
		}
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, r)
		if authenticated {
			if w.Code != 200 || strings.TrimSpace(w.Body.String()) != "ok" || calls != 1 {
				t.Fatalf("status=%d body=%s calls=%d", w.Code, w.Body, calls)
			}
		} else if w.Code != http.StatusUnauthorized || calls != 0 {
			t.Fatal("header overrides bypassed authentication")
		}
	}
}

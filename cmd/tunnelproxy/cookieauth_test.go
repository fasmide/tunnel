package main

import (
	"bufio"
	"bytes"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/bcrypt"
)

func testCookieAuth(t *testing.T, secure bool) *cookieAuth {
	t.Helper()
	first, err := parseBasicAuth("alice:secret")
	if err != nil {
		t.Fatal(err)
	}
	second, err := parseBasicAuth(":shared")
	if err != nil {
		t.Fatal(err)
	}
	hash, err := bcrypt.GenerateFromPassword([]byte("hashed-secret"), bcrypt.MinCost)
	if err != nil {
		t.Fatal(err)
	}
	third, err := parseBasicAuth("bob:" + string(hash))
	if err != nil {
		t.Fatal(err)
	}
	a, err := newCookieAuth(basicAuthList{first, second, third}, time.Hour, secure)
	if err != nil {
		t.Fatal(err)
	}
	a.now = func() time.Time { return time.Unix(1700000000, 0) }
	return a
}
func cookieFormRequest(a *cookieAuth, path, user, password, returnURL string) *http.Request {
	csrf := a.sign("csrf", "app.example.com", "", "test-nonce", 15*time.Minute)
	form := url.Values{"csrf": {csrf}, "username": {user}, "password": {password}, "return": {returnURL}}
	r := httptest.NewRequest("POST", "https://app.example.com"+path, strings.NewReader(form.Encode()))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	scheme := "http"
	if a.secure {
		scheme = "https"
	}
	r.Header.Set("Origin", scheme+"://app.example.com")
	r.AddCookie(a.cookie(a.csrfName(), csrf, time.Minute))
	return r
}
func TestCookieAuthCLI(t *testing.T) {
	for _, command := range []string{"serve", "joinserve"} {
		base := []string{command, "-s", "tunnel.example.com", "-n", "app.example.com", "-t", "127.0.0.1:8080"}
		c, err := parse(append(append([]string{}, base...), "--cookieauth", "--cookieauth=alice:secret", "--cookieauth=:shared", "--cookieauth-duration=12h"))
		if err != nil || !c.cookieAuthEnabled || len(c.cookieAuth) != 3 || c.cookieAuth[0] != "" || c.cookieAuthDuration != 12*time.Hour {
			t.Fatalf("config %+v %v", c, err)
		}
		for _, flags := range [][]string{{"--cookieauth", "--basicauth"}, {"--cookieauth-duration=1h"}, {"--cookieauth", "--cookieauth-duration=0s"}, {"--cookieauth", "--cookieauth-duration=-1h"}, {"--cookieauth=generate"}, {"--cookieauth=invalid", "--cookieauth=alice:valid"}} {
			if _, err := parse(append(append([]string{}, base...), flags...)); err == nil {
				t.Fatalf("accepted %v", flags)
			}
		}
		c, err = parse(append(append([]string{}, base...), "--cookieauth"))
		if err != nil || c.cookieAuthDuration != 24*time.Hour {
			t.Fatalf("default duration %v %v", c.cookieAuthDuration, err)
		}
	}
	if _, err := parse([]string{"join", "-s", "example.com", "-n", "app.example.com", "--cookieauth"}); err == nil {
		t.Fatal("join accepted cookieauth")
	}
	var out bytes.Buffer
	_, err := prepareBasicAuth(config{cookieAuthEnabled: true, cookieAuth: []string{"alice:secret"}, mode: "acme"}, &out)
	if err != nil || !strings.Contains(out.String(), "--cookieauth='alice:$2") || strings.Contains(out.String(), "secret") {
		t.Fatalf("hint %q %v", out.String(), err)
	}
}
func TestCookieAuthBrowserFlow(t *testing.T) {
	for _, secure := range []bool{true, false} {
		a := testCookieAuth(t, secure)
		called := false
		handler := a.wrap(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			called = true
			if _, err := r.Cookie(a.cookieName()); err == nil {
				t.Error("session leaked")
			}
			if _, err := r.Cookie(a.csrfName()); err == nil {
				t.Error("csrf leaked")
			}
			if c, err := r.Cookie("app"); err != nil || c.Value != "kept" {
				t.Error("app cookie lost")
			}
			w.WriteHeader(204)
		}))
		r := httptest.NewRequest("GET", "https://app.example.com/path?q=1", nil)
		r.Header.Set("Accept", "text/html")
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, r)
		if w.Code != 303 || !strings.HasPrefix(w.Header().Get("Location"), authLoginPath+"?") || called {
			t.Fatalf("redirect %d %v", w.Code, w.Header())
		}
		r = httptest.NewRequest("GET", "https://app.example.com"+w.Header().Get("Location"), nil)
		w = httptest.NewRecorder()
		handler.ServeHTTP(w, r)
		if w.Code != 200 || !strings.Contains(w.Body.String(), "name=\"username\"") || !strings.Contains(w.Body.String(), "name=\"password\"") || w.Header().Get("Content-Security-Policy") == "" {
			t.Fatalf("page %d %s", w.Code, w.Body.String())
		}
		csrf := w.Result().Cookies()[0]
		if csrf.Secure != secure || !csrf.HttpOnly || csrf.Domain != "" || csrf.Path != "/" {
			t.Fatalf("csrf attributes %+v", csrf)
		}
		form := url.Values{"csrf": {csrf.Value}, "username": {"alice"}, "password": {"secret"}, "return": {"/path?q=1"}}
		r = httptest.NewRequest("POST", "https://app.example.com"+authLoginPath, strings.NewReader(form.Encode()))
		r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		r.AddCookie(csrf)
		w = httptest.NewRecorder()
		handler.ServeHTTP(w, r)
		if w.Code != 303 || w.Header().Get("Location") != "/path?q=1" {
			t.Fatalf("login %d %s", w.Code, w.Body.String())
		}
		session := w.Result().Cookies()[0]
		if session.Name != a.cookieName() || session.Secure != secure || !session.HttpOnly || session.SameSite != http.SameSiteLaxMode || session.MaxAge != 3600 || session.Domain != "" || session.Path != "/" {
			t.Fatalf("session attributes %+v", session)
		}
		r = httptest.NewRequest("GET", "https://app.example.com/path", nil)
		r.AddCookie(session)
		r.AddCookie(csrf)
		r.AddCookie(&http.Cookie{Name: "app", Value: "kept"})
		w = httptest.NewRecorder()
		handler.ServeHTTP(w, r)
		if w.Code != 204 || !called {
			t.Fatalf("authenticated %d", w.Code)
		}
		original, _ := r.Cookie(a.cookieName())
		if original == nil {
			t.Fatal("original request mutated")
		}
		w = httptest.NewRecorder()
		handler.ServeHTTP(w, cookieFormRequest(a, authLogoutPath, "", "", "/"))
		if w.Code != 303 || len(w.Result().Cookies()) != 2 || w.Result().Cookies()[0].MaxAge != -1 {
			t.Fatalf("logout %d %v", w.Code, w.Header())
		}
	}
}
func TestCookieAuthSecurity(t *testing.T) {
	a := testCookieAuth(t, true)
	token := a.sign("session", "app.example.com", "alice", "", time.Hour)
	if !a.valid(token, "session", "app.example.com") || a.valid(token, "csrf", "app.example.com") || a.valid(token, "session", "other.example.com") || a.valid("x"+token, "session", "app.example.com") || a.valid(token+"x", "session", "app.example.com") {
		t.Fatal("token validation")
	}
	restarted := testCookieAuth(t, true)
	if restarted.valid(token, "session", "app.example.com") {
		t.Fatal("restart preserved session")
	}
	a.now = func() time.Time { return time.Unix(1700003600, 0) }
	if a.valid(token, "session", "app.example.com") {
		t.Fatal("expired session accepted")
	}
	a.now = func() time.Time { return time.Unix(1699999999, 0) }
	if a.valid(token, "session", "app.example.com") {
		t.Fatal("future token accepted")
	}
	a = testCookieAuth(t, true)
	handler := a.wrap(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { t.Fatal("unauthenticated backend access") }))
	for _, user := range []string{"alice", "bob"} {
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, cookieFormRequest(a, authLoginPath, user, "wrong", "/"))
		if w.Code != 401 || !strings.Contains(w.Body.String(), "Incorrect username or password") {
			t.Fatalf("wrong credentials %d", w.Code)
		}
	}
	wHash := httptest.NewRecorder()
	handler.ServeHTTP(wHash, cookieFormRequest(a, authLoginPath, "bob", "hashed-secret", "/"))
	if wHash.Code != 303 {
		t.Fatalf("bcrypt sign-in %d", wHash.Code)
	}
	for _, user := range []string{"", "someone"} {
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, cookieFormRequest(a, authLoginPath, user, "shared", "//evil.example"))
		if w.Code != 303 || w.Header().Get("Location") != "/" {
			t.Fatalf("password-only login %d", w.Code)
		}
	}
	for _, mutate := range []func(*http.Request){
		func(r *http.Request) { r.Header.Del("Cookie") },
		func(r *http.Request) { r.Header.Set("Origin", "https://evil.example") },
		func(r *http.Request) { r.Header.Set("Sec-Fetch-Site", "cross-site") },
	} {
		r := cookieFormRequest(a, authLoginPath, "alice", "secret", "/")
		mutate(r)
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, r)
		if w.Code != 403 {
			t.Fatalf("csrf bypass %d", w.Code)
		}
	}
	for _, method := range []string{"GET", "POST"} {
		r := httptest.NewRequest(method, "https://app.example.com/api", nil)
		if method == "GET" {
			r.Header.Set("Upgrade", "websocket")
			r.Header.Set("Accept", "text/html")
		}
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, r)
		if w.Code != 401 {
			t.Fatalf("API/upgrade status %d", w.Code)
		}
	}
	r := cookieFormRequest(a, authLoginPath, "alice", "secret", "/")
	r.Body = io.NopCloser(strings.NewReader(strings.Repeat("x", 17000)))
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, r)
	if w.Code != 400 {
		t.Fatalf("oversized form %d", w.Code)
	}
	for range cap(a.loginSlots) {
		a.loginSlots <- struct{}{}
	}
	w = httptest.NewRecorder()
	handler.ServeHTTP(w, cookieFormRequest(a, authLoginPath, "alice", "secret", "/"))
	if w.Code != 429 {
		t.Fatalf("busy login %d", w.Code)
	}
	response := &http.Response{Header: make(http.Header)}
	response.Header.Add("Set-Cookie", a.cookieName()+"=evil; Path=/")
	response.Header.Add("Set-Cookie", a.csrfName()+"=evil; Path=/")
	response.Header.Add("Set-Cookie", "app=kept; Path=/")
	a.filterResponse(response)
	if len(response.Header.Values("Set-Cookie")) != 1 || !strings.HasPrefix(response.Header.Get("Set-Cookie"), "app=") {
		t.Fatal("backend overwrote reserved cookie")
	}
}
func TestCookieAuthenticatedWebSocket(t *testing.T) {
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Cookie") != "" {
			t.Error("session cookie reached websocket backend")
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
	a := testCookieAuth(t, false)
	front := httptest.NewServer(a.wrap(proxy))
	defer front.Close()
	conn, err := net.Dial("tcp", front.Listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = conn.Close() }()
	_ = conn.SetDeadline(time.Now().Add(3 * time.Second))
	token := a.sign("session", "app.example.com", "alice", "", time.Hour)
	_, err = fmt.Fprintf(conn, "GET / HTTP/1.1\r\nHost: app.example.com\r\nCookie: %s=%s\r\nConnection: Upgrade\r\nUpgrade: websocket\r\n\r\n", a.cookieName(), token)
	if err != nil {
		t.Fatal(err)
	}
	rw := bufio.NewReader(conn)
	response, err := http.ReadResponse(rw, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = response.Body.Close() }()
	if response.StatusCode != 101 {
		t.Fatalf("upgrade %d", response.StatusCode)
	}
	_, _ = conn.Write([]byte("echo"))
	var reply [4]byte
	if _, err := io.ReadFull(rw, reply[:]); err != nil || string(reply[:]) != "echo" {
		t.Fatalf("relay %s %v", reply, err)
	}
}

func TestCookieAuthFirefoxOpaqueOrigin(t *testing.T) {
	a := testCookieAuth(t, true)
	handler := a.wrap(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { t.Fatal("unexpected backend request") }))
	page := httptest.NewRecorder()
	handler.ServeHTTP(page, httptest.NewRequest("GET", "https://app.example.com"+authLoginPath, nil))
	if page.Header().Get("Referrer-Policy") != "same-origin" {
		t.Fatal("auth pages must preserve same-origin provenance")
	}
	for _, path := range []string{authLoginPath, authLogoutPath} {
		for _, site := range []string{"same-origin", "cross-site", "same-site", "none", ""} {
			for _, withCookie := range []bool{true, false} {
				r := cookieFormRequest(a, path, "alice", "secret", "/")
				r.Header.Set("Origin", "null")
				r.Header.Set("Sec-Fetch-Site", site)
				if !withCookie {
					r.Header.Del("Cookie")
				}
				w := httptest.NewRecorder()
				handler.ServeHTTP(w, r)
				want := http.StatusForbidden
				if site == "same-origin" && withCookie {
					want = http.StatusSeeOther
				}
				if w.Code != want {
					t.Fatalf("%s site=%q cookie=%v: got %d want %d", path, site, withCookie, w.Code, want)
				}
			}
		}
		// Fetch Metadata does not bypass a missing or mismatched form token.
		r := cookieFormRequest(a, path, "alice", "secret", "/")
		r.Header.Set("Origin", "null")
		r.Header.Set("Sec-Fetch-Site", "same-origin")
		r.Body = io.NopCloser(strings.NewReader("csrf=incorrect&username=alice&password=secret"))
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, r)
		if w.Code != http.StatusForbidden {
			t.Fatalf("mismatched token accepted: %d", w.Code)
		}
	}
}

func TestCookieAuthFormsSurviveOtherTabs(t *testing.T) {
	a := testCookieAuth(t, true)
	handler := a.wrap(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { t.Fatal("unexpected backend request") }))
	first := httptest.NewRecorder()
	handler.ServeHTTP(first, httptest.NewRequest("GET", "https://app.example.com"+authLoginPath, nil))
	csrf := first.Result().Cookies()[0]
	for _, path := range []string{authLoginPath, authLogoutPath} {
		r := httptest.NewRequest("GET", "https://app.example.com"+path, nil)
		r.AddCookie(csrf)
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, r)
		if w.Code != 200 || len(w.Result().Cookies()) != 0 || !strings.Contains(w.Body.String(), csrf.Value) {
			t.Fatalf("%s rotated token: %d %v", path, w.Code, w.Header())
		}
	}
	form := url.Values{"csrf": {csrf.Value}, "username": {"alice"}, "password": {"secret"}}
	r := httptest.NewRequest("POST", "https://app.example.com"+authLoginPath, strings.NewReader(form.Encode()))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	r.AddCookie(csrf)
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, r)
	if w.Code != 303 {
		t.Fatalf("original form rejected: %d", w.Code)
	}
	// Expired browser tokens are replaced, not reused or extended indefinitely.
	a.now = func() time.Time { return time.Unix(1700000900, 0) }
	r = httptest.NewRequest("GET", "https://app.example.com"+authLoginPath, nil)
	r.AddCookie(csrf)
	w = httptest.NewRecorder()
	handler.ServeHTTP(w, r)
	cookies := w.Result().Cookies()
	if len(cookies) != 1 || cookies[0].Value == csrf.Value {
		t.Fatal("expired form token was reused")
	}
}

func TestSafeReturnURL(t *testing.T) {
	for _, value := range []string{"https://evil.example", "//evil.example", "/\\evil.example", "/%2f%2fevil.example", "/%5cevil.example", "/\r\nevil", "javascript:bad", authLoginPath, ""} {
		if got := safeReturnURL(value); got != "/" {
			t.Fatalf("unsafe %q => %q", value, got)
		}
	}
	if safeReturnURL("/path?q=1") != "/path?q=1" {
		t.Fatal("local return lost")
	}
}

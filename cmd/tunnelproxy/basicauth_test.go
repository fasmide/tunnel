package main

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"golang.org/x/crypto/bcrypt"
)

func TestBasicAuthCLI(t *testing.T) {
	hash, err := bcrypt.GenerateFromPassword([]byte("secret"), bcrypt.MinCost)
	if err != nil {
		t.Fatal(err)
	}
	for _, command := range []string{"serve", "joinserve"} {
		base := []string{command, "-s", "tunnel.example.com", "-n", "app.example.com", "-t", "127.0.0.1:8080"}
		for _, mode := range []string{"acme", "private", "http", "raw", "byo"} {
			args := append(append([]string{}, base...), "--mode", mode)
			if mode == "byo" {
				args = append(args, "--cert", "cert.pem", "--key", "key.pem")
			}
			for _, flag := range []string{"--basicauth", "--basicauth=user:secret", "--basicauth=user:with:colons", "--basicauth=:secret", "--basicauth=:" + string(hash), "--basicauth=user:" + string(hash)} {
				c, err := parse(append(append([]string{}, args...), flag))
				if err != nil || !c.basicAuthEnabled {
					t.Fatalf("%s %s %s: %v", command, mode, flag, err)
				}
				if flag == "--basicauth" && (len(c.basicAuth) != 1 || c.basicAuth[0] != "") {
					t.Fatal("bare flag did not select generation")
				}
			}
		}
		for _, flag := range []string{"--basicauth=", "--basicauth=oops", "--basicauth=:", "--basicauth=user:", "--basicauth=user:$2b$garbage", "--basicauth=user:" + string(hash[:59]), "--basicauth=user:" + string(hash[:59]) + "!"} {
			if _, err := parse(append(append([]string{}, base...), flag)); err == nil {
				t.Fatalf("accepted %s", flag)
			}
		}
		c, err := parse(base)
		if err != nil || c.basicAuthEnabled {
			t.Fatalf("default changed: %v", err)
		}
	}
	if _, err := parse([]string{"join", "-s", "tunnel.example.com", "-n", "app.example.com", "--basicauth"}); err == nil {
		t.Fatal("join accepted serving flag")
	}
}

func TestBasicAuthMiddleware(t *testing.T) {
	hash, err := bcrypt.GenerateFromPassword([]byte("secret:colon"), bcrypt.MinCost)
	if err != nil {
		t.Fatal(err)
	}
	for _, specification := range []string{"user:secret:colon", "user:" + string(hash), "user:$2b$" + string(hash[4:]), "user:$2y$" + string(hash[4:])} {
		auth, err := parseBasicAuth(specification)
		if err != nil {
			t.Fatal(err)
		}
		for _, tc := range []struct {
			name, header       string
			username, password string
			set, allowed       bool
		}{
			{name: "missing"},
			{name: "malformed", header: "Basic !!!"},
			{name: "bearer", header: "Bearer secret"},
			{name: "wrong user", username: "wrong", password: "secret:colon", set: true},
			{name: "wrong password", username: "user", password: "wrong", set: true},
			{name: "correct", username: "user", password: "secret:colon", set: true, allowed: true},
		} {
			t.Run(tc.name, func(t *testing.T) {
				called := false
				handler := auth.wrap(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					called = true
					if r.Header.Get("Authorization") != "" {
						t.Fatal("credentials leaked to backend")
					}
					w.WriteHeader(http.StatusNoContent)
				}))
				r := httptest.NewRequest(http.MethodGet, "https://example.com/", nil)
				r.Header.Set("Authorization", tc.header)
				if tc.set {
					r.SetBasicAuth(tc.username, tc.password)
				}
				original := r.Header.Get("Authorization")
				w := httptest.NewRecorder()
				handler.ServeHTTP(w, r)
				if called != tc.allowed {
					t.Fatalf("backend called=%v", called)
				}
				if !tc.allowed && (w.Code != http.StatusUnauthorized || !strings.HasPrefix(w.Header().Get("WWW-Authenticate"), "Basic ") || w.Header().Get("Cache-Control") != "no-store") {
					t.Fatalf("challenge: %d %v", w.Code, w.Header())
				}
				if tc.allowed && w.Code != http.StatusNoContent {
					t.Fatalf("status %d", w.Code)
				}
				if r.Header.Get("Authorization") != original {
					t.Fatal("mutated original request")
				}
			})
		}
	}
}

func TestGeneratedBasicAuthAndWarnings(t *testing.T) {
	var passwords []string
	for range 2 {
		var out bytes.Buffer
		auth, err := prepareBasicAuth(config{basicAuthEnabled: true, mode: "acme"}, &out)
		if err != nil {
			t.Fatal(err)
		}
		_, rest, ok := strings.Cut(out.String(), "Password: ")
		password, _, _ := strings.Cut(rest, "\n")
		if !ok || len(password) != 24 || !strings.Contains(out.String(), "Restarting tunnelproxy generates a new one") {
			t.Fatalf("output %q", out.String())
		}
		assertBcryptHint(t, out.String(), "", password)
		passwords = append(passwords, password)
		wrong := httptest.NewRequest(http.MethodGet, "https://example.com", nil)
		wrong.SetBasicAuth("anyone", "incorrect")
		denied := httptest.NewRecorder()
		auth.wrap(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { t.Fatal("wrong generated password reached backend") })).ServeHTTP(denied, wrong)
		if denied.Code != http.StatusUnauthorized {
			t.Fatalf("wrong generated password status %d", denied.Code)
		}
		for _, user := range []string{"", "alice", "bob"} {
			r := httptest.NewRequest(http.MethodGet, "https://example.com", nil)
			r.SetBasicAuth(user, password)
			w := httptest.NewRecorder()
			auth.wrap(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(204) })).ServeHTTP(w, r)
			if w.Code != 204 {
				t.Fatalf("username %q rejected", user)
			}
		}
	}
	if passwords[0] == passwords[1] {
		t.Fatal("password reused across invocations")
	}
	for _, mode := range []string{"acme", "private", "byo", "http", "raw"} {
		var out bytes.Buffer
		auth, err := prepareBasicAuth(config{basicAuthEnabled: true, basicAuth: []string{"user:secret"}, mode: mode}, &out)
		if err != nil || (auth == nil) != (mode == "raw") {
			t.Fatalf("%s: %v", mode, err)
		}
		if strings.Contains(out.String(), "secret") {
			t.Fatal("explicit secret logged")
		}
		if (mode == "http" || mode == "raw") && !strings.Contains(out.String(), "WARNING:") {
			t.Fatalf("%s missing warning", mode)
		}
	}
	var out bytes.Buffer
	auth, err := prepareBasicAuth(config{}, &out)
	if err != nil || auth != nil || out.Len() != 0 {
		t.Fatal("disabled auth changed behavior")
	}
	called := false
	auth.wrap(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { called = true })).ServeHTTP(httptest.NewRecorder(), httptest.NewRequest("GET", "/", nil))
	if !called {
		t.Fatal("disabled middleware blocked request")
	}
}

func assertBcryptHint(t *testing.T, output, username, password string) {
	t.Helper()
	_, rest, ok := strings.Cut(output, "--basicauth='")
	value, _, _ := strings.Cut(rest, "'\n")
	if !ok {
		t.Fatalf("missing bcrypt hint: %q", output)
	}
	auth, err := parseBasicAuth(value)
	if err != nil || auth.username != username || auth.anyUser != (username == "") || bcrypt.CompareHashAndPassword(auth.hash, []byte(password)) != nil {
		t.Fatalf("incorrect bcrypt hint: %q %v", value, err)
	}
}

func TestPasswordOnlyAndBcryptHints(t *testing.T) {
	hash, err := bcrypt.GenerateFromPassword([]byte("secret"), bcrypt.MinCost)
	if err != nil {
		t.Fatal(err)
	}
	for _, specification := range []string{":secret", ":" + string(hash)} {
		auth, err := parseBasicAuth(specification)
		if err != nil {
			t.Fatal(err)
		}
		for _, user := range []string{"", "alice", "nouser"} {
			for _, password := range []string{"secret", "wrong"} {
				r := httptest.NewRequest("GET", "/", nil)
				r.SetBasicAuth(user, password)
				w := httptest.NewRecorder()
				auth.wrap(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(204) })).ServeHTTP(w, r)
				want := 401
				if password == "secret" {
					want = 204
				}
				if w.Code != want {
					t.Fatalf("%s %s: %d", user, password, w.Code)
				}
			}
		}
	}
	for _, user := range []string{"", "alice"} {
		var out bytes.Buffer
		_, err := prepareBasicAuth(config{basicAuthEnabled: true, basicAuth: []string{user + ":secret"}, mode: "acme"}, &out)
		if err != nil {
			t.Fatal(err)
		}
		assertBcryptHint(t, out.String(), user, "secret")
		if strings.Contains(out.String(), "secret") {
			t.Fatal("plaintext leaked")
		}
	}
	var out bytes.Buffer
	_, err = prepareBasicAuth(config{basicAuthEnabled: true, basicAuth: []string{"user:" + string(hash)}, mode: "acme"}, &out)
	if err != nil || out.Len() != 0 {
		t.Fatalf("hash input emitted hint: %q %v", out.String(), err)
	}
	if err := printBcryptHint(&out, "user", strings.Repeat("x", 73)); err != nil || !strings.Contains(out.String(), "72 bytes") {
		t.Fatalf("long password: %q %v", out.String(), err)
	}
	out.Reset()
	if err := printBcryptHint(&out, "o'brien", "secret"); err != nil || !strings.Contains(out.String(), "o'\"'\"'brien:") {
		t.Fatalf("shell quoting: %q %v", out.String(), err)
	}
}

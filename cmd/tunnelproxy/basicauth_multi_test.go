package main

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"golang.org/x/crypto/bcrypt"
)

func TestRepeatedBasicAuthCLI(t *testing.T) {
	for _, command := range []string{"serve", "joinserve"} {
		base := []string{command, "-s", "tunnel.example.com", "-n", "app.example.com", "-t", "127.0.0.1:8080"}
		args := append(append([]string{}, base...), "--basicauth=alice:first,with:punctuation", "--basicauth", "--basicauth=bob:second", "--basicauth=")
		c, err := parse(args)
		if err != nil {
			t.Fatal(err)
		}
		want := []string{"alice:first,with:punctuation", "", "bob:second", ""}
		if len(c.basicAuth) != len(want) {
			t.Fatalf("identities: %v", c.basicAuth)
		}
		for i := range want {
			if c.basicAuth[i] != want[i] {
				t.Fatalf("identity %d: %q", i, c.basicAuth[i])
			}
		}
		for _, flags := range [][]string{
			{"--basicauth=invalid", "--basicauth=bob:valid"},
			{"--basicauth=alice:valid", "--basicauth=invalid"},
		} {
			if _, err := parse(append(append([]string{}, base...), flags...)); err == nil {
				t.Fatalf("accepted invalid identity in %v", flags)
			}
		}
	}
}

func TestMultipleBasicAuthIdentities(t *testing.T) {
	hash, err := bcrypt.GenerateFromPassword([]byte("bob-password"), bcrypt.MinCost)
	if err != nil {
		t.Fatal(err)
	}
	var out bytes.Buffer
	auth, err := prepareBasicAuth(config{
		basicAuthEnabled: true, mode: "acme",
		basicAuth: []string{"alice:alice-password", "bob:" + string(hash), "alice:other-password", ":shared-password", "", ""},
	}, &out)
	if err != nil {
		t.Fatal(err)
	}
	if len(auth) != 6 {
		t.Fatalf("identity count %d", len(auth))
	}
	var generated []string
	for _, line := range strings.Split(out.String(), "\n") {
		if password, ok := strings.CutPrefix(line, "Password: "); ok {
			generated = append(generated, password)
		}
	}
	if len(generated) != 2 || generated[0] == generated[1] {
		t.Fatalf("generated passwords: %v", generated)
	}
	cases := []struct {
		user, password string
		allowed        bool
	}{
		{"alice", "alice-password", true},
		{"bob", "bob-password", true},
		{"alice", "other-password", true},
		{"bob", "alice-password", false},
		{"alice", "bob-password", false},
		{"unknown", "bob-password", false},
		{"unknown", "wrong", false},
		{"anyone", "shared-password", true},
		{"", "shared-password", true},
		{"anyone", generated[0], true},
		{"someone-else", generated[1], true},
	}
	for _, tc := range cases {
		called := false
		handler := auth.wrap(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			called = true
			if r.Header.Get("Authorization") != "" {
				t.Error("credentials reached backend")
			}
			w.WriteHeader(http.StatusNoContent)
		}))
		r := httptest.NewRequest("GET", "/", nil)
		r.SetBasicAuth(tc.user, tc.password)
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, r)
		want := http.StatusUnauthorized
		if tc.allowed {
			want = http.StatusNoContent
		}
		if w.Code != want || called != tc.allowed {
			t.Fatalf("user %q: status %d called %v", tc.user, w.Code, called)
		}
	}
	// Missing credentials must not match any entry, including password-only ones.
	w := httptest.NewRecorder()
	auth.wrap(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { t.Fatal("missing credentials reached backend") })).ServeHTTP(w, httptest.NewRequest("GET", "/", nil))
	if w.Code != http.StatusUnauthorized {
		t.Fatalf("missing credentials status %d", w.Code)
	}
}

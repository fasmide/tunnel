package main

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestFileServeCLI(t *testing.T) {
	base := []string{"file-serve", "--server=tunnel.example.net", "--name=files.example.net"}
	c, err := parse(base)
	if err != nil || c.root != "." || c.browse || c.accessLog || c.revealSymlinks || c.target != "" {
		t.Fatalf("defaults: %+v %v", c, err)
	}
	for _, auth := range []string{"--basicauth=user:password", "--cookieauth=user:password", "--bearerauth=random-token", "--clientcertauth=" + strings.Repeat("ab", 32), "--clientcertauth-ca=clients.pem"} {
		c, err := parse(append(append([]string{}, base...), "--root=public", "--browse", "--access-log", auth))
		if err != nil || c.root != "public" || !c.browse || !c.accessLog {
			t.Fatalf("%s: %+v %v", auth, c, err)
		}
	}
	for _, flags := range [][]string{{"--mode=raw"}, {"--target=127.0.0.1:80"}, {"--root="}, {"--basicauth=a:b", "--bearerauth=token"}} {
		if _, err := parse(append(append([]string{}, base...), flags...)); err == nil {
			t.Fatalf("accepted %v", flags)
		}
	}
	var cHelp config
	cmd := newCommand(&cHelp, func(config) error { t.Fatal("help executed command"); return nil })
	var help bytes.Buffer
	cmd.SetOut(&help)
	cmd.SetArgs([]string{"file-serve", "--help"})
	if err := cmd.Execute(); err != nil {
		t.Fatal(err)
	}
	for _, flag := range []string{"--root", "--browse", "--access-log", "--basicauth", "--cookieauth", "--bearerauth", "--clientcertauth"} {
		if !strings.Contains(help.String(), flag) {
			t.Errorf("help missing %s", flag)
		}
	}
}

func TestFileHandler(t *testing.T) {
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, "hello.txt"), []byte("hello world"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(filepath.Join(root, "site"), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "site", "index.html"), []byte("home page"), 0600); err != nil {
		t.Fatal(err)
	}
	for _, browse := range []bool{false, true} {
		handler, closeFiles, err := newFileHandler(root, browse, false)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = closeFiles() })
		cases := []struct {
			method, path, header, value string
			status                      int
			body                        string
		}{
			{"GET", "/hello.txt", "", "", 200, "hello world"},
			{"HEAD", "/hello.txt", "", "", 200, ""},
			{"GET", "/hello.txt", "Range", "bytes=0-4", 206, "hello"},
			{"GET", "/hello.txt", "If-Modified-Since", "Thu, 01 Jan 2099 00:00:00 GMT", 304, ""},
			{"GET", "/site/", "", "", 200, "home page"},
			{"GET", "/site", "", "", 301, ""},
			{"GET", "/missing", "", "", 404, ""},
			{"POST", "/hello.txt", "", "", 405, ""},
		}
		for _, tc := range cases {
			r := httptest.NewRequest(tc.method, tc.path, nil)
			if tc.header != "" {
				r.Header.Set(tc.header, tc.value)
			}
			w := httptest.NewRecorder()
			handler.ServeHTTP(w, r)
			if w.Code != tc.status || tc.status < 300 && w.Body.String() != tc.body {
				t.Errorf("browse=%v %s %s: %d %q", browse, tc.method, tc.path, w.Code, w.Body.String())
			}
		}
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, httptest.NewRequest("GET", "/", nil))
		if browse && (w.Code != 200 || !strings.Contains(w.Body.String(), "hello.txt")) || !browse && w.Code != 404 {
			t.Fatalf("browse=%v: %d %s", browse, w.Code, w.Body.String())
		}
	}
}

func TestRevealSymlinks(t *testing.T) {
	root := t.TempDir()
	if err := os.Mkdir(filepath.Join(root, "target-directory"), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("target-directory", filepath.Join(root, "link")); err != nil {
		t.Skipf("symlinks unavailable: %v", err)
	}
	if err := os.Symlink("<script>alert(1)</script>", filepath.Join(root, "unsafe-link")); err != nil {
		t.Fatal(err)
	}
	for _, reveal := range []bool{false, true} {
		handler, closeFiles, err := newFileHandler(root, true, reveal)
		if err != nil {
			t.Fatal(err)
		}
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, httptest.NewRequest("GET", "/", nil))
		_ = closeFiles()
		if w.Code != 200 || !strings.Contains(w.Body.String(), `href="./link"`) && !strings.Contains(w.Body.String(), `href="link"`) {
			t.Fatalf("missing link: %d %s", w.Code, w.Body.String())
		}
		if strings.Contains(w.Body.String(), "→ target-directory") != reveal {
			t.Fatalf("reveal=%v: %s", reveal, w.Body.String())
		}
		if strings.Contains(w.Body.String(), "<script>") {
			t.Fatal("unescaped symlink target")
		}
		if strings.Contains(w.Body.String(), "&lt;script&gt;") != reveal {
			t.Fatal("symlink target visibility does not match flag")
		}
	}
	handler, closeFiles, err := newFileHandler(root, false, true)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = closeFiles() }()
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, httptest.NewRequest("GET", "/", nil))
	if w.Code != 404 {
		t.Fatal("reveal enabled browsing without --browse")
	}
	c, err := parse([]string{"file-serve", "--server=tunnel.example.net", "--name=files.example.net", "--reveal-symlinks", "--browse"})
	if err != nil || !c.revealSymlinks || !c.browse {
		t.Fatalf("config: %+v %v", c, err)
	}
}

func TestFileRootConfinement(t *testing.T) {
	root, outside := t.TempDir(), t.TempDir()
	secret := filepath.Join(outside, "secret.txt")
	if err := os.WriteFile(secret, []byte("outside-secret"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(secret, filepath.Join(root, "escape.txt")); err != nil {
		t.Skipf("symlinks unavailable: %v", err)
	}
	handler, closeFiles, err := newFileHandler(root, true, false)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = closeFiles() }()
	for _, target := range []string{"/escape.txt", "/../secret.txt", "/%2e%2e/secret.txt"} {
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, httptest.NewRequest("GET", target, nil))
		if w.Code == 200 || strings.Contains(w.Body.String(), "outside-secret") {
			t.Fatalf("escaped root via %s: %d %s", target, w.Code, w.Body.String())
		}
	}
}

func TestFileAuthAndAccessLog(t *testing.T) {
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, "hello.txt"), []byte("hello"), 0600); err != nil {
		t.Fatal(err)
	}
	files, closeFiles, err := newFileHandler(root, false, false)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = closeFiles() }()
	auth, err := parseBasicAuth("user:secret-password")
	if err != nil {
		t.Fatal(err)
	}
	var out bytes.Buffer
	handler := accessLogged(authenticatedHandler(files, basicAuthList{auth}, nil, nil), &out)
	for _, allowed := range []bool{false, true} {
		r := httptest.NewRequest("GET", "/hello.txt?private=query-secret", nil)
		r.Header.Set("Cookie", "private=cookie-secret")
		if allowed {
			r.SetBasicAuth("user", "secret-password")
		}
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, r)
		want := http.StatusUnauthorized
		if allowed {
			want = http.StatusOK
		}
		if w.Code != want {
			t.Fatalf("allowed=%v: %d", allowed, w.Code)
		}
	}
	for _, secret := range []string{"query-secret", "cookie-secret", "secret-password"} {
		if strings.Contains(out.String(), secret) {
			t.Fatalf("secret logged: %s", secret)
		}
	}
	lines := strings.Split(strings.TrimSpace(out.String()), "\n")
	if len(lines) != 2 {
		t.Fatalf("log lines: %s", out.String())
	}
	for i, line := range lines {
		var record struct {
			Status int   `json:"status"`
			Bytes  int64 `json:"bytes"`
		}
		if err := json.Unmarshal([]byte(line), &record); err != nil {
			t.Fatal(err)
		}
		if i == 0 && record.Status != 401 || i == 1 && (record.Status != 200 || record.Bytes != 5) {
			t.Fatalf("unexpected record: %s", line)
		}
	}
}

package main

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"strings"
	"testing"
)

func TestUserUnitArguments(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("Linux only")
	}
	base := []string{"serve", "-s", "tunnel.example.net", "-n", "app.example.net", "-t", "127.0.0.1:8080"}
	c, err := parse(append(base, "--install-user-unit", "--state=relative-state", "--header-host=localhost", "--header-x-token=secret $value%", "--basicauth=alice:password", "--basicauth=bob:password", "--join"))
	if err != nil {
		t.Fatal(err)
	}
	restored, err := parse(c.unitArgs)
	if err != nil {
		t.Fatal(err)
	}
	if restored.installUserUnit || !restored.join || !filepath.IsAbs(restored.state) || restored.headers.Get("Host") != "localhost" || restored.headers.Get("X-Token") != "secret $value%" || !reflect.DeepEqual(c.basicAuth, restored.basicAuth) {
		t.Fatalf("arguments not preserved: %q", c.unitArgs)
	}
	for _, flag := range []string{"--basicauth", "--cookieauth", "--bearerauth", "--bearerauth="} {
		if _, err := parse(append(append([]string{}, base...), "--install-user-unit", flag)); err == nil {
			t.Errorf("accepted generated authentication: %s", flag)
		}
	}
	if _, err := parse([]string{"join", "-s", "tunnel.example.net", "-n", "app.example.net", "--install-user-unit"}); err == nil {
		t.Fatal("join accepted install flag")
	}
	for _, name := range []string{"../../bad", "bad\nname", strings.Repeat("a.", 120) + "example.net"} {
		args := append(append([]string{}, base...), "--install-user-unit", "--name="+name)
		if _, err := parse(args); err == nil {
			t.Errorf("accepted unsafe unit name %q", name)
		}
	}
}

func TestUserUnitFilePaths(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("Linux only")
	}
	for _, command := range []string{"serve", "file-serve"} {
		args := []string{command, "-s", "tunnel.example.net", "-n", "app.example.net", "--mode=byo", "--cert=cert.pem", "--key=key.pem", "--clientcertauth-ca=clients.pem", "--install-user-unit"}
		if command == "serve" {
			args = append(args, "--target-unix-socket=app.sock")
		}
		c, err := parse(args)
		if err != nil {
			t.Fatal(err)
		}
		restored, err := parse(c.unitArgs)
		if err != nil {
			t.Fatal(err)
		}
		for _, path := range []string{restored.state, restored.cert, restored.key, restored.clientCertAuthCA} {
			if !filepath.IsAbs(path) {
				t.Errorf("relative path %q", path)
			}
		}
		if command == "serve" && !filepath.IsAbs(restored.targetUnixSocket) || command == "file-serve" && !filepath.IsAbs(restored.root) {
			t.Fatalf("relative serving path: %q", c.unitArgs)
		}
	}
}

func TestWriteUserUnit(t *testing.T) {
	dir := t.TempDir()
	c := config{name: "app.example.net", drainTimeout: 2500000000, unitArgs: []string{"serve", "--header-authorization=Bearer secret", "--basicauth=alice:$2b$hash%", "--header-x-test=quoted \"value\"\\path"}}
	unitPath, err := writeUserUnit(c, dir, "/opt/my proxy%/$bin", "/srv/my files%")
	if err != nil {
		t.Fatal(err)
	}
	if unitPath != filepath.Join(dir, "systemd", "user", "tunnelproxy-app.example.net.service") {
		t.Fatal(unitPath)
	}
	data, err := os.ReadFile(unitPath)
	if err != nil {
		t.Fatal(err)
	}
	unit := string(data)
	for _, want := range []string{`ExecStart="/opt/my proxy%%/$$bin" "serve" "--header-authorization=Bearer secret" "--basicauth=alice:$$2b$$hash%%" "--header-x-test=quoted \"value\"\\path"`, `WorkingDirectory="/srv/my files%%"`, "Restart=on-failure", "TimeoutStopSec=7s", "WantedBy=default.target"} {
		if !strings.Contains(unit, want) {
			t.Errorf("unit missing %q: %s", want, unit)
		}
	}
	info, err := os.Stat(unitPath)
	if err != nil || info.Mode().Perm() != 0600 {
		t.Fatalf("expected private unit %s: %v", unitPath, err)
	}
	if _, err := os.Stat(filepath.Join(dir, "tunnelproxy")); !os.IsNotExist(err) {
		t.Fatal("unexpected separate argument directory")
	}
	if _, err := writeUserUnit(c, dir, "/another/bin", "/"); err == nil {
		t.Fatal("overwrote installed unit")
	}
	after, _ := os.ReadFile(unitPath)
	if string(after) != unit {
		t.Fatal("existing unit changed")
	}
}

func TestInstallUserUnitReportsNextSteps(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("Linux only")
	}
	dir := t.TempDir()
	t.Setenv("XDG_CONFIG_HOME", dir)
	t.Setenv("PATH", t.TempDir()) // Missing systemctl must not fail installation.
	var out bytes.Buffer
	err := run(context.Background(), []string{"serve", "-s", "tunnel.example.net", "-n", "app.example.net", "-t", "127.0.0.1:8080", "--install-user-unit"}, &out)
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		filepath.Join(dir, "systemd", "user", "tunnelproxy-app.example.net.service"),
		"has not been enabled or started", "systemctl --user daemon-reload",
		"systemctl --user enable --now tunnelproxy-app.example.net.service",
		"loginctl show-user", "loginctl enable-linger",
	} {
		if !strings.Contains(out.String(), want) {
			t.Errorf("output missing %q: %s", want, out.String())
		}
	}
}

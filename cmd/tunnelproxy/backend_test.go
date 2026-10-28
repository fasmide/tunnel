package main

import (
	"context"
	"path/filepath"
	"testing"
	"time"
)

func TestTargetSelectionCLI(t *testing.T) {
	base := []string{"serve", "--server=tunnel.example.net", "--name=app.example.net"}
	for _, flags := range [][]string{
		{"--target=127.0.0.1:8080"},
		{"-t", "127.0.0.1:8080"},
		{"--target-unix-socket=/run/app.sock"},
		{"--target-unix-socket=relative.sock", "--join"},
	} {
		c, err := parse(append(append([]string{}, base...), flags...))
		if err != nil {
			t.Fatalf("%v: %v", flags, err)
		}
		if (c.target == "") == (c.targetUnixSocket == "") {
			t.Fatalf("expected exactly one target: %+v", c)
		}
	}
	for _, flags := range [][]string{
		nil,
		{"--target="},
		{"--target-unix-socket="},
		{"--target=127.0.0.1:8080", "--target-unix-socket=/run/app.sock"},
		{"-t", "127.0.0.1:8080", "--target-unix-socket="},
		{"--target=", "--target-unix-socket=/run/app.sock"},
		{"--target-unix-socket=/run/app.sock", "--target-timeout=0s"},
	} {
		if _, err := parse(append(append([]string{}, base...), flags...)); err == nil {
			t.Fatalf("accepted invalid target selection: %v", flags)
		}
	}
	for _, command := range []string{"join", "file-serve"} {
		if _, err := parse([]string{command, "--server=tunnel.example.net", "--name=app.example.net", "--target-unix-socket=/run/app.sock"}); err == nil {
			t.Fatalf("%s accepted proxy target", command)
		}
	}
}

func TestDialBackendFailures(t *testing.T) {
	if conn, err := dialBackend(context.Background(), "tcp", nil, time.Second); err == nil || conn != nil {
		t.Fatal("empty backend list accepted")
	}
	path := filepath.Join(t.TempDir(), "missing.sock")
	if conn, err := dialBackend(context.Background(), "unix", []string{path}, time.Second); err == nil || conn != nil {
		t.Fatal("missing Unix socket accepted")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if conn, err := dialBackend(ctx, "unix", []string{path}, time.Second); err == nil || conn != nil {
		t.Fatal("canceled dial accepted")
	}
}

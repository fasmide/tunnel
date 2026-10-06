package main

import (
	"net"
	"os"
	"path/filepath"
	"testing"
)

func TestPrivateSocketDirectory(t *testing.T) {
	socket := filepath.Join(t.TempDir(), "run", "admin.sock")
	if err := prepareSocketDirectory(socket); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(filepath.Dir(socket))
	if err != nil || info.Mode().Perm() != 0700 {
		t.Fatalf("directory: %v %v", info, err)
	}
	if err := prepareSocketDirectory("relative/admin.sock"); err == nil {
		t.Fatal("relative path accepted")
	}
	if err := os.Chmod(filepath.Dir(socket), 0755); err != nil {
		t.Fatal(err)
	}
	if err := prepareSocketDirectory(socket); err == nil {
		t.Fatal("public directory accepted")
	}
	target := t.TempDir()
	link := filepath.Join(t.TempDir(), "link")
	if err := os.Symlink(target, link); err != nil {
		t.Fatal(err)
	}
	if err := prepareSocketDirectory(filepath.Join(link, "admin.sock")); err == nil {
		t.Fatal("symlink runtime directory accepted")
	}
}

func TestPrepareSocketPath(t *testing.T) {
	socket := filepath.Join(t.TempDir(), "run", "pprof.sock")
	if err := prepareSocketDirectory(socket); err != nil {
		t.Fatal(err)
	}
	listener, err := net.Listen("unix", socket)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = listener.Close() }()
	if err := prepareSocketPath(socket, "pprof socket"); err == nil {
		t.Fatal("active socket accepted")
	}
	_ = listener.Close()
	if err := prepareSocketPath(socket, "pprof socket"); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(socket); !os.IsNotExist(err) {
		t.Fatalf("stale socket not removed: %v", err)
	}
}

func TestListenPprof(t *testing.T) {
	socket := filepath.Join(t.TempDir(), "run", "pprof.sock")
	if err := prepareSocketDirectory(socket); err != nil {
		t.Fatal(err)
	}
	server, err := listenPprof(socket)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = server.Close() }()
	info, err := os.Stat(socket)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode()&os.ModeSocket == 0 || info.Mode().Perm() != 0600 {
		t.Fatalf("socket mode %v", info.Mode())
	}
}

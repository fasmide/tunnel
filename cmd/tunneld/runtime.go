package main

import (
	"context"
	"fmt"
	"net"
	"net/http"
	_ "net/http/pprof"
	"os"
	"path/filepath"
	"syscall"
	"time"
)

func prepareSocketDirectory(socket string) error {
	if !filepath.IsAbs(socket) {
		return fmt.Errorf("socket path must be absolute")
	}
	dir := filepath.Dir(socket)
	if err := os.MkdirAll(dir, 0700); err != nil {
		return fmt.Errorf("create socket directory %q: %w", dir, err)
	}
	info, err := os.Lstat(dir)
	if err != nil {
		return fmt.Errorf("stat socket directory %q: %w", dir, err)
	}
	if !info.IsDir() || info.Mode().Perm()&0077 != 0 {
		return fmt.Errorf("socket directory must be a private directory (0700)")
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || int(stat.Uid) != os.Geteuid() {
		return fmt.Errorf("socket directory must be owned by daemon user")
	}
	return nil
}

func prepareSocketPath(path, label string) error {
	dialCtx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if conn, err := (&net.Dialer{}).DialContext(dialCtx, "unix", path); err == nil {
		_ = conn.Close()
		return fmt.Errorf("%s already in use", label)
	}
	if info, err := os.Lstat(path); err == nil {
		if info.Mode()&os.ModeSocket == 0 {
			return fmt.Errorf("%s path is not a socket", label)
		}
		if err = os.Remove(path); err != nil {
			return fmt.Errorf("remove stale %s path %q: %w", label, path, err)
		}
	} else if !os.IsNotExist(err) {
		return fmt.Errorf("stat %s path %q: %w", label, path, err)
	}
	return nil
}

func listenPprof(path string) (*http.Server, error) {
	lc := net.ListenConfig{}
	listener, err := lc.Listen(context.Background(), "unix", path)
	if err != nil {
		return nil, fmt.Errorf("listen on pprof socket %q: %w", path, err)
	}
	if err := os.Chmod(path, 0600); err != nil {
		_ = listener.Close()
		return nil, fmt.Errorf("chmod pprof socket %q: %w", path, err)
	}
	server := &http.Server{Handler: http.DefaultServeMux, ReadHeaderTimeout: 10 * time.Second}
	go func() { _ = server.Serve(listener) }()
	return server, nil
}

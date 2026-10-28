package main

import (
	"context"
	"errors"
	"net"
	"time"
)

// dialBackend shares one deadline across all pinned backend addresses.
// Unix socket targets use a single path and bypass TCP/DNS resolution entirely.
func dialBackend(ctx context.Context, network string, addresses []string, timeout time.Duration) (net.Conn, error) {
	dial, stop := context.WithTimeout(ctx, timeout)
	defer stop()
	var err error
	for _, address := range addresses {
		var conn net.Conn
		conn, err = (&net.Dialer{}).DialContext(dial, network, address)
		if err == nil {
			return conn, nil
		}
	}
	if err == nil {
		err = errors.New("no backend addresses")
	}
	return nil, err
}

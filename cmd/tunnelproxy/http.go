package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"sync"
	"time"

	"github.com/fasmide/tunnel"
)

// newHTTPProxy pins every backend dial to the validated loopback addresses.
// There is no environment proxy, DNS re-resolution, redirect following, or
// backend HTTP/2 negotiation. Host is preserved for existing virtual hosts.
func newHTTPProxy(addresses []string, dialTimeout time.Duration) (*httputil.ReverseProxy, *http.Transport) {
	transport := &http.Transport{
		DialContext: func(ctx context.Context, network, address string) (net.Conn, error) {
			dial, stop := context.WithTimeout(ctx, dialTimeout)
			defer stop()
			var err error
			for _, target := range addresses {
				var conn net.Conn
				conn, err = (&net.Dialer{}).DialContext(dial, "tcp", target)
				if err == nil {
					return conn, nil
				}
			}
			if err == nil {
				err = errors.New("no backend addresses")
			}
			return nil, err
		},
		MaxIdleConns: 128, MaxIdleConnsPerHost: 128, MaxConnsPerHost: 128,
		IdleConnTimeout: 90 * time.Second, ResponseHeaderTimeout: 30 * time.Second,
		ExpectContinueTimeout: time.Second,
	}
	proxy := &httputil.ReverseProxy{Transport: transport, Rewrite: func(r *httputil.ProxyRequest) {
		r.SetURL(&url.URL{Scheme: "http", Host: "loopback.internal"})
		r.Out.Host = r.In.Host
		// Rewrite already removes inbound X-Forwarded-*; Forwarded is removed
		// explicitly so neither standardized nor legacy spoofed chains survive.
		r.Out.Header.Del("Forwarded")
		r.SetXForwarded()
	}}
	return proxy, transport
}

// The daemon's one-shot HTTP path half-closes after the framed request. Go's
// HTTP server treats a background-read EOF as a disconnected caller and cancels
// its handler. Hold that EOF until response/Close instead; malformed truncated
// bodies still time out. This adapter is only for plaintext one-shot HTTP.
type oneShotConn struct {
	net.Conn
	done chan struct{}
	once sync.Once
}

func (c *oneShotConn) Read(p []byte) (int, error) {
	n, err := c.Conn.Read(p)
	if errors.Is(err, io.EOF) {
		if n > 0 {
			return n, nil
		}
		select {
		case <-c.done:
			return 0, net.ErrClosed
		case <-time.After(30 * time.Second):
			return 0, io.ErrUnexpectedEOF
		}
	}
	if err != nil {
		return n, fmt.Errorf("read one-shot connection: %w", err)
	}
	return n, nil
}
func (c *oneShotConn) Close() error {
	c.once.Do(func() { close(c.done) })
	if err := c.Conn.Close(); err != nil {
		return fmt.Errorf("close one-shot connection: %w", err)
	}
	return nil
}

// The Client owns listener removal. Serve/Shutdown otherwise call Close while
// CloseGracefully holds its lifecycle lock, deadlocking HTTP/2 GOAWAY shutdown.
type borrowedListener struct{ net.Listener }

func (borrowedListener) Close() error { return nil }

type oneShotContextKey struct{}
type oneShotListener struct{ net.Listener }

func (l oneShotListener) Accept() (net.Conn, error) {
	c, err := l.Listener.Accept()
	if err != nil {
		return nil, fmt.Errorf("accept one-shot listener: %w", err)
	}
	return &oneShotConn{Conn: c, done: make(chan struct{})}, nil
}

func forwardHTTP(ctx context.Context, client *tunnel.Client, l net.Listener, addresses []string, dialTimeout, drainTimeout time.Duration, plain bool, auth basicAuthList, out io.Writer) error {
	proxy, transport := newHTTPProxy(addresses, dialTimeout)
	var handler http.Handler = auth.wrap(proxy)
	if plain {
		l = oneShotListener{l}
		next := handler
		handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			r.Close = true
			w.Header().Set("Connection", "close")
			next.ServeHTTP(w, r)
			// Release the background EOF read once handler work is complete, so
			// net/http can finish/flush its response and close this one-shot stream.
			if conn, ok := r.Context().Value(oneShotContextKey{}).(*oneShotConn); ok {
				conn.once.Do(func() { close(conn.done) })
			}
		})
	}
	defer transport.CloseIdleConnections()
	// Server.Close/Shutdown do not manage hijacked WebSocket connections. Keep
	// them tracked until final cleanup; tunnel drain itself accounts for them.
	var mu sync.Mutex
	hijacked := map[net.Conn]bool{}
	app := &http.Server{Handler: handler, ReadHeaderTimeout: 10 * time.Second, IdleTimeout: 60 * time.Second, MaxHeaderBytes: 64 << 10,
		ConnContext: func(ctx context.Context, conn net.Conn) context.Context {
			if c, ok := conn.(*oneShotConn); ok {
				return context.WithValue(ctx, oneShotContextKey{}, c)
			}
			return ctx
		},
		ConnState: func(conn net.Conn, state http.ConnState) {
			mu.Lock()
			defer mu.Unlock()
			switch state {
			case http.StateHijacked:
				hijacked[conn] = true
			case http.StateClosed:
				delete(hijacked, conn)
			}
		},
	}
	// Serve (rather than ServeTLS) consumes locally handshaken *tls.Conn values.
	app.Protocols = new(http.Protocols)
	app.Protocols.SetHTTP1(true)
	app.Protocols.SetHTTP2(true)
	app.HTTP2 = &http.HTTP2Config{MaxConcurrentStreams: 128}
	defer func() {
		_ = app.Close()
		mu.Lock()
		defer mu.Unlock()
		for conn := range hijacked {
			_ = conn.Close()
		}
	}()
	served := make(chan error, 1)
	go func() { served <- app.Serve(borrowedListener{l}) }()
	select {
	case err := <-served:
		return fmt.Errorf("HTTP listener: %w", err)
	case <-ctx.Done():
		if _, err := fmt.Fprintln(out, "draining HTTP connections"); err != nil {
			return fmt.Errorf("announce HTTP drain: %w", err)
		}
		drain, stop := context.WithTimeout(context.WithoutCancel(ctx), drainTimeout)
		defer stop()
		// Existing allocated streams/handshakes must still reach Serve. Do NOT call
		// Shutdown first: that would close the listener and discard queued streams.
		app.SetKeepAlivesEnabled(false)
		drained := make(chan error, 1)
		go func() { drained <- client.CloseGracefully(drain) }()
		select {
		case <-served:
			// Accept exits once the allocation barrier and queued connections are
			// processed. Shutdown now closes idle HTTP/2 connections via GOAWAY and
			// waits for active handlers while tunnel drain continues independently.
			shutdownErr := app.Shutdown(drain)
			drainErr := <-drained
			return errors.Join(drainErr, shutdownErr)
		case <-drain.Done():
			_ = app.Close()
			return <-drained
		}
	}
}

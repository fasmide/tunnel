package server

import (
	"context"
	"fmt"
	"net"
	"sync"
	"time"
)

// TLSEdge is a public TCP SNI passthrough listener. It holds no public TLS
// configuration, certificates, or private keys. Close aborts edge traffic and
// waits for handlers; it does not close the tunnel-facing Server.
type TLSEdge struct {
	listener net.Listener
	server   *Server
	ctx      context.Context
	cancel   context.CancelFunc
	wg       sync.WaitGroup
	once     sync.Once
	slots    chan struct{}
	mu       sync.Mutex
	peers    map[net.Conn]bool
	closeErr error
	http     bool
}

// ListenTLS binds a public TCP address (normally :443). The listener only peeks
// the ClientHello and calls Forward; application TLS terminates at the client.
func (s *Server) ListenTLS(addr string) (*TLSEdge, error) { return s.listenEdge(addr, false) }

// ListenHTTP binds the public HTTP edge (normally :80). Plain forwarding is
// opt-in through client ListenHTTP; other valid requests redirect to HTTPS.
func (s *Server) ListenHTTP(addr string) (*TLSEdge, error) { return s.listenEdge(addr, true) }

func (s *Server) listenEdge(addr string, plainHTTP bool) (*TLSEdge, error) {
	s.edgeMu.Lock()
	defer s.edgeMu.Unlock()
	if s.closing {
		return nil, net.ErrClosed
	}
	lc := net.ListenConfig{}
	listener, err := lc.Listen(s.ctx, "tcp", addr)
	if err != nil {
		return nil, fmt.Errorf("listen edge: %w", err)
	}
	ctx, cancel := context.WithCancel(s.ctx)
	e := &TLSEdge{listener: listener, server: s, ctx: ctx, cancel: cancel, slots: make(chan struct{}, 1024), peers: map[net.Conn]bool{}, http: plainHTTP}
	s.edges[e] = true
	e.wg.Add(1)
	go e.accept()
	go func() { <-ctx.Done(); _ = e.Close() }()
	return e, nil
}
func (e *TLSEdge) Addr() net.Addr { return e.listener.Addr() }
func (e *TLSEdge) Close() error {
	e.once.Do(func() {
		e.cancel()
		e.closeErr = e.listener.Close()
		e.mu.Lock()
		for conn := range e.peers {
			_ = conn.Close()
		}
		e.mu.Unlock()
	})
	e.wg.Wait()
	e.server.edgeMu.Lock()
	delete(e.server.edges, e)
	e.server.edgeMu.Unlock()
	return e.closeErr
}
func (e *TLSEdge) accept() {
	defer e.wg.Done()
	for {
		conn, err := e.listener.Accept()
		if err != nil {
			return
		}
		select {
		case e.slots <- struct{}{}:
		default:
			_ = conn.Close()
			continue
		}
		e.mu.Lock()
		if e.ctx.Err() != nil {
			e.mu.Unlock()
			_ = conn.Close()
			<-e.slots
			return
		}
		e.peers[conn] = true
		e.mu.Unlock()
		e.wg.Add(1)
		go func() {
			defer e.wg.Done()
			defer func() { e.mu.Lock(); delete(e.peers, conn); e.mu.Unlock(); <-e.slots }()
			defer func() { _ = conn.Close() }()
			if e.http {
				e.server.serveHTTP(e.ctx, conn)
				return
			}
			if err := conn.SetReadDeadline(time.Now().Add(10 * time.Second)); err != nil {
				return
			}
			host, prefix, err := peekSNI(conn)
			if err != nil {
				return
			}
			if err := conn.SetReadDeadline(time.Time{}); err != nil {
				return
			}
			_ = e.server.Forward(e.ctx, conn, host, prefix)
		}()
	}
}

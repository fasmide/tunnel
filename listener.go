package tunnel

import (
	"context"
	"crypto/rand"
	"crypto/tls"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"sync"
	"time"

	"tunnel/internal/names"
	"tunnel/internal/streamconn"
	"tunnel/internal/wire"
)

type rawListener struct {
	client         *Client
	id, name, mode string
	tlsConfig      *tls.Config
	handshakes     map[*streamconn.Conn]bool
	mu             sync.Mutex
	queue          []net.Conn
	changed        chan struct{}
	closed         bool
	draining       bool
	err            error
}

func (l *rawListener) signal() { close(l.changed); l.changed = make(chan struct{}) }
func (l *rawListener) Accept() (net.Conn, error) {
	for {
		l.mu.Lock()
		if l.closed {
			err := l.err
			l.mu.Unlock()
			return nil, err
		}
		if len(l.queue) > 0 {
			conn := l.queue[0]
			l.queue = l.queue[1:]
			l.mu.Unlock()
			return conn, nil
		}
		if l.draining {
			l.mu.Unlock()
			return nil, net.ErrClosed
		}
		changed := l.changed
		l.mu.Unlock()
		<-changed
	}
}
func (l *rawListener) Addr() net.Addr {
	port := ":443"
	if l.mode == "http" {
		port = ":80"
	}
	return tunnelAddr(l.name + port)
}
func closeQueued(conn net.Conn) {
	if c, ok := conn.(*streamconn.Conn); ok {
		c.Abort()
	} else {
		_ = conn.Close()
	}
}
func (l *rawListener) stop(err error) {
	l.mu.Lock()
	if l.closed {
		l.mu.Unlock()
		return
	}
	l.closed = true
	l.err = err
	queue := l.queue
	l.queue = nil
	handshakes := []*streamconn.Conn{}
	for conn := range l.handshakes {
		handshakes = append(handshakes, conn)
	}
	l.signal()
	l.mu.Unlock()
	for _, conn := range handshakes {
		conn.Abort()
	}
	for _, conn := range queue {
		closeQueued(conn)
	}
}
func (l *rawListener) clearQueue() {
	l.mu.Lock()
	queue := l.queue
	l.queue = nil
	l.signal()
	l.mu.Unlock()
	for _, conn := range queue {
		closeQueued(conn)
	}
}
func (l *rawListener) Close() error {
	l.client.ops.Lock()
	defer l.client.ops.Unlock()
	l.stop(net.ErrClosed)
	l.client.mu.Lock()
	delete(l.client.listeners, l.id)
	s := l.client.session
	status := l.client.status
	l.client.mu.Unlock()
	if status != "connected" && status != "draining" {
		return nil
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	_, err := l.client.unadvertise(ctx, s, l.id)
	return err
}
func (l *rawListener) deliver(conn net.Conn) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.closed || l.draining || len(l.queue) >= 64 {
		return false
	}
	l.queue = append(l.queue, conn)
	l.signal()
	return true
}

type tunnelAddr string

func (a tunnelAddr) Network() string                          { return "tcp" }
func (a tunnelAddr) String() string                           { return string(a) }
func (c *Client) ListenRaw(ctx context.Context, name string) (net.Listener, error) {
	return c.listen(ctx, name, "raw", nil)
}

// ListenHTTP opts into one-shot plaintext HTTP, independently of TLS listeners.
func (c *Client) ListenHTTP(ctx context.Context, name string) (net.Listener, error) {
	return c.listen(ctx, name, "http", nil)
}
func (c *Client) listen(ctx context.Context, name, mode string, config *tls.Config) (net.Listener, error) {
	name, err := canonicalName(name)
	if err != nil {
		return nil, err
	}
	c.mu.Lock()
	ready := c.status == "connected" && c.terminal == nil
	c.mu.Unlock()
	if !ready {
		return nil, errors.New("client is not connected or is draining")
	}
	c.ops.Lock()
	defer c.ops.Unlock()
	c.mu.Lock()
	if c.terminal != nil {
		err := c.terminal
		c.mu.Unlock()
		return nil, err
	}
	if c.status != "connected" {
		c.mu.Unlock()
		return nil, errors.New("client is not connected or is draining")
	}
	s := c.session
	for _, other := range c.listeners {
		if other.name == name && (other.mode == "http") == (mode == "http") {
			c.mu.Unlock()
			return nil, errors.New("name already listening")
		}
	}
	var nonce [16]byte
	if _, err = rand.Read(nonce[:]); err != nil {
		c.mu.Unlock()
		return nil, fmt.Errorf("generate listener nonce: %w", err)
	}
	l := &rawListener{client: c, id: hex.EncodeToString(nonce[:]), name: name, mode: mode, tlsConfig: config, changed: make(chan struct{}), handshakes: map[*streamconn.Conn]bool{}}
	c.listeners[l.id] = l
	c.mu.Unlock()
	advertiseCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	if err := c.advertise(advertiseCtx, s, l); err != nil {
		c.mu.Lock()
		delete(c.listeners, l.id)
		c.mu.Unlock()
		l.stop(err)
		return nil, err
	}
	return l, nil
}
func (c *Client) advertise(ctx context.Context, s *clientSession, l *rawListener) error {
	for attempt := 0; attempt < 3; attempt++ {
		data, err := c.rpcSession(ctx, s, &wire.Envelope{Type: "RouteList"})
		if err != nil {
			return err
		}
		var routes wire.RouteList
		if err = decodeRoutes(data, &routes); err != nil {
			return err
		}
		if !allowed(routes, l.name) {
			return errors.New("listener name is not authorized")
		}
		data, err = c.rpcSession(ctx, s, &wire.Advertise{Envelope: wire.Envelope{Type: "Advertise"}, ListenerID: l.id, Name: l.name, Mode: l.mode, Revision: routes.Revision})
		if err != nil {
			return err
		}
		var ack wire.AdvertiseAck
		if err = wire.DecodeFrame(data, &ack, "type", "id", "listener_id", "name", "mode", "revision", "ok", "code", "error"); err != nil {
			return fmt.Errorf("decode advertise acknowledgement: %w", err)
		}
		if ack.Type != "AdvertiseAck" || ack.ListenerID != l.id || ack.Name != l.name || ack.Mode != l.mode {
			return errors.New("mismatched AdvertiseAck")
		}
		if ack.OK {
			c.mu.Lock()
			live := c.session == s && c.listeners[l.id] == l && c.terminal == nil
			c.mu.Unlock()
			if !live {
				return errors.New("listener closed during advertisement")
			}
			return nil
		}
		if ack.Code != "stale_routes" {
			return errors.New("advertise rejected: " + ack.Error)
		}
	}
	return errors.New("authorization changed repeatedly while advertising")
}
func (c *Client) acceptStreams(ctx context.Context, s *clientSession) {
	for {
		stream, err := s.conn.AcceptStream(ctx)
		if err != nil {
			s.drop(err)
			return
		}
		c.mu.Lock()
		if c.session != s || c.terminal != nil {
			c.mu.Unlock()
			stream.CancelRead(5)
			stream.CancelWrite(5)
			continue
		}
		c.receiving++
		c.acceptedStream = int64(stream.StreamID())
		c.signalLocked()
		c.mu.Unlock()
		go func() {
			defer func() { c.mu.Lock(); c.receiving--; c.signalLocked(); c.mu.Unlock() }()
			reject := func() { stream.CancelRead(3); stream.CancelWrite(3) }
			if err := stream.SetReadDeadline(time.Now().Add(10 * time.Second)); err != nil {
				reject()
				return
			}
			h, err := wire.ReadDataHeader(stream)
			if clearErr := stream.SetReadDeadline(time.Time{}); clearErr != nil {
				reject()
				return
			}
			if err != nil || h.Scheme != "tls" && h.Scheme != "http" {
				reject()
				return
			}
			remote, err := netip.ParseAddrPort(h.RemoteAddr)
			if err != nil || !names.Valid(h.Name) {
				reject()
				return
			}
			revision, err := wire.Counter(h.Revision)
			if err != nil {
				reject()
				return
			}
			c.mu.Lock()
			current, _ := wire.Counter(c.routes.Revision)
			c.mu.Unlock()
			if revision > current {
				routeCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
				_, err = c.rpcSession(routeCtx, s, &wire.Envelope{Type: "RouteList"})
				cancel()
				if err != nil {
					reject()
					return
				}
			}
			c.mu.Lock()
			l := c.listeners[h.ListenerID]
			routes := c.routes
			if c.session != s || c.terminal != nil || l == nil || (l.mode == "http") != (h.Scheme == "http") || !allowed(routes, h.Name) || !names.Covers(h.Name, l.name) {
				c.mu.Unlock()
				reject()
				return
			}
			conn := &streamconn.Conn{Stream: stream, Local: l.Addr(), Remote: net.TCPAddrFromAddrPort(remote)}
			conn.OnClose = func() { c.mu.Lock(); delete(c.active, conn); c.signalLocked(); c.mu.Unlock() }
			c.active[conn] = true
			c.signalLocked()
			c.mu.Unlock()
			l.receive(ctx, conn, h.Name)
		}()
	}
}

package tunnel

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"math/rand/v2"
	"net"
	"sort"
	"strconv"
	"sync"
	"time"

	"github.com/fasmide/tunnel/internal/names"
	"github.com/fasmide/tunnel/internal/streamconn"
	"github.com/fasmide/tunnel/internal/wire"
	quic "github.com/quic-go/quic-go"
	"golang.org/x/crypto/acme"
	"golang.org/x/crypto/acme/autocert"
	"golang.org/x/net/idna"
)

type Option func(*dialOptions) error

type dialOptions struct {
	credentials Credentials
	tls         *tls.Config
	acme        *acme.Client
	email       string
	acmeError   func(string, error)
}

var ErrIdentityNotApproved = errors.New("identity is not approved for forwarding")
var ErrIdentityRevoked = errors.New("identity revoked")

func WithCredentials(c Credentials) Option {
	return func(o *dialOptions) error {
		if c.PublicKey() == nil {
			return errors.New("invalid credentials")
		}
		o.credentials = c
		return nil
	}
}

// WithTLSConfig supplies server trust roots/ServerName. Verification is required.
func WithTLSConfig(config *tls.Config) Option {
	return func(o *dialOptions) error {
		if config == nil || config.InsecureSkipVerify {
			return errors.New("verified TLS configuration required")
		}
		o.tls = config.Clone()
		return nil
	}
}

type clientSession struct {
	conn    *quic.Conn
	control *quic.Stream
	rpcMu   sync.Mutex
	mu      sync.Mutex
	nextID  uint64
	pending map[string]chan rpcResult
	done    chan struct{}
	once    sync.Once
	err     error
	started time.Time
}
type rpcResult struct {
	data []byte
	err  error
}
type Client struct {
	mu             sync.Mutex
	ops            sync.Mutex // serializes listener lifecycle, re-advertise and drain
	session        *clientSession
	listeners      map[string]*rawListener
	routes         wire.RouteList
	status         string
	terminal       error
	done           chan struct{}
	changed        chan struct{}
	once           sync.Once
	ctx            context.Context
	cancel         context.CancelFunc
	addr           string
	options        dialOptions
	active         map[*streamconn.Conn]bool
	receiving      int
	acceptedStream int64
	acmeMu         sync.Mutex
	acmeManager    *autocert.Manager
	storage        Storage
	acmeClient     *acme.Client
	acmeEmail      string
}

// Dial retries transient connection failures until ctx expires. ctx bounds setup;
// the returned Client reconnects independently until explicitly closed/denied.
func Dial(ctx context.Context, addr string, options ...Option) (*Client, error) {
	o := dialOptions{tls: &tls.Config{}}
	for _, opt := range options {
		if opt == nil {
			return nil, errors.New("nil dial option")
		}
		if err := opt(&o); err != nil {
			return nil, err
		}
	}
	if o.credentials.PublicKey() == nil {
		return nil, errors.New("credentials required")
	}
	life, cancel := context.WithCancel(context.WithoutCancel(ctx))
	c := &Client{listeners: map[string]*rawListener{}, status: "connecting", done: make(chan struct{}), changed: make(chan struct{}), ctx: life, cancel: cancel, addr: addr, options: o, active: map[*streamconn.Conn]bool{}, acceptedStream: -1, storage: o.credentials.storage, acmeClient: o.acme, acmeEmail: o.email}
	for attempt := 0; ; attempt++ {
		session, routes, err, permanent := c.connect(ctx)
		if err == nil {
			c.install(life, session, routes)
			go c.supervise(life)
			return c, nil
		}
		if permanent || ctx.Err() != nil {
			cancel()
			return nil, err
		}
		if err = waitBackoff(ctx, attempt); err != nil {
			cancel()
			return nil, err
		}
	}
}
func (c *Client) connect(ctx context.Context) (*clientSession, wire.RouteList, error, bool) {
	config := c.options.tls.Clone()
	cert, err := c.options.credentials.identityCertificate(time.Now())
	if err != nil {
		return nil, wire.RouteList{}, err, true
	}
	config.Certificates = []tls.Certificate{cert}
	config.GetClientCertificate = nil
	config.NextProtos = []string{wire.ALPN}
	config.MinVersion = tls.VersionTLS13
	config.MaxVersion = tls.VersionTLS13
	config.ClientSessionCache = nil
	attempt, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	conn, err := quic.DialAddr(attempt, c.addr, config, &quic.Config{Versions: []quic.Version{quic.Version1}, MaxIdleTimeout: 30 * time.Second, KeepAlivePeriod: 10 * time.Second, MaxIncomingStreams: 256, MaxIncomingUniStreams: -1})
	if err != nil {
		return nil, wire.RouteList{}, fmt.Errorf("dial QUIC tunnel %s: %w", c.addr, err), trustFailure(err)
	}
	success := false
	defer func() {
		if !success {
			_ = conn.CloseWithError(0, "setup failed")
		}
	}()
	control, err := conn.OpenStreamSync(attempt)
	if err != nil {
		return nil, wire.RouteList{}, fmt.Errorf("open control stream: %w", err), false
	}
	stop := context.AfterFunc(attempt, func() { _ = conn.CloseWithError(0, "setup canceled") })
	defer stop()
	if err := control.SetDeadline(time.Now().Add(10 * time.Second)); err != nil {
		return nil, wire.RouteList{}, fmt.Errorf("set initial control deadline: %w", err), false
	}
	if err = wire.WriteFrame(control, wire.Envelope{Type: "RouteList", ID: "1"}); err != nil {
		return nil, wire.RouteList{}, fmt.Errorf("write initial route list request: %w", err), false
	}
	data, err := wire.ReadFrame(control)
	if err != nil {
		return nil, wire.RouteList{}, fmt.Errorf("read initial route list response: %w", err), deniedTransport(err)
	}
	var env wire.Envelope
	if err = wire.DecodeFrame(data, &env, "type", "id"); err != nil {
		return nil, wire.RouteList{}, fmt.Errorf("decode initial route list envelope: %w", err), true
	}
	if env.Type == "Revoked" {
		return nil, wire.RouteList{}, ErrIdentityRevoked, true
	}
	var routes wire.RouteList
	if err = decodeRoutes(data, &routes); err != nil {
		return nil, routes, err, true
	}
	if routes.ID != "1" || routes.Identity != c.options.credentials.Identity() || routes.Status != "approved" {
		return nil, routes, ErrIdentityNotApproved, true
	}
	if err := control.SetDeadline(time.Time{}); err != nil {
		return nil, wire.RouteList{}, fmt.Errorf("clear control deadline: %w", err), false
	}
	success = true
	return &clientSession{conn: conn, control: control, nextID: 1, pending: map[string]chan rpcResult{}, done: make(chan struct{}), started: time.Now()}, routes, nil, false
}
func trustFailure(err error) bool {
	var verification *tls.CertificateVerificationError
	var unknown x509.UnknownAuthorityError
	var hostname x509.HostnameError
	return errors.As(err, &verification) || errors.As(err, &unknown) || errors.As(err, &hostname)
}
func deniedTransport(err error) bool {
	var app *quic.ApplicationError
	return errors.As(err, &app) && (app.ErrorCode == 1 || app.ErrorCode == 2)
}
func waitBackoff(ctx context.Context, attempt int) error {
	cap := 250 * time.Millisecond
	for i := 0; i < attempt && cap < 30*time.Second; i++ {
		cap *= 2
	}
	if cap > 30*time.Second {
		cap = 30 * time.Second
	}
	timer := time.NewTimer(time.Duration(rand.Int64N(int64(cap) + 1)))
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return fmt.Errorf("backoff canceled: %w", ctx.Err())
	case <-timer.C:
		return nil
	}
}
func (c *Client) signalLocked() { close(c.changed); c.changed = make(chan struct{}) }
func (c *Client) install(ctx context.Context, s *clientSession, r wire.RouteList) {
	c.mu.Lock()
	c.session = s
	c.routes = r
	c.acceptedStream = -1
	c.signalLocked()
	c.mu.Unlock()
	c.applyRoutes(s, r)
	go c.readControl(s)
	go c.acceptStreams(ctx, s)
	c.mu.Lock()
	if c.terminal == nil {
		c.status = "connected"
	}
	c.signalLocked()
	c.mu.Unlock()
}
func (c *Client) supervise(ctx context.Context) {
	attempt := 0
	for {
		c.mu.Lock()
		s := c.session
		c.mu.Unlock()
		select {
		case <-c.done:
			return
		case <-s.done:
		}
		c.mu.Lock()
		if c.terminal != nil {
			c.mu.Unlock()
			return
		}
		if c.status == "draining" {
			c.mu.Unlock()
			c.fail(s.err)
			return
		}
		if deniedTransport(s.err) {
			c.mu.Unlock()
			c.deny(s.err)
			return
		}
		c.status = "reconnecting"
		c.signalLocked()
		c.mu.Unlock()
		c.abortSessionStreams()
		if time.Since(s.started) >= 30*time.Second {
			attempt = 0
		}
		for {
			if err := waitBackoff(ctx, attempt); err != nil {
				return
			}
			attempt++
			next, r, err, permanent := c.connect(ctx)
			if err != nil {
				if permanent {
					c.deny(err)
					return
				}
				continue
			}
			c.ops.Lock()
			c.mu.Lock()
			closed := c.terminal != nil || c.status == "draining"
			c.mu.Unlock()
			if closed {
				_ = next.conn.CloseWithError(0, "client stopping")
				c.ops.Unlock()
				return
			}
			c.install(ctx, next, r)
			c.mu.Lock()
			c.status = "reconnecting"
			listeners := []*rawListener{}
			for _, l := range c.listeners {
				listeners = append(listeners, l)
			}
			c.mu.Unlock()
			for _, l := range listeners {
				if err := c.advertise(ctx, next, l); err != nil {
					select {
					case <-next.done:
					default:
						c.mu.Lock()
						delete(c.listeners, l.id)
						c.mu.Unlock()
						l.stop(err)
					}
				}
			}
			c.mu.Lock()
			if c.terminal == nil {
				c.status = "connected"
			}
			c.signalLocked()
			c.mu.Unlock()
			c.ops.Unlock()
			break
		}
	}
}
func (c *Client) rpc(ctx context.Context, message any) ([]byte, error) {
	c.mu.Lock()
	s := c.session
	err := c.terminal
	c.mu.Unlock()
	if err != nil {
		return nil, err
	}
	if s == nil {
		return nil, net.ErrClosed
	}
	return c.rpcSession(ctx, s, message)
}
func (s *clientSession) drop(err error) {
	s.once.Do(func() {
		s.mu.Lock()
		s.err = err
		s.mu.Unlock()
		close(s.done)
		_ = s.conn.CloseWithError(0, "session lost")
	})
}
func (c *Client) rpcSession(ctx context.Context, s *clientSession, message any) ([]byte, error) {
	s.rpcMu.Lock()
	defer s.rpcMu.Unlock()
	if err := ctx.Err(); err != nil {
		return nil, fmt.Errorf("RPC canceled before send: %w", err)
	}
	select {
	case <-s.done:
		return nil, s.err
	default:
	}
	s.mu.Lock()
	s.nextID++
	id := strconv.FormatUint(s.nextID, 10)
	result := make(chan rpcResult, 1)
	s.pending[id] = result
	s.mu.Unlock()
	defer func() { s.mu.Lock(); delete(s.pending, id); s.mu.Unlock() }()
	var expected string
	switch v := message.(type) {
	case *wire.Envelope:
		v.ID = id
		expected = v.Type
		if expected == "Ping" {
			expected = "Pong"
		}
	case *wire.Advertise:
		v.ID = id
		expected = "AdvertiseAck"
	case *wire.IssueCertificate:
		v.ID = id
		expected = "CertificateResult"
	case *wire.Unadvertise:
		v.ID = id
		expected = "Unadvertise"
	default:
		return nil, errors.New("unsupported RPC")
	}
	deadline := time.Now().Add(10 * time.Second)
	if d, ok := ctx.Deadline(); ok && d.Before(deadline) {
		deadline = d
	}
	if err := s.control.SetWriteDeadline(deadline); err != nil {
		wrapped := fmt.Errorf("set control write deadline: %w", err)
		s.drop(wrapped)
		return nil, wrapped
	}
	stop := context.AfterFunc(ctx, func() { s.drop(ctx.Err()) })
	defer stop()
	if err := wire.WriteFrame(s.control, message); err != nil {
		wrapped := fmt.Errorf("write control frame: %w", err)
		s.drop(wrapped)
		return nil, wrapped
	}
	timer := time.NewTimer(time.Until(deadline))
	defer timer.Stop()
	select {
	case r := <-result:
		var env wire.Envelope
		if err := wire.Decode(r.data, &env, "type", "id"); err != nil {
			return nil, fmt.Errorf("decode RPC response envelope: %w", err)
		}
		if env.Type != expected {
			return nil, errors.New("unexpected response type")
		}
		return r.data, r.err
	case <-ctx.Done():
		wrapped := fmt.Errorf("RPC canceled while waiting for response: %w", ctx.Err())
		s.drop(wrapped)
		return nil, wrapped
	case <-timer.C:
		err := errors.New("control response deadline exceeded")
		s.drop(err)
		return nil, err
	case <-s.done:
		return nil, s.err
	case <-c.done:
		c.mu.Lock()
		err := c.terminal
		c.mu.Unlock()
		if err != nil {
			return nil, fmt.Errorf("client closed while waiting for RPC response: %w", err)
		}
		return nil, net.ErrClosed
	}
}
func decodeRoutes(data []byte, r *wire.RouteList) error {
	if err := wire.DecodeFrame(data, r, "type", "id", "identity", "status", "routes", "exclusions", "revision", "withdrawn", "error"); err != nil {
		return fmt.Errorf("decode route list: %w", err)
	}
	if r.Type != "RouteList" {
		return errors.New("expected RouteList")
	}
	if _, err := wire.Counter(r.Revision); err != nil {
		return fmt.Errorf("parse route revision: %w", err)
	}
	for _, name := range append(append([]string{}, r.Routes...), r.Exclusions...) {
		if !names.Valid(name) {
			return errors.New("invalid route snapshot")
		}
	}
	return nil
}
func (c *Client) readControl(s *clientSession) {
	for {
		var first [1]byte
		if err := s.control.SetReadDeadline(time.Time{}); err != nil {
			s.drop(err)
			return
		}
		if _, err := io.ReadFull(s.control, first[:]); err != nil {
			s.drop(err)
			return
		}
		if err := s.control.SetReadDeadline(time.Now().Add(10 * time.Second)); err != nil {
			s.drop(err)
			return
		}
		data, err := wire.ReadFrame(io.MultiReader(&byteReader{b: first[0]}, s.control))
		if err != nil {
			// A connection loss halfway through a frame is transient too; JSON
			// validation errors on a healthy connection remain protocol failures.
			var network net.Error
			if errors.As(err, &network) || errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) || s.conn.Context().Err() != nil {
				s.drop(err)
			} else {
				c.deny(err)
			}
			return
		}
		var env wire.Envelope
		if err := wire.DecodeFrame(data, &env, "type", "id"); err != nil {
			c.deny(err)
			return
		}
		c.mu.Lock()
		current := c.session == s
		c.mu.Unlock()
		if !current {
			return
		}
		if env.Type == "Revoked" {
			c.deny(errors.New("identity revoked"))
			return
		}
		if env.Type == "RouteList" {
			var r wire.RouteList
			if err := decodeRoutes(data, &r); err != nil {
				c.deny(err)
				return
			}
			if r.Status != "approved" {
				c.deny(errors.New("identity no longer approved"))
				return
			}
			c.applyRoutes(s, r)
		}
		if env.ID == "" {
			if env.Type != "RouteList" {
				c.deny(errors.New("unexpected event"))
				return
			}
			continue
		}
		s.mu.Lock()
		pending := s.pending[env.ID]
		s.mu.Unlock()
		if pending == nil {
			select {
			case <-s.done:
				return
			default:
			}
			c.deny(errors.New("unexpected response ID"))
			return
		}
		select {
		case pending <- rpcResult{data: data}:
		default:
			c.deny(errors.New("duplicate response"))
			return
		}
	}
}
func (c *Client) applyRoutes(s *clientSession, r wire.RouteList) {
	c.mu.Lock()
	if c.session != s {
		c.mu.Unlock()
		return
	}
	old, _ := wire.Counter(c.routes.Revision)
	revision, _ := wire.Counter(r.Revision)
	if revision < old {
		c.mu.Unlock()
		return
	}
	c.routes = r
	closed := []*rawListener{}
	for _, l := range c.listeners {
		if !allowed(r, l.name) {
			delete(c.listeners, l.id)
			closed = append(closed, l)
		}
	}
	c.mu.Unlock()
	for _, l := range closed {
		l.stop(errors.New("listener route is no longer authorized"))
	}
}
func allowed(r wire.RouteList, name string) bool {
	if r.Status != "approved" {
		return false
	}
	longest, excluded := -1, -1
	for _, root := range r.Routes {
		if names.Covers(name, root) && len(root) > longest {
			longest = len(root)
		}
	}
	for _, root := range r.Exclusions {
		if names.Covers(name, root) && len(root) > excluded {
			excluded = len(root)
		}
	}
	return longest >= 0 && longest > excluded
}
func canonicalName(name string) (string, error) {
	name, err := idna.Lookup.ToASCII(name)
	if err != nil {
		return "", fmt.Errorf("canonicalize listener name: %w", err)
	}
	if len(name) > 0 && name[len(name)-1] == '.' {
		name = name[:len(name)-1]
	}
	if !names.Valid(name) {
		return "", errors.New("invalid listener name")
	}
	return name, nil
}
func (c *Client) Routes() []string {
	c.mu.Lock()
	defer c.mu.Unlock()
	return append([]string{}, c.routes.Routes...)
}
func (c *Client) Listening() []string {
	c.mu.Lock()
	defer c.mu.Unlock()
	out := []string{}
	for _, l := range c.listeners {
		out = append(out, l.name)
	}
	sort.Strings(out)
	return out
}
func (c *Client) Status() string { c.mu.Lock(); defer c.mu.Unlock(); return c.status }
func (c *Client) Close() error   { c.fail(net.ErrClosed); return nil }
func (c *Client) deny(err error) { c.finish(err, "denied") }
func (c *Client) fail(err error) { c.finish(err, "closed") }
func (c *Client) finish(err error, status string) {
	c.once.Do(func() {
		c.mu.Lock()
		c.terminal = err
		c.status = status
		listeners := c.listeners
		c.listeners = map[string]*rawListener{}
		s := c.session
		close(c.done)
		c.signalLocked()
		c.mu.Unlock()
		c.cancel()
		if s != nil {
			s.drop(err)
		}
		c.abortSessionStreams()
		for _, l := range listeners {
			l.stop(err)
		}
	})
}
func (c *Client) abortSessionStreams() {
	c.mu.Lock()
	active := []*streamconn.Conn{}
	for conn := range c.active {
		active = append(active, conn)
	}
	listeners := []*rawListener{}
	for _, l := range c.listeners {
		listeners = append(listeners, l)
	}
	c.mu.Unlock()
	for _, conn := range active {
		conn.Abort()
	}
	for _, l := range listeners {
		l.clearQueue()
	}
}

type byteReader struct {
	b    byte
	used bool
}

func (r *byteReader) Read(p []byte) (int, error) {
	if r.used {
		return 0, io.EOF
	}
	if len(p) == 0 {
		return 0, nil
	}
	p[0] = r.b
	r.used = true
	return 1, nil
}

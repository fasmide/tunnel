package server

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"strconv"
	"sync"
	"time"

	quic "github.com/quic-go/quic-go"
	"tunnel/internal/transportpki"
	"tunnel/internal/wire"
)

const frameTimeout = 10 * time.Second

// Server owns the tunnel-facing QUIC listener and public TLS passthrough edges.
// Join storage, the plain-HTTP edge, and admin CLIs are delivered separately.
type Server struct {
	listener    *quic.Listener
	manager     *Manager
	ctx         context.Context
	cancel      context.CancelFunc
	wg          sync.WaitGroup
	slots       chan struct{}
	once        sync.Once
	limitMu     sync.Mutex
	perIP       map[string]int
	perKey      map[string]int
	edgeMu      sync.Mutex
	edges       map[*TLSEdge]bool
	closing     bool
	closeErr    error
	joins       map[string]joinRate
	globalJoins joinRate
	issuer      *transportpki.Authority
}
type joinRate struct {
	window time.Time
	count  int
}

func (s *Server) allowJoin(ip string) bool {
	s.limitMu.Lock()
	defer s.limitMu.Unlock()
	now := time.Now()
	if now.Sub(s.globalJoins.window) >= time.Minute {
		s.globalJoins = joinRate{window: now}
	}
	r := s.joins[ip]
	if now.Sub(r.window) >= time.Minute {
		r = joinRate{window: now}
	}
	if r.count >= 30 || s.globalJoins.count >= 300 {
		return false
	}
	if len(s.joins) >= 4096 {
		for key, v := range s.joins {
			if now.Sub(v.window) >= time.Minute {
				delete(s.joins, key)
			}
		}
		if len(s.joins) >= 4096 {
			return false
		}
	}
	r.count++
	s.joins[ip] = r
	s.globalJoins.count++
	return true
}

// Listen binds the tunnel endpoint and starts accepting connections. Connections
// are bounded globally (256) and by source IP / identity (16 each). Configuration
// for those limits will accompany the daemon CLI.
func Listen(addr string, tlsConfig *tls.Config, manager *Manager) (*Server, error) {
	return listen(addr, tlsConfig, manager, nil)
}

// ListenWithAuthority enables authenticated private certificate issuance.
func ListenWithAuthority(addr string, tlsConfig *tls.Config, manager *Manager, issuer *transportpki.Authority) (*Server, error) {
	return listen(addr, tlsConfig, manager, issuer)
}
func listen(addr string, tlsConfig *tls.Config, manager *Manager, issuer *transportpki.Authority) (*Server, error) {
	if manager == nil {
		return nil, errors.New("nil pool manager")
	}
	config, err := serverTLS(tlsConfig)
	if err != nil {
		return nil, err
	}
	listener, err := quic.ListenAddr(addr, config, &quic.Config{
		Versions:              []quic.Version{quic.Version1},
		MaxIdleTimeout:        30 * time.Second,
		KeepAlivePeriod:       10 * time.Second,
		MaxIncomingStreams:    2, // allow one extra so misuse is observable and rejected
		MaxIncomingUniStreams: -1,
		Allow0RTT:             false,
		EnableDatagrams:       false,
	})
	if err != nil {
		return nil, fmt.Errorf("listen QUIC server: %w", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	s := &Server{listener: listener, manager: manager, ctx: ctx, cancel: cancel, slots: make(chan struct{}, 256), perIP: map[string]int{}, perKey: map[string]int{}, edges: map[*TLSEdge]bool{}, joins: map[string]joinRate{}, issuer: issuer}
	s.wg.Add(1)
	go s.accept()
	return s, nil
}

func (s *Server) Addr() string { return s.listener.Addr().String() }
func (s *Server) Close() error {
	s.once.Do(func() {
		s.edgeMu.Lock()
		s.closing = true
		edges := make([]*TLSEdge, 0, len(s.edges))
		for edge := range s.edges {
			edges = append(edges, edge)
		}
		s.edgeMu.Unlock()
		s.cancel()
		s.closeErr = s.listener.Close()
		for _, edge := range edges {
			_ = edge.Close()
		}
	})
	s.wg.Wait()
	return s.closeErr
}

func (s *Server) accept() {
	defer s.wg.Done()
	for {
		conn, err := s.listener.Accept(s.ctx)
		if err != nil {
			return
		}
		select {
		case s.slots <- struct{}{}:
			s.wg.Add(1)
			go func() { defer s.wg.Done(); defer func() { <-s.slots }(); s.handle(conn) }()
		default:
			_ = conn.CloseWithError(4, "connection limit reached")
		}
	}
}

func (s *Server) handle(conn *quic.Conn) {
	defer func() { _ = conn.CloseWithError(0, "session ended") }()
	ctx, cancel := context.WithCancel(conn.Context())
	defer cancel()
	go func() {
		select {
		case <-s.ctx.Done():
			_ = conn.CloseWithError(0, "server shutdown")
		case <-ctx.Done():
		}
	}()
	peers := conn.ConnectionState().TLS.PeerCertificates
	if len(peers) != 1 {
		_ = conn.CloseWithError(2, "missing identity certificate")
		return
	}
	pub, err := verifyIdentity([][]byte{peers[0].Raw}, time.Now())
	if err != nil {
		_ = conn.CloseWithError(2, err.Error())
		return
	}
	ip, _, err := net.SplitHostPort(conn.RemoteAddr().String())
	if err != nil {
		_ = conn.CloseWithError(1, "invalid peer address")
		return
	}
	identity := Identity(pub)
	s.limitMu.Lock()
	if s.perIP[ip] >= 16 || s.perKey[identity] >= 16 {
		s.limitMu.Unlock()
		_ = conn.CloseWithError(4, "source or identity connection limit")
		return
	}
	s.perIP[ip]++
	s.perKey[identity]++
	s.limitMu.Unlock()
	defer func() {
		s.limitMu.Lock()
		defer s.limitMu.Unlock()
		s.perIP[ip]--
		s.perKey[identity]--
		if s.perIP[ip] == 0 {
			delete(s.perIP, ip)
		}
		if s.perKey[identity] == 0 {
			delete(s.perKey, identity)
		}
	}()
	firstCtx, firstCancel := context.WithTimeout(ctx, frameTimeout)
	control, err := conn.AcceptStream(firstCtx)
	firstCancel()
	if err != nil {
		_ = conn.CloseWithError(4, "control stream deadline")
		return
	}
	if control.StreamID() != 0 {
		_ = conn.CloseWithError(1, "control must be stream 0")
		return
	}
	go func() {
		if _, err := conn.AcceptStream(ctx); err == nil {
			_ = conn.CloseWithError(1, "extra client stream forbidden")
		}
	}()
	id, updates := s.manager.connect(pub, func() { _ = conn.CloseWithError(2, "identity revoked or slow control consumer") })
	s.manager.mu.Lock()
	s.manager.sessions[id].conn = conn
	s.manager.sessions[id].active = map[*forwarding]bool{}
	s.manager.mu.Unlock()
	defer s.manager.Disconnect(id)
	var writeMu sync.Mutex
	send := func(value any) error {
		writeMu.Lock()
		defer writeMu.Unlock()
		timeout := frameTimeout
		if _, revoked := value.(wire.Revoked); revoked {
			timeout = time.Second
		}
		if err := control.SetWriteDeadline(time.Now().Add(timeout)); err != nil {
			return fmt.Errorf("set control write deadline: %w", err)
		}
		if err := wire.WriteFrame(control, value); err != nil {
			return fmt.Errorf("write control frame: %w", err)
		}
		return nil
	}
	// Events are bounded and never block authorization/pool mutations.
	go func() {
		for {
			select {
			case <-ctx.Done():
				return
			case event := <-updates:
				if _, revoked := event.(wire.Revoked); revoked {
					_ = send(event)
					_ = conn.CloseWithError(2, "identity revoked")
					return
				}
				if err := send(event); err != nil {
					_ = conn.CloseWithError(5, "control event write failed")
					return
				}
			}
		}
	}()
	if err := control.SetReadDeadline(time.Now().Add(frameTimeout)); err != nil {
		return
	}
	var lastID uint64
	first := true
	for {
		// Wait indefinitely for the first byte after initialization. Once a frame
		// begins, bound the entire prefix/payload read by a fresh deadline.
		var initial [1]byte
		if _, err := io.ReadFull(control, initial[:]); err != nil {
			return
		}
		if err := control.SetReadDeadline(time.Now().Add(frameTimeout)); err != nil {
			return
		}
		data, err := wire.ReadFrame(io.MultiReader(&oneByteReader{value: initial[0]}, control))
		if err != nil {
			_ = conn.CloseWithError(1, err.Error())
			return
		}
		if err := control.SetReadDeadline(time.Time{}); err != nil {
			return
		}
		var envelope wire.Envelope
		if err := wire.DecodeFrame(data, &envelope, "type", "id"); err != nil {
			_ = conn.CloseWithError(1, err.Error())
			return
		}
		counter, err := wire.Counter(envelope.ID)
		if err != nil || counter == 0 || counter <= lastID {
			_ = conn.CloseWithError(1, "invalid request ID")
			return
		}
		lastID = counter
		if first && (counter != 1 || envelope.Type != "RouteList" && envelope.Type != "Join") {
			_ = conn.CloseWithError(1, "first request must be RouteList or Join with ID 1")
			return
		}
		first = false
		snapshot, revoked := s.manager.Snapshot(id, envelope.ID)
		if revoked {
			_ = send(wire.Revoked{Envelope: wire.Envelope{Type: "Revoked", ID: ""}, Identity: snapshot.Identity, Revision: snapshot.Revision, Reason: "identity revoked"})
			_ = conn.CloseWithError(2, "identity revoked")
			return
		}
		switch envelope.Type {
		case "RouteList":
			err = send(snapshot)
		case "Ping":
			s.manager.mu.Lock()
			active := len(s.manager.sessions[id].active)
			s.manager.mu.Unlock()
			err = send(wire.Pong{Envelope: wire.Envelope{Type: "Pong", ID: envelope.ID}, ActiveStreams: strconv.Itoa(active)})
		case "Advertise":
			var a wire.Advertise
			if err = wire.DecodeFrame(data, &a, "listener_id", "name", "mode", "revision"); err == nil {
				err = send(s.manager.Advertise(id, a))
			}
		case "Unadvertise":
			var u wire.Unadvertise
			if err = wire.DecodeFrame(data, &u, "listener_id", "ack"); err == nil {
				if u.Ack || !validListenerID(u.ListenerID) {
					err = errors.New("invalid Unadvertise request")
				} else {
					u.LastStreamID = s.manager.Unadvertise(id, u.ListenerID)
					u.Ack = true
					err = send(u)
				}
			}
		case "IssueCertificate":
			var request wire.IssueCertificate
			if err = wire.DecodeFrame(data, &request, "name", "csr"); err == nil {
				err = send(s.manager.issueCertificate(id, request, s.issuer))
			}
		case "Join":
			if !s.allowJoin(ip) {
				err = send(wire.JoinResult{Envelope: wire.Envelope{Type: "JoinResult", ID: envelope.ID}, Status: "error", Code: "rate_limited", Error: "join rate limit", Routes: snapshot.Routes, Revision: snapshot.Revision})
				break
			}
			j, decodeErr := wire.DecodeJoin(data)
			if decodeErr != nil {
				err = send(wire.JoinResult{Envelope: wire.Envelope{Type: "JoinResult", ID: envelope.ID}, Status: "error", Code: "invalid_request", Error: decodeErr.Error(), Routes: snapshot.Routes, Revision: snapshot.Revision})
			} else {
				err = send(s.manager.SubmitJoin(pub, j))
			}
		default:
			err = errors.New("unsupported client message type: " + envelope.Type)
		}
		if err != nil {
			_ = conn.CloseWithError(1, err.Error())
			return
		}
	}
}

type oneByteReader struct {
	value byte
	read  bool
}

func (r *oneByteReader) Read(dst []byte) (int, error) {
	if r.read {
		return 0, io.EOF
	}
	if len(dst) == 0 {
		return 0, nil
	}
	dst[0] = r.value
	r.read = true
	return 1, nil
}

// Revision is useful for tests and later admin state snapshots.
func (m *Manager) Revision() string {
	m.mu.Lock()
	defer m.mu.Unlock()
	return strconv.FormatUint(m.revision, 10)
}

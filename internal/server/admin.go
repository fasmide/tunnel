package server

import (
	"context"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"net"
	"os"
	"sync"
	"time"

	"github.com/fasmide/tunnel/internal/transportpki"
	"github.com/fasmide/tunnel/internal/wire"
)

type AdminRequest struct {
	Command string   `json:"command"`
	ID      string   `json:"id"`
	Routes  []string `json:"routes"`
}
type AdminResult struct {
	Error       string                    `json:"error"`
	Warnings    []string                  `json:"warnings"`
	Invites     []Invite                  `json:"invites"`
	Identities  map[string]IdentityRecord `json:"identities"`
	Routes      []RouteRecord             `json:"routes"`
	Fingerprint string                    `json:"fingerprint"`
	Domain      string                    `json:"domain"`
	PublicCA    string                    `json:"public_ca,omitempty"`
}

func (m *Manager) Admin(request AdminRequest) AdminResult {
	return m.admin(request, "", "", "")
}

func (m *Manager) admin(request AdminRequest, fingerprint, domain, publicCA string) AdminResult {
	result := AdminResult{Warnings: []string{}, Invites: []Invite{}, Identities: map[string]IdentityRecord{}, Routes: []RouteRecord{}}
	var err error
	switch request.Command {
	case "invites":
		result.Invites = m.Invites()
	case "routes":
		result.Routes = m.Routes()
	case "fingerprint":
		if fingerprint == "" {
			err = errors.New("transport fingerprint unavailable")
		} else {
			result.Fingerprint = fingerprint
			result.Domain = domain
		}
	case "extract-public-ca":
		if publicCA == "" {
			err = errors.New("generated public CA unavailable; requires tunneld --domain mode")
		} else {
			result.PublicCA = publicCA
			result.Fingerprint = fingerprint
			result.Domain = domain
		}
	case "approve", "reject":
		result.Warnings, err = m.DecideInvite(request.ID, request.Command == "approve")
	case "revoke", "set-routes":
		pub, e := m.publicKey(request.ID)
		err = e
		if err == nil {
			if request.Command == "revoke" {
				err = m.Revoke(pub, "revoked by administrator")
			} else {
				result.Warnings, err = m.SetRoutes(pub, request.Routes)
			}
		}
	default:
		err = errors.New("unknown admin command")
	}
	if err != nil {
		result.Error = err.Error()
	}
	return result
}

// AdminSocket is local only. Its containing directory must be owned by the
// daemon user and mode 0700. The socket is 0600; there is no public admin API.
type AdminSocket struct {
	listener    net.Listener
	manager     *Manager
	fingerprint string
	domain      string
	publicCA    string
	wg          sync.WaitGroup
	once        sync.Once
	mu          sync.Mutex
	peers       map[net.Conn]bool
	closed      bool
	slots       chan struct{}
}

func ListenAdmin(path string, m *Manager, fingerprint, domain, publicCA string) (*AdminSocket, error) {
	if m == nil {
		return nil, errors.New("nil manager")
	}
	if publicCA != "" {
		block, rest := pem.Decode([]byte(publicCA))
		if block == nil || block.Type != "CERTIFICATE" || len(rest) != 0 || len(block.Headers) != 0 {
			return nil, errors.New("expected exactly one public CA certificate")
		}
		ca, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("parse public CA: %w", err)
		}
		if err := transportpki.ValidateCA(ca); err != nil {
			return nil, fmt.Errorf("validate public CA constraints: %w", err)
		}
		if ca.PermittedDNSDomains[0] != domain || transportpki.Fingerprint(ca) != fingerprint {
			return nil, errors.New("public CA does not match daemon domain/fingerprint")
		}
		// Re-encode the original signed DER, preserving every name constraint.
		publicCA = string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: ca.Raw}))
	}
	// Never remove an existing socket blindly: it might belong to a live daemon.
	lc := net.ListenConfig{}
	listener, err := lc.Listen(context.Background(), "unix", path)
	if err != nil {
		return nil, fmt.Errorf("listen admin socket: %w", err)
	}
	if err = os.Chmod(path, 0600); err != nil {
		_ = listener.Close()
		return nil, fmt.Errorf("chmod admin socket: %w", err)
	}
	a := &AdminSocket{listener: listener, manager: m, fingerprint: fingerprint, domain: domain, publicCA: publicCA, peers: map[net.Conn]bool{}, slots: make(chan struct{}, 32)}
	a.wg.Add(1)
	go a.accept()
	return a, nil
}
func (a *AdminSocket) Close() error {
	var err error
	a.once.Do(func() {
		a.mu.Lock()
		a.closed = true
		err = a.listener.Close()
		for conn := range a.peers {
			_ = conn.Close()
		}
		a.mu.Unlock()
		if err != nil {
			err = fmt.Errorf("close admin socket: %w", err)
		}
	})
	a.wg.Wait()
	return err
}
func (a *AdminSocket) accept() {
	defer a.wg.Done()
	for {
		conn, err := a.listener.Accept()
		if err != nil {
			return
		}
		select {
		case a.slots <- struct{}{}:
		default:
			_ = conn.Close()
			continue
		}
		a.mu.Lock()
		if a.closed {
			a.mu.Unlock()
			_ = conn.Close()
			<-a.slots
			return
		}
		a.peers[conn] = true
		a.mu.Unlock()
		a.wg.Add(1)
		go func() {
			defer a.wg.Done()
			defer func() { _ = conn.Close() }()
			defer func() { a.mu.Lock(); delete(a.peers, conn); a.mu.Unlock(); <-a.slots }()
			if err := conn.SetDeadline(time.Now().Add(10 * time.Second)); err != nil {
				return
			}
			data, err := wire.ReadFrame(conn)
			if err != nil {
				return
			}
			var request AdminRequest
			if err = wire.DecodeFrame(data, &request, "command", "id", "routes"); err != nil {
				return
			}
			_ = wire.WriteAdminFrame(conn, a.manager.admin(request, a.fingerprint, a.domain, a.publicCA))
		}()
	}
}
func AdminCall(ctx context.Context, path string, request AdminRequest) (AdminResult, error) {
	conn, err := (&net.Dialer{}).DialContext(ctx, "unix", path)
	if err != nil {
		return AdminResult{}, fmt.Errorf("dial admin socket: %w", err)
	}
	defer func() { _ = conn.Close() }()
	stop := context.AfterFunc(ctx, func() { _ = conn.Close() })
	defer stop()
	deadline := time.Now().Add(10 * time.Second)
	if d, ok := ctx.Deadline(); ok && d.Before(deadline) {
		deadline = d
	}
	if err := conn.SetDeadline(deadline); err != nil {
		return AdminResult{}, fmt.Errorf("set admin socket deadline: %w", err)
	}
	if request.Routes == nil {
		request.Routes = []string{}
	}
	if err = wire.WriteFrame(conn, request); err != nil {
		return AdminResult{}, fmt.Errorf("write admin request: %w", err)
	}
	data, err := wire.ReadAdminFrame(conn)
	if err != nil {
		return AdminResult{}, fmt.Errorf("read admin response: %w", err)
	}
	var result AdminResult
	if err = json.Unmarshal(data, &result); err != nil {
		return result, fmt.Errorf("decode admin response: %w", err)
	}
	if result.Error != "" {
		return result, errors.New(result.Error)
	}
	return result, nil
}

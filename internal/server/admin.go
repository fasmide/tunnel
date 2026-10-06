package server

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"sync"
	"time"

	"tunnel/internal/wire"
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
}

func (m *Manager) Admin(request AdminRequest) AdminResult {
	return m.admin(request, "", "")
}

func (m *Manager) admin(request AdminRequest, fingerprint, domain string) AdminResult {
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
	wg          sync.WaitGroup
	once        sync.Once
	mu          sync.Mutex
	peers       map[net.Conn]bool
	closed      bool
	slots       chan struct{}
}

func ListenAdmin(path string, m *Manager, fingerprint, domain string) (*AdminSocket, error) {
	if m == nil {
		return nil, errors.New("nil manager")
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
	a := &AdminSocket{listener: listener, manager: m, fingerprint: fingerprint, domain: domain, peers: map[net.Conn]bool{}, slots: make(chan struct{}, 32)}
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
			_ = wire.WriteAdminFrame(conn, a.manager.admin(request, a.fingerprint, a.domain))
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

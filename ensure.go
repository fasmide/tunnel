package tunnel

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io/fs"
	"log"
	"net"
	"strings"
	"time"
)

type JoinEventType string

const (
	JoinEventLoadedIdentity JoinEventType = "loaded_identity"
	JoinEventJoinSubmitted  JoinEventType = "join_submitted"
	JoinEventWaiting        JoinEventType = "waiting"
	JoinEventApproved       JoinEventType = "approved"
	JoinEventCheckFailed    JoinEventType = "check_failed"
	JoinEventRevoked        JoinEventType = "revoked"
)

type JoinEvent struct {
	Time     time.Time
	Type     JoinEventType
	Message  string
	Identity string
	InviteID string
	Routes   []string
	Err      error
}

type JoinWaitOptions struct {
	JoinRequest  JoinRequest
	PollInterval time.Duration
	OnEvent      func(JoinEvent)
}

type ListenFunc func(context.Context, *Client) (net.Listener, error)

func (o JoinWaitOptions) pollInterval() time.Duration {
	if o.PollInterval <= 0 {
		return time.Second
	}
	return o.PollInterval
}

func (o JoinWaitOptions) emit(event JoinEvent) {
	event.Time = time.Now()
	if o.OnEvent != nil {
		o.OnEvent(event)
		return
	}
	log.Print(FormatJoinEvent(event))
}

// EnsureJoined makes sure a local identity has a submitted join request and then
// waits until an administrator approves it. The wait is canceled by ctx.
//
// If credential storage already contains an approved identity, no new join is
// submitted. If an identity exists but is not approved, EnsureJoined submits a
// fresh join request before waiting.
func EnsureJoined(ctx context.Context, addr string, options JoinWaitOptions) (Credentials, error) {
	if options.JoinRequest.Storage == nil {
		return Credentials{}, errors.New("join storage is required")
	}
	if creds, err := LoadCredentials(options.JoinRequest.Storage); err == nil {
		options.emit(JoinEvent{Type: JoinEventLoadedIdentity, Message: "loaded existing identity", Identity: creds.Identity()})
		approved, err := probeApproved(ctx, addr, creds, options.JoinRequest.TLSConfig, options)
		if err == nil {
			return approved, nil
		}
		if errors.Is(err, ErrIdentityRevoked) {
			return Credentials{}, err
		}
		if !errors.Is(err, ErrIdentityNotApproved) {
			return Credentials{}, err
		}
	} else if !errors.Is(err, fs.ErrNotExist) {
		return Credentials{}, err
	}
	creds, result, err := requestJoin(ctx, addr, options.JoinRequest)
	if err != nil {
		return Credentials{}, err
	}
	identity := creds.Identity()
	options.emit(JoinEvent{Type: JoinEventJoinSubmitted, Message: "join request submitted; waiting for approval", Identity: identity, InviteID: result.InviteID, Routes: append([]string(nil), result.Routes...)})
	if result.Status == "approved" {
		options.emit(JoinEvent{Type: JoinEventApproved, Message: "identity approved", Identity: identity, InviteID: result.InviteID, Routes: append([]string(nil), result.Routes...)})
		return creds, nil
	}
	approved, err := waitApprovedState(ctx, addr, creds, options.JoinRequest.TLSConfig, options.pollInterval(), options)
	return approved, err
}

// EnsureJoinedAndListen combines EnsureJoined, Dial, and listener creation.
// The listen callback selects the desired listener mode, for example:
//
//	listener, client, err := tunnel.EnsureJoinedAndListen(ctx, addr, opts,
//		func(ctx context.Context, c *tunnel.Client) (net.Listener, error) { return c.Listen(ctx, name) })
func EnsureJoinedAndListen(ctx context.Context, addr string, options JoinWaitOptions, listen ListenFunc, dialOptions ...Option) (net.Listener, *Client, error) {
	if listen == nil {
		return nil, nil, errors.New("listen callback is required")
	}
	creds, err := EnsureJoined(ctx, addr, options)
	if err != nil {
		return nil, nil, err
	}
	dial := ensureDialOptions(creds, options.JoinRequest.TLSConfig, dialOptions)
	client, err := Dial(ctx, addr, dial...)
	if err != nil {
		return nil, nil, err
	}
	listener, err := listen(ctx, client)
	if err != nil {
		_ = client.Close()
		return nil, nil, err
	}
	return listener, client, nil
}

func probeApproved(ctx context.Context, addr string, creds Credentials, transportTLS *tls.Config, options JoinWaitOptions) (Credentials, error) {
	attempt, cancel := context.WithTimeout(ctx, 10*time.Second)
	client, err := Dial(attempt, addr, dialApprovalOptions(creds, transportTLS)...)
	cancel()
	if err != nil {
		return Credentials{}, err
	}
	_ = client.Close()
	options.emit(JoinEvent{Type: JoinEventApproved, Message: "identity approved", Identity: creds.Identity()})
	return creds, nil
}

func waitApprovedState(ctx context.Context, addr string, creds Credentials, transportTLS *tls.Config, poll time.Duration, options JoinWaitOptions) (Credentials, error) {
	lastFailure := ""
	emittedWaiting := false
	for {
		approved, err := probeApproved(ctx, addr, creds, transportTLS, options)
		if err == nil {
			return approved, nil
		}
		if ctx.Err() != nil {
			return Credentials{}, fmt.Errorf("approval wait canceled: %w", ctx.Err())
		}
		switch {
		case errors.Is(err, ErrIdentityNotApproved):
			if !emittedWaiting {
				emittedWaiting = true
				options.emit(JoinEvent{Type: JoinEventWaiting, Message: "still waiting for administrator approval", Identity: creds.Identity()})
			}
		case errors.Is(err, ErrIdentityRevoked):
			options.emit(JoinEvent{Type: JoinEventRevoked, Message: "identity revoked while waiting for approval", Identity: creds.Identity(), Err: err})
			return Credentials{}, err
		default:
			text := err.Error()
			if text != lastFailure {
				lastFailure = text
				options.emit(JoinEvent{Type: JoinEventCheckFailed, Message: "approval check failed; retrying", Identity: creds.Identity(), Err: err})
			}
		}
		if err := sleepContext(ctx, poll); err != nil {
			return Credentials{}, err
		}
	}
}

func dialApprovalOptions(creds Credentials, transportTLS *tls.Config) []Option {
	options := []Option{WithCredentials(creds)}
	if transportTLS != nil {
		options = append(options, WithTLSConfig(transportTLS))
	}
	return options
}

func ensureDialOptions(creds Credentials, transportTLS *tls.Config, extra []Option) []Option {
	options := make([]Option, 0, len(extra)+2)
	if transportTLS != nil {
		options = append(options, WithTLSConfig(transportTLS))
	}
	options = append(options, extra...)
	options = append(options, WithCredentials(creds))
	return options
}

func sleepContext(ctx context.Context, d time.Duration) error {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return fmt.Errorf("sleep canceled: %w", ctx.Err())
	case <-t.C:
		return nil
	}
}

func FormatJoinEvent(event JoinEvent) string {
	parts := []string{}
	if event.Message != "" {
		parts = append(parts, event.Message)
	}
	if event.Identity != "" {
		parts = append(parts, "identity="+event.Identity)
	}
	if event.InviteID != "" {
		parts = append(parts, "invite="+event.InviteID)
	}
	if event.Err != nil {
		parts = append(parts, "error="+event.Err.Error())
	}
	if len(parts) == 0 && event.Type != "" {
		parts = append(parts, string(event.Type))
	}
	return fmt.Sprintf("tunnel %s: %s", event.Type, strings.Join(parts, "; "))
}

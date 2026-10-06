package tunnel

import (
	"context"
	"errors"
	"net"
	"sync"
	"testing"
	"time"
)

func TestEnsureJoinedWaitsForApproval(t *testing.T) {
	s, m, config := runningServer(t)
	storage := FileStorage(t.TempDir())
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	eventsMu := sync.Mutex{}
	events := []JoinEvent{}
	done := make(chan struct{})
	go func() {
		defer close(done)
		for len(m.Invites()) == 0 {
			time.Sleep(10 * time.Millisecond)
		}
		invite := m.Invites()[0]
		_, _ = m.DecideInvite(invite.ID, true)
	}()
	creds, err := EnsureJoined(ctx, s.Addr(), JoinWaitOptions{
		JoinRequest:  JoinRequest{Storage: storage, Routes: []string{"alice.example.com"}, TLSConfig: config},
		PollInterval: 10 * time.Millisecond,
		OnEvent: func(event JoinEvent) {
			eventsMu.Lock()
			defer eventsMu.Unlock()
			events = append(events, event)
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	<-done
	if creds.Identity() == "" {
		t.Fatal("missing identity")
	}
	eventsMu.Lock()
	defer eventsMu.Unlock()
	seenSubmitted, seenApproved := false, false
	for _, event := range events {
		if event.Type == JoinEventJoinSubmitted {
			seenSubmitted = true
		}
		if event.Type == JoinEventApproved {
			seenApproved = true
		}
	}
	if !seenSubmitted || !seenApproved {
		t.Fatalf("events: %+v", events)
	}
}

func TestEnsureJoinedAndListen(t *testing.T) {
	s, m, config := runningServer(t)
	storage := FileStorage(t.TempDir())
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	go func() {
		for len(m.Invites()) == 0 {
			time.Sleep(10 * time.Millisecond)
		}
		invite := m.Invites()[0]
		_, _ = m.DecideInvite(invite.ID, true)
	}()
	listener, client, err := EnsureJoinedAndListen(ctx, s.Addr(), JoinWaitOptions{
		JoinRequest:  JoinRequest{Storage: storage, Routes: []string{"alice.example.com"}, TLSConfig: config},
		PollInterval: 10 * time.Millisecond,
	}, func(ctx context.Context, c *Client) (net.Listener, error) {
		return c.ListenRaw(ctx, "alice.example.com")
	}, WithTLSConfig(config))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = listener.Close() }()
	defer func() { _ = client.Close() }()
	if client.Status() != "connected" {
		t.Fatalf("status %s", client.Status())
	}
}

func TestEnsureJoinedCancelled(t *testing.T) {
	s, _, config := runningServer(t)
	storage := FileStorage(t.TempDir())
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	_, err := EnsureJoined(ctx, s.Addr(), JoinWaitOptions{
		JoinRequest:  JoinRequest{Storage: storage, Routes: []string{"alice.example.com"}, TLSConfig: config},
		PollInterval: 10 * time.Millisecond,
	})
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("got %v", err)
	}
}

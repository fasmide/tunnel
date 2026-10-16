package server

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io/fs"
	"strconv"
	"testing"
	"time"

	"github.com/fasmide/tunnel/internal/wire"
)

type inviteStore struct {
	data []byte
	fail bool
}

func (s *inviteStore) Get(string) ([]byte, error) {
	if s.data == nil {
		return nil, fs.ErrNotExist
	}
	return s.data, nil
}
func (s *inviteStore) Put(_ string, data []byte) error {
	if s.fail {
		return errors.New("disk failed")
	}
	s.data = append([]byte(nil), data...)
	return nil
}

func lifecycleJoin(t *testing.T, m *Manager) (ed25519.PublicKey, wire.Join, string) {
	t.Helper()
	pub, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	j := wire.Join{Envelope: wire.Envelope{Type: "Join", ID: "1"}, Request: wire.JoinPayload{
		Pubkey: base64.StdEncoding.EncodeToString(pub), Routes: []string{"alice.example.com"},
		Metadata: map[string]string{}, Nonce: base64.StdEncoding.EncodeToString(make([]byte, 32)),
		Timestamp: strconv.FormatInt(time.Now().Unix(), 10),
	}}
	payload, err := wire.JoinBytes(j.Request)
	if err != nil {
		t.Fatal(err)
	}
	j.Signature = base64.StdEncoding.EncodeToString(ed25519.Sign(key, payload))
	result := m.SubmitJoin(pub, j)
	if result.Code != "ok" {
		t.Fatal(result)
	}
	return pub, j, result.InviteID
}

func TestInviteExpiryAndPruning(t *testing.T) {
	store := &inviteStore{}
	m, err := OpenManager(store)
	if err != nil {
		t.Fatal(err)
	}
	pub, j, id := lifecycleJoin(t, m)
	i := m.invites[id]
	if i.ExpiresAt-i.CreatedAt != int64(InviteLifetime/time.Second) {
		t.Fatal(i)
	}
	if err := m.cleanupInvitesLocked(i.ExpiresAt - 1); err != nil {
		t.Fatal(err)
	}
	if m.invites[id].Status != "pending" {
		t.Fatal("expired early")
	}
	if err := m.cleanupInvitesLocked(i.ExpiresAt); err != nil {
		t.Fatal(err)
	}
	if m.invites[id].Status != "expired" {
		t.Fatal("did not expire")
	}
	if _, err := m.DecideInvite(id, true); err == nil {
		t.Fatal("approved expired invite")
	}
	if result := m.SubmitJoin(pub, j); result.Code != "expired" {
		t.Fatal(result)
	}
	reloaded, err := OpenManager(store)
	if err != nil {
		t.Fatal(err)
	}
	if reloaded.invites[id].Status != "expired" {
		t.Fatal("expiration not durable")
	}
	if err := reloaded.cleanupInvitesLocked(i.ExpiresAt + int64(InviteRetention/time.Second)); err != nil {
		t.Fatal(err)
	}
	if len(reloaded.invites) != 0 {
		t.Fatal("history not pruned")
	}
}

func TestDecisionChecksExpiryWithoutBackgroundCleanup(t *testing.T) {
	m := NewManager()
	_, _, id := lifecycleJoin(t, m)
	i := m.invites[id]
	i.CreatedAt = time.Now().Add(-InviteLifetime).Unix()
	i.ExpiresAt = time.Now().Unix()
	m.invites[id] = i
	if len(m.Invites()) != 0 {
		t.Fatal("listed expired pending invite")
	}
	if _, err := m.DecideInvite(id, true); err == nil {
		t.Fatal("approved expired invite before background cleanup")
	}
	if len(m.grants) != 0 || m.invites[id].Status != "expired" {
		t.Fatal("expiry granted authorization or was not committed")
	}
}

func TestInviteCleanupPreservesAuthorization(t *testing.T) {
	for _, approve := range []bool{true, false} {
		m := NewManager()
		pub, j, id := lifecycleJoin(t, m)
		if _, err := m.DecideInvite(id, approve); err != nil {
			t.Fatal(err)
		}
		if result := m.SubmitJoin(pub, j); result.InviteID != id || result.Code != "ok" {
			t.Fatal(result)
		}
		if approve {
			if err := m.Revoke(pub, "test"); err != nil {
				t.Fatal(err)
			}
		}
		revision := m.revision
		i := m.invites[id]
		if err := m.cleanupInvitesLocked(i.FinishedAt + int64(InviteRetention/time.Second)); err != nil {
			t.Fatal(err)
		}
		if len(m.invites) != 0 || m.revision != revision {
			t.Fatal("cleanup changed revision or retained history")
		}
		if approve && !m.grants[Identity(pub)].revoked {
			t.Fatal("cleanup removed revocation")
		}
	}
	m := NewManager()
	pub, _, id := lifecycleJoin(t, m)
	if _, err := m.DecideInvite(id, true); err != nil {
		t.Fatal(err)
	}
	if err := m.cleanupInvitesLocked(m.invites[id].FinishedAt + int64(InviteRetention/time.Second)); err != nil {
		t.Fatal(err)
	}
	if len(m.grants[Identity(pub)].routes) != 1 {
		t.Fatal("cleanup removed grant")
	}
}

func TestLegacyInviteMigrationIsDurable(t *testing.T) {
	m := NewManager()
	_, _, id := lifecycleJoin(t, m)
	i := m.invites[id]
	i.CreatedAt, i.ExpiresAt, i.FinishedAt = 0, 0, 0
	m.invites[id] = i
	data, err := json.Marshal(m.stateLocked())
	if err != nil {
		t.Fatal(err)
	}
	store := &inviteStore{data: data}
	loaded, err := OpenManager(store)
	if err != nil {
		t.Fatal(err)
	}
	first := loaded.invites[id]
	if first.CreatedAt == 0 || first.ExpiresAt <= first.CreatedAt {
		t.Fatal(first)
	}
	loaded, err = OpenManager(store)
	if err != nil {
		t.Fatal(err)
	}
	if loaded.invites[id].ExpiresAt != first.ExpiresAt {
		t.Fatal("restart renewed grace period")
	}
}

func TestInviteCapacityRecoversBeforeAdmission(t *testing.T) {
	m := NewManager()
	_, _, id := lifecycleJoin(t, m)
	old := m.invites[id]
	old.CreatedAt = time.Now().Add(-InviteLifetime - InviteRetention - time.Hour).Unix()
	old.ExpiresAt = old.CreatedAt + int64(InviteLifetime/time.Second)
	for n := 0; n < maxInvites; n++ {
		i := old
		i.ID = strconv.Itoa(n)
		m.invites[i.ID] = i
	}
	delete(m.invites, id)
	// SubmitJoin must reclaim capacity before its global and per-key checks.
	lifecycleJoin(t, m)
	if len(m.invites) != 1 {
		t.Fatal("expired history still occupies capacity")
	}
}

func TestInviteCleanupCommitFailure(t *testing.T) {
	store := &inviteStore{}
	m, err := OpenManager(store)
	if err != nil {
		t.Fatal(err)
	}
	_, _, id := lifecycleJoin(t, m)
	store.fail = true
	if err := m.cleanupInvitesLocked(m.invites[id].ExpiresAt); err == nil {
		t.Fatal("ignored persistence failure")
	}
	if m.invites[id].Status != "pending" || m.stateErr == nil {
		t.Fatal("published uncommitted cleanup")
	}
}

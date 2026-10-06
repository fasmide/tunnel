package tunnel

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"errors"
	"path/filepath"
	"strconv"
	"testing"
	"time"

	"github.com/fasmide/tunnel/internal/server"
	"github.com/fasmide/tunnel/internal/wire"
)

func signedJoin(t *testing.T, c Credentials, routes ...string) wire.Join {
	t.Helper()
	j := wire.Join{Envelope: wire.Envelope{Type: "Join", ID: "1"}, Request: wire.JoinPayload{Pubkey: base64.StdEncoding.EncodeToString(c.PublicKey()), Routes: routes, Metadata: map[string]string{"agent": "test"}, Nonce: base64.StdEncoding.EncodeToString(make([]byte, 32)), Timestamp: strconv.FormatInt(time.Now().Unix(), 10)}}
	signJoin(t, c, &j)
	return j
}
func signJoin(t *testing.T, c Credentials, j *wire.Join) {
	t.Helper()
	data, err := wire.JoinBytes(j.Request)
	if err != nil {
		t.Fatal(err)
	}
	j.Signature = base64.StdEncoding.EncodeToString(ed25519.Sign(c.privateKey, data))
}
func TestJoinApproveHTTPSAndPersistentRevoke(t *testing.T) {
	store := FileStorage(t.TempDir())
	m, err := server.OpenManager(store)
	if err != nil {
		t.Fatal(err)
	}
	s, _, config := runningManager(t, m)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	clientStore := FileStorage(t.TempDir())
	creds, err := RequestJoin(ctx, s.Addr(), JoinRequest{Routes: []string{"alice.example.com"}, Storage: clientStore, TLSConfig: config})
	if err != nil {
		t.Fatal(err)
	}
	if loaded, err := LoadCredentials(clientStore); err != nil || loaded.Identity() != creds.Identity() {
		t.Fatal("bootstrap identity not persisted")
	}
	if _, err := Dial(ctx, s.Addr(), WithCredentials(creds), WithTLSConfig(config)); err == nil {
		t.Fatal("pending identity connected")
	}
	socket := filepath.Join(t.TempDir(), "admin.sock")
	admin, err := server.ListenAdmin(socket, m, "", "")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = admin.Close() }()
	invites, err := server.AdminCall(ctx, socket, server.AdminRequest{Command: "invites"})
	if err != nil || len(invites.Invites) != 1 {
		t.Fatalf("invites: %+v %v", invites, err)
	}
	if _, err := server.AdminCall(ctx, socket, server.AdminRequest{Command: "approve", ID: invites.Invites[0].ID}); err != nil {
		t.Fatal(err)
	}
	c := connected(t, s, config, creds)
	cert, roots := applicationCertificate(t)
	serveApplication(t, listenRaw(t, c, "alice.example.com"), cert, "joined")
	edge, err := s.ListenTLS("127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	if got := edgeRequest(t, edge, roots, "foo.alice.example.com"); got != "joined:real HTTPS request" {
		t.Fatal(got)
	}
	if _, err := server.AdminCall(ctx, socket, server.AdminRequest{Command: "revoke", ID: creds.Identity()}); err != nil {
		t.Fatal(err)
	}
	_ = s.Close()
	_ = admin.Close()
	restarted, err := server.OpenManager(store)
	if err != nil {
		t.Fatal(err)
	}
	s2, _, config2 := runningManager(t, restarted)
	if _, err := Dial(ctx, s2.Addr(), WithCredentials(creds), WithTLSConfig(config2)); err == nil {
		t.Fatal("revoked identity admitted after restart")
	}
}

func TestPersistentJoinsAndDecisions(t *testing.T) {
	storage := FileStorage(t.TempDir())
	m, err := server.OpenManager(storage)
	if err != nil {
		t.Fatal(err)
	}
	c := identity(t)
	j := signedJoin(t, c, "alice.example.com")
	first := m.SubmitJoin(c.PublicKey(), j)
	if first.Status != "pending" || first.Code != "ok" {
		t.Fatalf("join: %+v", first)
	}
	// Invalid signatures and certificate/pubkey swapping never create invites.
	bad := j
	bad.Signature = base64.StdEncoding.EncodeToString(make([]byte, 64))
	if result := m.SubmitJoin(c.PublicKey(), bad); result.Code != "invalid_signature" {
		t.Fatal("bad signature accepted")
	}
	if result := m.SubmitJoin(identity(t).PublicKey(), j); result.Code != "invalid_signature" {
		t.Fatal("pubkey swap accepted")
	}
	conflict := j
	conflict.Request.Timestamp = strconv.FormatInt(time.Now().Unix()-1000, 10)
	signJoin(t, c, &conflict)
	if result := m.SubmitJoin(c.PublicKey(), conflict); result.Code != "replay_conflict" {
		t.Fatal("nonce payload changed")
	}
	if len(m.Invites()) != 1 {
		t.Fatal("unverified request stored")
	}
	old := signedJoin(t, c, "stale.example.com")
	old.Request.Nonce = base64.StdEncoding.EncodeToString(append([]byte{7}, make([]byte, 31)...))
	old.Request.Timestamp = "1"
	signJoin(t, c, &old)
	if result := m.SubmitJoin(c.PublicKey(), old); result.Code != "invalid_request" {
		t.Fatal("stale new request accepted")
	}
	listed := m.Invites()
	listed[0].Join.Request.Routes[0] = "mutated.example.com"
	listed[0].Join.Request.Metadata["agent"] = "changed"
	if m.Invites()[0].Join.Request.Routes[0] != "alice.example.com" {
		t.Fatal("invite aliases internal state")
	}
	reloaded, err := server.OpenManager(storage)
	if err != nil {
		t.Fatal(err)
	}
	if result := reloaded.SubmitJoin(c.PublicKey(), j); result.InviteID != first.InviteID {
		t.Fatal("restart lost nonce dedup")
	}
	socket := filepath.Join(t.TempDir(), "admin.sock")
	admin, err := server.ListenAdmin(socket, reloaded, "", "")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = admin.Close() }()
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	if _, err := server.AdminCall(ctx, socket, server.AdminRequest{Command: "approve", ID: first.InviteID}); err != nil {
		t.Fatal(err)
	}
	approved, err := server.OpenManager(storage)
	if err != nil {
		t.Fatal(err)
	}
	if record := approved.Identities()[c.Identity()]; len(record.Routes) != 1 || record.Routes[0] != "alice.example.com" {
		t.Fatal("approval not persisted")
	}
	second := signedJoin(t, c, "other.example.com")
	second.Request.Nonce = base64.StdEncoding.EncodeToString(append([]byte{1}, make([]byte, 31)...))
	signJoin(t, c, &second)
	pending := approved.SubmitJoin(c.PublicKey(), second)
	if pending.Status != "pending" || len(pending.Routes) != 1 {
		t.Fatal("additional request lost existing grants")
	}
	if _, err := approved.DecideInvite(pending.InviteID, false); err != nil {
		t.Fatal(err)
	}
	if len(approved.Identities()[c.Identity()].Routes) != 1 {
		t.Fatal("rejection altered approvals")
	}
	third := second
	third.Request.Nonce = base64.StdEncoding.EncodeToString(append([]byte{2}, make([]byte, 31)...))
	signJoin(t, c, &third)
	pending = approved.SubmitJoin(c.PublicKey(), third)
	if _, err := approved.DecideInvite(pending.InviteID, true); err != nil {
		t.Fatal(err)
	}
	if len(approved.Identities()[c.Identity()].Routes) != 2 {
		t.Fatal("additional approval did not union routes")
	}
	child := identity(t)
	childJoin := signedJoin(t, child, "api.alice.example.com")
	childPending := approved.SubmitJoin(child.PublicKey(), childJoin)
	warnings, err := approved.DecideInvite(childPending.InviteID, true)
	if err != nil || len(warnings) == 0 {
		t.Fatalf("approval overlap warning: %v %v", warnings, err)
	}
	if err := approved.Revoke(c.PublicKey(), "test"); err != nil {
		t.Fatal(err)
	}
	revoked, err := server.OpenManager(storage)
	if err != nil {
		t.Fatal(err)
	}
	if !revoked.Identities()[c.Identity()].Revoked || revoked.SubmitJoin(c.PublicKey(), j).Code != "revoked" {
		t.Fatal("revocation not durable")
	}
}

type brokenState struct{ Storage }

func (s brokenState) Put(string, []byte) error { return errors.New("disk unavailable") }
func TestStateCommitFailureAndCorruption(t *testing.T) {
	storage := MemoryStorage()
	m, err := server.OpenManager(brokenState{storage})
	if err != nil {
		t.Fatal(err)
	}
	c := identity(t)
	result := m.SubmitJoin(c.PublicKey(), signedJoin(t, c, "alice.example.com"))
	if result.Status != "error" || len(m.Invites()) != 0 {
		t.Fatal("failed commit admitted join")
	}
	if _, err := m.SetRoutes(c.PublicKey(), []string{"alice.example.com"}); err == nil {
		t.Fatal("uncertain state allowed mutation")
	}
	if err := storage.Put("server/state", []byte(`{"version":1,"revision":"0","identities":{},"invites":{},"version":1}`)); err != nil {
		t.Fatal(err)
	}
	if _, err := server.OpenManager(storage); err == nil {
		t.Fatal("corrupt state accepted")
	}
}

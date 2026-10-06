package tunnel

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"sort"
	"strconv"
	"time"

	"github.com/fasmide/tunnel/internal/wire"
	quic "github.com/quic-go/quic-go"
)

type JoinRequest struct {
	Routes   []string
	Storage  Storage
	Metadata map[string]string
	// TLSConfig optionally supplies private roots/ServerName for tunnel TLS.
	// Public CA trust is used by default; verification cannot be disabled.
	TLSConfig *tls.Config
}

// RequestJoin returns persisted credentials after durable pending submission,
// not after human approval. A new Dial is required once an admin approves it.
func RequestJoin(ctx context.Context, addr string, request JoinRequest) (Credentials, error) {
	creds, _, err := requestJoin(ctx, addr, request)
	return creds, err
}

func requestJoin(ctx context.Context, addr string, request JoinRequest) (Credentials, wire.JoinResult, error) {
	if request.Storage == nil {
		return Credentials{}, wire.JoinResult{}, errors.New("join storage is required")
	}
	creds, err := loadOrCreateCredentials(request.Storage)
	if err != nil {
		return Credentials{}, wire.JoinResult{}, err
	}
	routes := make([]string, 0, len(request.Routes))
	seen := map[string]bool{}
	for _, name := range request.Routes {
		name, err = canonicalName(name)
		if err != nil {
			return Credentials{}, wire.JoinResult{}, err
		}
		if !seen[name] {
			routes = append(routes, name)
			seen[name] = true
		}
	}
	sort.Strings(routes)
	metadata := map[string]string{}
	for k, v := range request.Metadata {
		metadata[k] = v
	}
	serverID := sha256.Sum256([]byte(addr))
	pendingKey := "creds/join/" + hex.EncodeToString(serverID[:])
	var j wire.Join
	saved, err := request.Storage.Get(pendingKey)
	if err == nil {
		j, err = wire.DecodeJoin(saved)
		if err != nil {
			return Credentials{}, wire.JoinResult{}, fmt.Errorf("decode saved join request: %w", err)
		}
		if wire.VerifyJoin(j, creds.PublicKey()) != nil {
			return Credentials{}, wire.JoinResult{}, errors.New("invalid saved join")
		}
		// Preserve the unresolved nonce only for the identical request shape.
		old, _ := json.Marshal(struct {
			Routes   []string
			Metadata map[string]string
		}{j.Request.Routes, j.Request.Metadata})
		next, _ := json.Marshal(struct {
			Routes   []string
			Metadata map[string]string
		}{routes, metadata})
		if string(old) != string(next) {
			j = wire.Join{}
		}
	} else if !errors.Is(err, fs.ErrNotExist) {
		return Credentials{}, wire.JoinResult{}, fmt.Errorf("load pending join request: %w", err)
	}
	if j.Signature == "" {
		var nonce [32]byte
		if _, err = rand.Read(nonce[:]); err != nil {
			return Credentials{}, wire.JoinResult{}, fmt.Errorf("generate join nonce: %w", err)
		}
		j = wire.Join{Envelope: wire.Envelope{Type: "Join", ID: "1"}, Request: wire.JoinPayload{Pubkey: base64.StdEncoding.EncodeToString(creds.PublicKey()), Routes: routes, Metadata: metadata, Nonce: base64.StdEncoding.EncodeToString(nonce[:]), Timestamp: strconv.FormatInt(time.Now().Unix(), 10)}}
		bytes, err := wire.JoinBytes(j.Request)
		if err != nil {
			return Credentials{}, wire.JoinResult{}, fmt.Errorf("encode join payload: %w", err)
		}
		j.Signature = base64.StdEncoding.EncodeToString(ed25519.Sign(creds.privateKey, bytes))
		saved, err = json.Marshal(j)
		if err != nil {
			return Credentials{}, wire.JoinResult{}, fmt.Errorf("marshal join request: %w", err)
		}
		if err = request.Storage.Put(pendingKey, saved); err != nil {
			return Credentials{}, wire.JoinResult{}, fmt.Errorf("persist pending join request: %w", err)
		}
	}
	config := &tls.Config{}
	if request.TLSConfig != nil {
		config = request.TLSConfig.Clone()
	}
	if config.InsecureSkipVerify {
		return Credentials{}, wire.JoinResult{}, errors.New("server verification cannot be disabled")
	}
	cert, err := creds.identityCertificate(time.Now())
	if err != nil {
		return Credentials{}, wire.JoinResult{}, err
	}
	config.Certificates = []tls.Certificate{cert}
	config.GetClientCertificate = nil
	config.NextProtos = []string{wire.ALPN}
	config.MinVersion = tls.VersionTLS13
	config.ClientSessionCache = nil
	conn, err := quic.DialAddr(ctx, addr, config, &quic.Config{MaxIncomingStreams: -1, MaxIncomingUniStreams: -1})
	if err != nil {
		return Credentials{}, wire.JoinResult{}, fmt.Errorf("dial join endpoint %s: %w", addr, err)
	}
	defer func() { _ = conn.CloseWithError(0, "join finished") }()
	stream, err := conn.OpenStreamSync(ctx)
	if err != nil {
		return Credentials{}, wire.JoinResult{}, fmt.Errorf("open join control stream: %w", err)
	}
	stop := context.AfterFunc(ctx, func() { _ = conn.CloseWithError(0, "join canceled") })
	defer stop()
	deadline := time.Now().Add(10 * time.Second)
	if d, ok := ctx.Deadline(); ok && d.Before(deadline) {
		deadline = d
	}
	if err := stream.SetDeadline(deadline); err != nil {
		return Credentials{}, wire.JoinResult{}, fmt.Errorf("set join stream deadline: %w", err)
	}
	if err = wire.WriteFrame(stream, j); err != nil {
		return Credentials{}, wire.JoinResult{}, fmt.Errorf("write join request: %w", err)
	}
	data, err := wire.ReadFrame(stream)
	if err != nil {
		return Credentials{}, wire.JoinResult{}, fmt.Errorf("read join response: %w", err)
	}
	var result wire.JoinResult
	if err = wire.DecodeFrame(data, &result, "type", "id", "invite_id", "status", "code", "error", "routes", "revision"); err != nil {
		return Credentials{}, wire.JoinResult{}, fmt.Errorf("decode join response: %w", err)
	}
	if result.Type != "JoinResult" || result.ID != "1" {
		return Credentials{}, wire.JoinResult{}, errors.New("unexpected join response")
	}
	if result.Code != "ok" || result.Status != "pending" && result.Status != "approved" {
		return Credentials{}, wire.JoinResult{}, errors.New("join rejected: " + result.Error)
	}
	if err = request.Storage.Delete(pendingKey); err != nil {
		return Credentials{}, wire.JoinResult{}, fmt.Errorf("delete pending join request: %w", err)
	}
	return creds, result, nil
}

package wire

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strconv"
	"strings"
	"unicode/utf8"

	"github.com/fasmide/tunnel/internal/names"
)

type JoinPayload struct {
	Pubkey    string            `json:"pubkey"`
	Routes    []string          `json:"requested_routes"`
	Metadata  map[string]string `json:"metadata"`
	Nonce     string            `json:"nonce"`
	Timestamp string            `json:"timestamp"`
}
type Join struct {
	Envelope
	Request   JoinPayload `json:"request"`
	Signature string      `json:"signature"`
}
type JoinResult struct {
	Envelope
	InviteID string   `json:"invite_id"`
	Status   string   `json:"status"`
	Code     string   `json:"code"`
	Error    string   `json:"error"`
	Routes   []string `json:"routes"`
	Revision string   `json:"revision"`
}

func Base64(s string, size int) ([]byte, error) {
	b, err := base64.StdEncoding.Strict().DecodeString(s)
	if err != nil || len(b) != size || base64.StdEncoding.EncodeToString(b) != s {
		return nil, errors.New("invalid base64 field")
	}
	return b, nil
}
func CanonicalJoin(p JoinPayload) ([]byte, error) {
	if _, err := Base64(p.Pubkey, 32); err != nil {
		return nil, err
	}
	if _, err := Base64(p.Nonce, 32); err != nil {
		return nil, err
	}
	if _, err := Counter(p.Timestamp); err != nil {
		return nil, err
	}
	if len(p.Routes) == 0 || len(p.Routes) > 128 || p.Metadata == nil || len(p.Metadata) > 32 {
		return nil, errors.New("invalid join routes or metadata")
	}
	for i, name := range p.Routes {
		if !names.Valid(name) || i > 0 && p.Routes[i-1] >= name {
			return nil, errors.New("routes must be canonical, sorted and unique")
		}
	}
	keys := []string{}
	for k, v := range p.Metadata {
		if len(k) == 0 || len(k) > 64 || len(v) > 1024 || !utf8.ValidString(v) {
			return nil, errors.New("invalid metadata")
		}
		for _, c := range k {
			if (c < 'a' || c > 'z') && (c < '0' || c > '9') && !strings.ContainsRune("_.-", c) {
				return nil, errors.New("invalid metadata key")
			}
		}
		for _, c := range v {
			if c < 32 {
				return nil, errors.New("control character in metadata")
			}
		}
		keys = append(keys, k)
	}
	sort.Strings(keys)
	quote := func(s string) string { return `"` + strings.NewReplacer(`\`, `\\`, `"`, `\"`).Replace(s) + `"` }
	var b strings.Builder
	b.WriteString(`{"pubkey":` + quote(p.Pubkey) + `,"requested_routes":[`)
	for i, s := range p.Routes {
		if i > 0 {
			b.WriteByte(',')
		}
		b.WriteString(quote(s))
	}
	b.WriteString(`],"metadata":{`)
	for i, k := range keys {
		if i > 0 {
			b.WriteByte(',')
		}
		b.WriteString(quote(k) + ":" + quote(p.Metadata[k]))
	}
	b.WriteString(`},"nonce":` + quote(p.Nonce) + `,"timestamp":` + quote(p.Timestamp) + `}`)
	return []byte(b.String()), nil
}
func JoinBytes(p JoinPayload) ([]byte, error) {
	b, err := CanonicalJoin(p)
	return append([]byte("selfhost-tunnel/join/1\n"), b...), err
}
func DecodeJoin(data []byte) (Join, error) {
	var j Join
	if err := Decode(data, &j, "type", "id", "request", "signature"); err != nil {
		return j, fmt.Errorf("decode join envelope: %w", err)
	}
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(data, &fields); err != nil {
		return j, fmt.Errorf("unmarshal join fields: %w", err)
	}
	var payload map[string]json.RawMessage
	if err := json.Unmarshal(fields["request"], &payload); err != nil {
		return j, fmt.Errorf("unmarshal signed join payload: %w", err)
	}
	if len(payload) != 5 {
		return j, errors.New("unknown/missing signed payload fields")
	}
	for _, k := range []string{"pubkey", "requested_routes", "metadata", "nonce", "timestamp"} {
		if b, ok := payload[k]; !ok || bytes.Equal(bytes.TrimSpace(b), []byte("null")) {
			return j, errors.New("missing signed payload field")
		}
	}
	if _, err := CanonicalJoin(j.Request); err != nil {
		return j, fmt.Errorf("canonicalize join payload: %w", err)
	}
	return j, nil
}
func VerifyJoin(j Join, pub ed25519.PublicKey) error {
	key, err := Base64(j.Request.Pubkey, 32)
	if err != nil {
		return err
	}
	sig, err := Base64(j.Signature, 64)
	if err != nil {
		return err
	}
	b, err := JoinBytes(j.Request)
	if err != nil {
		return err
	}
	if !bytes.Equal(key, pub) || !ed25519.Verify(pub, b, sig) {
		return errors.New("invalid join signature or TLS identity mismatch")
	}
	return nil
}
func Timestamp(p JoinPayload) (int64, error) {
	value, err := strconv.ParseInt(p.Timestamp, 10, 64)
	if err != nil {
		return 0, fmt.Errorf("parse join timestamp: %w", err)
	}
	return value, nil
}

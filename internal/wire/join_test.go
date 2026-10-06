package wire

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"
)

func TestCanonicalJoinAndSignature(t *testing.T) {
	priv := ed25519.NewKeyFromSeed(make([]byte, 32))
	pub := priv.Public().(ed25519.PublicKey)
	p := JoinPayload{Pubkey: base64.StdEncoding.EncodeToString(pub), Routes: []string{"alice.example.com"}, Metadata: map[string]string{"z": "<>&\u2028", "a": "quote\"slash\\"}, Nonce: base64.StdEncoding.EncodeToString(make([]byte, 32)), Timestamp: "1"}
	b, err := CanonicalJoin(p)
	if err != nil {
		t.Fatal(err)
	}
	want := `{"pubkey":"` + p.Pubkey + `","requested_routes":["alice.example.com"],"metadata":{"a":"quote\"slash\\","z":"<>&` + "\u2028" + `"},"nonce":"` + p.Nonce + `","timestamp":"1"}`
	if string(b) != want {
		t.Fatalf("canonical:\n%s\nwant:\n%s", b, want)
	}
	bytes, _ := JoinBytes(p)
	j := Join{Envelope: Envelope{Type: "Join", ID: "1"}, Request: p, Signature: base64.StdEncoding.EncodeToString(ed25519.Sign(priv, bytes))}
	data, _ := json.Marshal(j)
	decoded, err := DecodeJoin(data)
	if err != nil || VerifyJoin(decoded, pub) != nil {
		t.Fatalf("verify: %v", err)
	}
	modified := strings.Replace(string(data), `"timestamp":"1"`, `"timestamp":"2"`, 1)
	decoded, err = DecodeJoin([]byte(modified))
	if err != nil || VerifyJoin(decoded, pub) == nil {
		t.Fatal("signed fields were mutable")
	}
	unknown := strings.Replace(string(data), `"request":{`, `"request":{"extra":true,`, 1)
	if _, err := DecodeJoin([]byte(unknown)); err == nil {
		t.Fatal("unknown signed field accepted")
	}
}

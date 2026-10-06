package wire

import (
	"bytes"
	"encoding/hex"
	"io"
	"testing"
)

// Fixed bytes are not generated with the production encoder: an independent
// peer must see a uint32 big-endian JSON length with no newline/BOM.
func TestConformanceControlWireVector(t *testing.T) {
	vector, err := hex.DecodeString("000000187b2274797065223a2250696e67222c226964223a2231227d")
	if err != nil {
		t.Fatal(err)
	}
	// Payload has 24 bytes; encoding must match exactly, including field order
	// of this envelope (unsigned JSON object order is otherwise not normative).
	var output bytes.Buffer
	if err := WriteFrame(&output, Envelope{Type: "Ping", ID: "1"}); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(output.Bytes(), vector) {
		t.Fatalf("encoder got %x want %x", output.Bytes(), vector)
	}
	data, err := ReadFrame(bytes.NewReader(vector))
	if err != nil {
		t.Fatal(err)
	}
	var message Envelope
	if err := Decode(data, &message, "type", "id"); err != nil || message.Type != "Ping" || message.ID != "1" {
		t.Fatalf("decode %+v %v", message, err)
	}
}
func TestConformanceDataHeaderIndependentLayout(t *testing.T) {
	payload := []byte(`{"name":"foo.example.com","remote_addr":"[::1]:1234","scheme":"tls","listener_id":"0123456789abcdef0123456789abcdef","revision":"7"}`)
	// Build the prefix without WriteFrame/binary.PutUint32; exercise actual byte
	// layout, a fragmented reader, and an opaque binary payload directly after it.
	n := len(payload)
	input := []byte{byte(n >> 24), byte(n >> 16), byte(n >> 8), byte(n)}
	input = append(input, payload...)
	input = append(input, 0, 255, 22, 3, 3)
	reader := fragmented{bytes.NewReader(input)}
	header, err := ReadDataHeader(reader)
	if err != nil {
		t.Fatal(err)
	}
	if header.Name != "foo.example.com" || header.RemoteAddr != "[::1]:1234" || header.Revision != "7" {
		t.Fatalf("header %+v", header)
	}
	remainder, err := io.ReadAll(reader)
	if err != nil || !bytes.Equal(remainder, []byte{0, 255, 22, 3, 3}) {
		t.Fatalf("raw bytes consumed: %x %v", remainder, err)
	}
}
func TestConformanceUnknownUnsignedFieldsAndDuplicateNestedFields(t *testing.T) {
	var message Envelope
	if err := Decode([]byte(`{"type":"Ping","id":"1","future":{"flag":true}}`), &message, "type", "id"); err != nil {
		t.Fatal("unknown unsigned field rejected:", err)
	}
	for _, data := range []string{
		`{"type":"Ping","id":"1","future":{"a":1,"a":2}}`,
		`{"type":"Ping","id":"1","future":[{"a":1,"\u0061":2}]}`,
		`{"type":"Ping","id":"1"} {}`,
	} {
		if err := Decode([]byte(data), &message, "type", "id"); err == nil {
			t.Fatalf("invalid JSON accepted: %s", data)
		}
	}
}

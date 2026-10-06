package server

import (
	"bytes"
	"encoding/binary"
	"io"
	"testing"
)

func vector16(data []byte) []byte {
	out := make([]byte, 2, len(data)+2)
	binary.BigEndian.PutUint16(out, uint16(len(data)))
	return append(out, data...)
}
func extension(kind uint16, body []byte) []byte {
	out := make([]byte, 2)
	binary.BigEndian.PutUint16(out, kind)
	return append(out, vector16(body)...)
}
func sniExtension(host string) []byte {
	return extension(0, vector16(append([]byte{0}, vector16([]byte(host))...)))
}
func hello(ext []byte) []byte {
	body := []byte{3, 3}
	body = append(body, make([]byte, 32)...)
	body = append(body, 0)
	body = append(body, 0, 2, 0x13, 1, 1, 0)
	body = append(body, vector16(ext)...)
	return append([]byte{1, byte(len(body) >> 16), byte(len(body) >> 8), byte(len(body))}, body...)
}
func record(data []byte) []byte {
	return append([]byte{22, 3, 1, byte(len(data) >> 8), byte(len(data))}, data...)
}

type oneAtATime struct{ io.Reader }

func (r oneAtATime) Read(p []byte) (int, error) {
	if len(p) > 1 {
		p = p[:1]
	}
	return r.Reader.Read(p)
}

func TestPeekSNIFragmentedRecordsAndReplay(t *testing.T) {
	h := hello(append(sniExtension("Foo.Alice.Example.com."), extension(16, []byte{0, 12, 11, 'a', 'c', 'm', 'e', '-', 't', 'l', 's', '/', '1'})...))
	// Split the handshake header itself, then the body, across TLS records.
	raw := append(record(h[:2]), record(h[2:11])...)
	raw = append(raw, record(h[11:])...)
	input := append(append([]byte{}, raw...), []byte("later encrypted traffic")...)
	reader := bytes.NewReader(input)
	name, prefix, err := peekSNI(oneAtATime{reader})
	if err != nil || name != "foo.alice.example.com" || !bytes.Equal(prefix, raw) {
		t.Fatalf("peek: %s %v", name, err)
	}
	rest, _ := io.ReadAll(reader)
	if string(rest) != "later encrypted traffic" {
		t.Fatal("consumed subsequent bytes")
	}
	// Bytes following ClientHello in its last record are also replayed unchanged.
	bundled := record(append(h, []byte{2, 0, 0, 0}...))
	_, prefix, err = peekSNI(bytes.NewReader(bundled))
	if err != nil || !bytes.Equal(prefix, bundled) {
		t.Fatal("bundled record lost bytes")
	}
}
func TestPeekSNIRejectsMalformed(t *testing.T) {
	duplicateNames := extension(0, vector16(append(append([]byte{0}, vector16([]byte("a.example"))...), append([]byte{0}, vector16([]byte("b.example"))...)...)))
	cases := map[string][]byte{
		"empty":               nil,
		"not TLS":             []byte("GET / HTTP/1.1\r\n"),
		"application record":  {23, 3, 3, 0, 1, 0},
		"zero record":         {22, 3, 3, 0, 0},
		"oversized record":    {22, 3, 3, 0x40, 1},
		"bad version":         {22, 2, 0, 0, 1, 0},
		"wrong handshake":     record([]byte{2, 0, 0, 0}),
		"oversized hello":     record([]byte{1, 255, 255, 255}),
		"no SNI":              record(hello(nil)),
		"duplicate extension": record(hello(append(sniExtension("a.example"), sniExtension("b.example")...))),
		"duplicate names":     record(hello(duplicateNames)),
		"wildcard":            record(hello(sniExtension("*.example.com"))),
		"IP":                  record(hello(sniExtension("127.0.0.1"))),
		"port":                record(hello(sniExtension("a.example:443"))),
		"non ASCII":           record(hello(sniExtension("bücher.example"))),
		"bad extension":       record(hello([]byte{0, 0, 0, 10, 0})),
		"truncated":           record(hello(sniExtension("a.example")))[:20],
	}
	for name, data := range cases {
		t.Run(name, func(t *testing.T) {
			if _, _, err := peekSNI(bytes.NewReader(data)); err == nil {
				t.Fatal("malformed accepted")
			}
		})
	}
}
func TestPeekSNIRejectsAggregateLimit(t *testing.T) {
	// Many small records would otherwise evade a handshake-payload-only bound.
	h := []byte{1, 3, 255, 255}
	raw := record(h)
	for len(raw) <= maxClientHello {
		raw = append(raw, record([]byte{0})...)
	}
	if _, _, err := peekSNI(bytes.NewReader(raw)); err == nil {
		t.Fatal("aggregate limit ignored")
	}
}
func FuzzPeekSNI(f *testing.F) {
	f.Add(record(hello(sniExtension("alice.example.com"))))
	f.Add([]byte{22, 3, 3, 0, 1, 0})
	f.Fuzz(func(t *testing.T, data []byte) { _, _, _ = peekSNI(bytes.NewReader(data)) })
}

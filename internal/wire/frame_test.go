package wire

import (
	"bytes"
	"encoding/binary"
	"errors"
	"io"
	"testing"
)

type fragmented struct{ io.Reader }

func (r fragmented) Read(p []byte) (int, error) {
	if len(p) > 1 {
		p = p[:1]
	}
	return r.Reader.Read(p)
}

func TestFrames(t *testing.T) {
	var buf bytes.Buffer
	for _, id := range []string{"1", "2"} {
		if err := WriteFrame(&buf, Envelope{Type: "Ping", ID: id}); err != nil {
			t.Fatal(err)
		}
	}
	r := fragmented{&buf}
	for _, id := range []string{"1", "2"} {
		data, err := ReadFrame(r)
		if err != nil {
			t.Fatal(err)
		}
		var e Envelope
		if err := Decode(data, &e, "type", "id"); err != nil || e.ID != id {
			t.Fatalf("%+v %v", e, err)
		}
	}
	if _, err := ReadFrame(r); !errors.Is(err, io.EOF) {
		t.Fatalf("EOF: %v", err)
	}
}

func TestInvalidJSON(t *testing.T) {
	for _, data := range [][]byte{
		[]byte(`{"type":"Ping","type":"Join"}`), []byte(`{"nested":{"a":1,"a":2}}`),
		[]byte(`{"id":"\u0000"}`), []byte(`{} {}`), []byte(`[]`), []byte(`{"a":`),
		{'{', '"', 'a', '"', ':', '"', 0xff, '"', '}'},
	} {
		if err := ValidateJSON(data); err == nil {
			t.Errorf("accepted %q", data)
		}
	}
	for _, data := range []string{`{}`, `{"nested":[{"a":"b"},1,true,null]}`} {
		if err := ValidateJSON([]byte(data)); err != nil {
			t.Error(err)
		}
	}
}

func TestBoundsAndFields(t *testing.T) {
	for _, size := range []uint32{0, MaxControlFrame + 1} {
		var prefix [4]byte
		binary.BigEndian.PutUint32(prefix[:], size)
		if _, err := ReadFrame(bytes.NewReader(prefix[:])); err == nil {
			t.Fatal("accepted invalid size")
		}
	}
	for _, data := range []string{`{"type":"Ping"}`, `{"type":"Ping","id":null}`, `{"type":"Ping","id":12}`} {
		var e Envelope
		if err := Decode([]byte(data), &e, "type", "id"); err == nil {
			t.Fatal("accepted missing/null/wrong type")
		}
	}
	for _, s := range []string{"", "01", "-1", "1.0", "18446744073709551616"} {
		if _, err := Counter(s); err == nil {
			t.Fatal("invalid counter")
		}
	}
}

func TestDataHeaderFraming(t *testing.T) {
	var buf bytes.Buffer
	h := DataHeader{Name: "foo.example.com", RemoteAddr: "[::1]:1234", Scheme: "tls", ListenerID: "0123456789abcdef0123456789abcdef", Revision: "9"}
	if err := WriteDataHeader(&buf, h); err != nil {
		t.Fatal(err)
	}
	buf.WriteString("untouched public bytes")
	got, err := ReadDataHeader(fragmented{&buf})
	if err != nil || got != h {
		t.Fatalf("header: %+v %v", got, err)
	}
	if buf.String() != "untouched public bytes" {
		t.Fatal("header consumed payload")
	}
	var prefix [4]byte
	binary.BigEndian.PutUint32(prefix[:], MaxDataHeader+1)
	if _, err := ReadDataHeader(bytes.NewReader(prefix[:])); err == nil {
		t.Fatal("oversize accepted")
	}
	var missing bytes.Buffer
	if err := WriteFrame(&missing, map[string]string{"name": "example.com"}); err != nil {
		t.Fatal(err)
	}
	if _, err := ReadDataHeader(&missing); err == nil {
		t.Fatal("missing fields accepted")
	}
}

func FuzzReadFrame(f *testing.F) {
	f.Add([]byte{0, 0, 0, 2, '{', '}'})
	f.Add([]byte{0xff, 0xff, 0xff, 0xff})
	f.Fuzz(func(t *testing.T, data []byte) { _, _ = ReadFrame(bytes.NewReader(data)) })
}

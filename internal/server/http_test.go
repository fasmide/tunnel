package server

import (
	"bufio"
	"bytes"
	"io"
	"strings"
	"testing"
)

func TestHTTPHeaderBoundsAndStrictFraming(t *testing.T) {
	for _, raw := range []string{
		"GET / HTTP/1.1\nHost: a.example\n\n",
		"GET / HTTP/1.1\r\nHost: a.example\r\n folded: yes\r\n\r\n",
		"POST / HTTP/1.1\r\nHost: a.example\r\nContent-Length: 0\r\nContent-Length: 0\r\n\r\n",
		"POST / HTTP/1.0\r\nHost: a.example\r\nTransfer-Encoding: gzip\r\n\r\n",
		"POST / HTTP/1.1\r\nHost: a.example\r\nContent-Length: +2\r\n\r\n",
		"GET / HTTP/1.1\r\nHost: a.example\r\nX: " + strings.Repeat("a", maxHTTPHeader) + "\r\n\r\n",
		"GET / HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n",
		"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n",
	} {
		if _, _, _, err := readPublicRequest(bufio.NewReader(strings.NewReader(raw))); err == nil {
			t.Errorf("accepted %q", raw[:min(len(raw), 80)])
		}
	}
}
func TestHTTPBodyBoundary(t *testing.T) {
	for _, chunked := range []bool{false, true} {
		body := "hello"
		length := int64(5)
		if chunked {
			body = "5\r\nhello\r\n0\r\nX: trailer\r\n\r\n"
			length = -1
		}
		reader := bufio.NewReader(strings.NewReader(body + "SECOND REQUEST"))
		var output bytes.Buffer
		if err := copyHTTPBody(&output, reader, length, chunked); err != nil {
			t.Fatal(err)
		}
		if output.String() != body {
			t.Fatal("body changed")
		}
		rest, _ := io.ReadAll(reader)
		if string(rest) != "SECOND REQUEST" {
			t.Fatal("pipelined bytes consumed")
		}
	}
	for _, body := range []string{"x\r\n", "1\r\naXX", "0\r\nContent-Length: 1\r\n\r\n", "0\r\nX: bad\x00value\r\n\r\n"} {
		if err := copyHTTPBody(io.Discard, bufio.NewReader(strings.NewReader(body)), -1, true); err == nil {
			t.Fatalf("invalid chunk body %q accepted", body)
		}
	}
}
func FuzzPublicHTTPHeader(f *testing.F) {
	f.Add([]byte("GET / HTTP/1.1\r\nHost: alice.example.com\r\n\r\n"))
	f.Add([]byte("POST / HTTP/1.1\r\nHost: a.example\r\nContent-Length: 0\r\n\r\n"))
	f.Fuzz(func(t *testing.T, data []byte) {
		_, _, _, _ = readPublicRequest(bufio.NewReader(bytes.NewReader(data)))
	})
}

package server

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"strings"

	"github.com/fasmide/tunnel/internal/names"
)

const maxClientHello = 256 * 1024
const maxTLSRecord = 16384

// peekSNI consumes complete TLS handshake records until the first ClientHello
// is complete. Every consumed byte is returned for exact replay. It does not
// construct a tls.Conn or decrypt/terminate any part of the public session.
// The caller must set a read deadline to bound slow fragmented input.
func peekSNI(r io.Reader) (string, []byte, error) {
	raw := make([]byte, 0, 4096)
	handshake := make([]byte, 0, 4096)
	for {
		var header [5]byte
		if _, err := io.ReadFull(r, header[:]); err != nil {
			return "", nil, fmt.Errorf("read TLS record header: %w", err)
		}
		size := int(binary.BigEndian.Uint16(header[3:]))
		if header[0] != 22 || header[1] != 3 || header[2] > 3 || size == 0 || size > maxTLSRecord {
			return "", nil, errors.New("invalid TLS handshake record")
		}
		if len(raw)+5+size > maxClientHello {
			return "", nil, errors.New("ClientHello buffer limit exceeded")
		}
		raw = append(raw, header[:]...)
		start := len(raw)
		raw = append(raw, make([]byte, size)...)
		if _, err := io.ReadFull(r, raw[start:]); err != nil {
			return "", nil, fmt.Errorf("read TLS record body: %w", err)
		}
		handshake = append(handshake, raw[start:]...)
		if len(handshake) < 4 {
			continue
		}
		if handshake[0] != 1 {
			return "", nil, errors.New("first handshake is not ClientHello")
		}
		length := int(handshake[1])<<16 | int(handshake[2])<<8 | int(handshake[3])
		if length+4 > maxClientHello {
			return "", nil, errors.New("ClientHello length limit exceeded")
		}
		if len(handshake) < length+4 {
			continue
		}
		name, err := clientHelloName(handshake[4 : 4+length])
		if err != nil {
			return "", nil, err
		}
		return name, raw, nil
	}
}

type helloCursor struct{ data []byte }

func (c *helloCursor) take(n int) ([]byte, bool) {
	if n < 0 || n > len(c.data) {
		return nil, false
	}
	v := c.data[:n]
	c.data = c.data[n:]
	return v, true
}
func (c *helloCursor) vector(width int) ([]byte, bool) {
	prefix, ok := c.take(width)
	if !ok {
		return nil, false
	}
	size := int(prefix[0])
	if width == 2 {
		size = int(binary.BigEndian.Uint16(prefix))
	}
	return c.take(size)
}
func clientHelloName(body []byte) (string, error) {
	malformed := errors.New("malformed TLS ClientHello")
	c := helloCursor{data: body}
	version, ok := c.take(2)
	if !ok || version[0] != 3 || version[1] < 1 || version[1] > 3 {
		return "", malformed
	}
	if _, ok := c.take(32); !ok {
		return "", malformed
	}
	session, ok := c.vector(1)
	if !ok || len(session) > 32 {
		return "", malformed
	}
	suites, ok := c.vector(2)
	if !ok || len(suites) < 2 || len(suites)%2 != 0 {
		return "", malformed
	}
	compression, ok := c.vector(1)
	if !ok || len(compression) == 0 {
		return "", malformed
	}
	extensions, ok := c.vector(2)
	if !ok || len(c.data) != 0 {
		return "", malformed
	}
	ext := helloCursor{data: extensions}
	seen := map[uint16]bool{}
	name := ""
	for len(ext.data) > 0 {
		kind, ok := ext.take(2)
		if !ok {
			return "", malformed
		}
		typ := binary.BigEndian.Uint16(kind)
		payload, ok := ext.vector(2)
		if !ok || seen[typ] {
			return "", malformed
		}
		seen[typ] = true
		if typ != 0 {
			continue
		}
		sni := helloCursor{data: payload}
		list, ok := sni.vector(2)
		if !ok || len(list) == 0 || len(sni.data) != 0 {
			return "", malformed
		}
		entries := helloCursor{data: list}
		types := map[byte]bool{}
		for len(entries.data) > 0 {
			kind, ok := entries.take(1)
			if !ok || types[kind[0]] {
				return "", malformed
			}
			types[kind[0]] = true
			host, ok := entries.vector(2)
			if !ok || len(host) == 0 {
				return "", malformed
			}
			if kind[0] != 0 {
				return "", errors.New("unsupported SNI name type")
			}
			// Only visible ASCII DNS SNI is routable; do not decode an ECH inner name.
			for _, b := range host {
				if b >= 128 {
					return "", malformed
				}
			}
			name = strings.TrimSuffix(strings.ToLower(string(host)), ".")
			if !names.Valid(name) {
				return "", errors.New("invalid DNS SNI")
			}
		}
	}
	if name == "" {
		return "", errors.New("visible DNS SNI required")
	}
	return name, nil
}

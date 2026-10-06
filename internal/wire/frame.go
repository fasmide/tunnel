// Package wire implements the bounded JSON frames in PROTOCOL.md.
package wire

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"
	"unicode/utf8"
)

const ALPN = "selfhost-tunnel/1"
const MaxControlFrame = 65536

// ReadFrame reads exactly one frame. The caller supplies stream deadlines.
func ReadFrame(r io.Reader) ([]byte, error) { return readFrame(r, MaxControlFrame) }

func readFrame(r io.Reader, limit uint32) ([]byte, error) {
	var prefix [4]byte
	if _, err := io.ReadFull(r, prefix[:]); err != nil {
		return nil, fmt.Errorf("read frame length prefix: %w", err)
	}
	size := binary.BigEndian.Uint32(prefix[:])
	if size == 0 || size > limit {
		return nil, fmt.Errorf("invalid frame length %d", size)
	}
	data := make([]byte, int(size))
	if _, err := io.ReadFull(r, data); err != nil {
		return nil, fmt.Errorf("read frame body: %w", err)
	}
	if err := ValidateJSON(data); err != nil {
		return nil, fmt.Errorf("validate frame JSON: %w", err)
	}
	return data, nil
}

// Admin frames use a separate local-only limit; tunnel control stays at 64 KiB.
func ReadAdminFrame(r io.Reader) ([]byte, error)   { return readFrame(r, 32*1024*1024) }
func WriteAdminFrame(w io.Writer, value any) error { return writeFrame(w, value, 32*1024*1024) }
func WriteFrame(w io.Writer, value any) error      { return writeFrame(w, value, MaxControlFrame) }
func writeFrame(w io.Writer, value any, limit int) error {
	data, err := json.Marshal(value)
	if err != nil {
		return fmt.Errorf("marshal frame: %w", err)
	}
	if len(data) == 0 || len(data) > limit {
		return errors.New("control frame too large")
	}
	if err := ValidateJSON(data); err != nil {
		return fmt.Errorf("validate marshaled frame JSON: %w", err)
	}
	var prefix [4]byte
	binary.BigEndian.PutUint32(prefix[:], uint32(len(data)))
	if err := writeAll(w, prefix[:]); err != nil {
		return fmt.Errorf("write frame length prefix: %w", err)
	}
	if err := writeAll(w, data); err != nil {
		return fmt.Errorf("write frame body: %w", err)
	}
	return nil
}

func writeAll(w io.Writer, data []byte) error {
	for len(data) > 0 {
		n, err := w.Write(data)
		if n < 0 || n > len(data) {
			return errors.New("invalid write count")
		}
		data = data[n:]
		if err != nil {
			return fmt.Errorf("write frame bytes: %w", err)
		}
		if n == 0 {
			return io.ErrShortWrite
		}
	}
	return nil
}

// ValidateJSON rejects duplicate keys at every nesting level, invalid UTF-8,
// NULs, non-object frames, trailing values, and excessive nesting.
func ValidateJSON(data []byte) error {
	if !utf8.Valid(data) {
		return errors.New("invalid UTF-8")
	}
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.UseNumber()
	token, err := dec.Token()
	if err != nil {
		return fmt.Errorf("read first JSON token: %w", err)
	}
	if token != json.Delim('{') {
		return errors.New("frame must be an object")
	}
	if err := walk(dec, token, 0); err != nil {
		return err
	}
	if _, err := dec.Token(); err != io.EOF {
		return errors.New("trailing JSON data")
	}
	return nil
}

func walk(dec *json.Decoder, token json.Token, depth int) error {
	if depth > 64 {
		return errors.New("JSON nesting limit")
	}
	if str, ok := token.(string); ok && strings.ContainsRune(str, 0) {
		return errors.New("NUL in string")
	}
	delim, ok := token.(json.Delim)
	if !ok {
		return nil
	}
	switch delim {
	case '{':
		seen := map[string]bool{}
		for dec.More() {
			key, err := dec.Token()
			if err != nil {
				return fmt.Errorf("read object key token: %w", err)
			}
			s, ok := key.(string)
			if !ok || seen[s] || strings.ContainsRune(s, 0) {
				return errors.New("duplicate or invalid object key")
			}
			seen[s] = true
			v, err := dec.Token()
			if err != nil {
				return fmt.Errorf("read object value token: %w", err)
			}
			if err := walk(dec, v, depth+1); err != nil {
				return err
			}
		}
		end, err := dec.Token()
		if err != nil || end != json.Delim('}') {
			return errors.New("invalid object ending")
		}
	case '[':
		for dec.More() {
			v, err := dec.Token()
			if err != nil {
				return fmt.Errorf("read array value token: %w", err)
			}
			if err := walk(dec, v, depth+1); err != nil {
				return err
			}
		}
		end, err := dec.Token()
		if err != nil || end != json.Delim(']') {
			return errors.New("invalid array ending")
		}
	default:
		return errors.New("unexpected JSON delimiter")
	}
	return nil
}

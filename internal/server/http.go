package server

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"
)

const maxHTTPHeader = 64 * 1024

var httpReaderPool = sync.Pool{New: func() any { return bufio.NewReaderSize(nil, 4096) }}

func getHTTPReader(r io.Reader) *bufio.Reader {
	reader, ok := httpReaderPool.Get().(*bufio.Reader)
	if !ok {
		reader = bufio.NewReaderSize(nil, 4096)
	}
	reader.Reset(r)
	return reader
}

func putHTTPReader(reader *bufio.Reader) {
	if reader == nil {
		return
	}
	reader.Reset(nil)
	httpReaderPool.Put(reader)
}

// readHTTPHeader reads only the header, retaining its exact bytes. Strict CRLF,
// no folding, and no duplicate Host/Content-Length avoid ambiguous framing.
func readHTTPHeader(r *bufio.Reader) ([]byte, error) {
	raw := []byte{}
	first := true
	counts := map[string]int{}
	for {
		line, err := readHTTPLine(r, maxHTTPHeader-len(raw))
		if err != nil {
			return nil, err
		}
		raw = append(raw, line...)
		if first {
			first = false
			continue
		}
		if len(line) == 2 {
			break
		}
		text := string(line[:len(line)-2])
		key, value, ok := strings.Cut(text, ":")
		if !ok || !httpToken(key) {
			return nil, errors.New("invalid HTTP header field")
		}
		for _, b := range []byte(value) {
			if b < 32 && b != '\t' || b == 127 {
				return nil, errors.New("invalid HTTP header value")
			}
		}
		key = strings.ToLower(key)
		if key == "transfer-encoding" && !strings.EqualFold(strings.TrimSpace(value), "chunked") {
			return nil, errors.New("unsupported transfer coding")
		}
		if key == "content-length" {
			value = strings.TrimSpace(value)
			if value == "" {
				return nil, errors.New("empty Content-Length")
			}
			for _, c := range value {
				if c < '0' || c > '9' {
					return nil, errors.New("invalid Content-Length")
				}
			}
		}
		counts[key]++
		if counts[key] > 1 && (key == "host" || key == "content-length" || key == "transfer-encoding") {
			return nil, errors.New("ambiguous HTTP framing/Host")
		}
	}
	if counts["content-length"] > 0 && counts["transfer-encoding"] > 0 {
		return nil, errors.New("Transfer-Encoding with Content-Length")
	}
	return raw, nil
}
func readHTTPLine(r *bufio.Reader, limit int) ([]byte, error) {
	if limit < 2 {
		return nil, errors.New("HTTP header/line limit exceeded")
	}
	line := []byte{}
	for {
		part, err := r.ReadSlice('\n')
		if len(line)+len(part) > limit {
			return nil, errors.New("HTTP header/line limit exceeded")
		}
		line = append(line, part...)
		if errors.Is(err, bufio.ErrBufferFull) {
			continue
		}
		if err != nil {
			return nil, fmt.Errorf("read HTTP line: %w", err)
		}
		if len(line) < 2 || line[len(line)-2] != '\r' {
			return nil, errors.New("HTTP requires CRLF")
		}
		return line, nil
	}
}
func httpToken(s string) bool {
	if s == "" {
		return false
	}
	for _, c := range s {
		if (c < 'a' || c > 'z') && (c < 'A' || c > 'Z') && (c < '0' || c > '9') && !strings.ContainsRune("!#$%&'*+-.^_`|~", c) {
			return false
		}
	}
	return true
}
func httpHost(value string) (string, error) {
	if strings.TrimSpace(value) != value {
		return "", errors.New("invalid Host")
	}
	host := value
	if strings.Contains(value, ":") {
		h, p, err := net.SplitHostPort(value)
		if err != nil {
			return "", errors.New("invalid Host port")
		}
		port, err := strconv.ParseUint(p, 10, 16)
		if err != nil || port == 0 {
			return "", errors.New("invalid Host port")
		}
		host = h
	}
	host = strings.TrimSuffix(strings.ToLower(host), ".")
	if !ValidName(host) {
		return "", errors.New("invalid DNS Host")
	}
	return host, nil
}
func readPublicRequest(r *bufio.Reader) (*http.Request, string, []byte, error) {
	raw, err := readHTTPHeader(r)
	if err != nil {
		return nil, "", nil, err
	}
	headerReader := getHTTPReader(bytes.NewReader(raw))
	defer putHTTPReader(headerReader)
	req, err := http.ReadRequest(headerReader)
	if err != nil {
		return nil, "", nil, fmt.Errorf("parse public HTTP request: %w", err)
	}
	if req.ProtoMajor != 1 || req.ProtoMinor > 1 || !httpToken(req.Method) || req.Method == http.MethodConnect || req.Header.Get("Upgrade") != "" || headerToken(req.Header, "Connection", "upgrade") {
		return nil, "", nil, errors.New("unsupported HTTP request")
	}
	if !strings.HasPrefix(req.RequestURI, "/") || strings.HasPrefix(req.RequestURI, "//") {
		return nil, "", nil, errors.New("origin-form request target required")
	}
	parsed, err := url.ParseRequestURI(req.RequestURI)
	if err != nil || parsed.IsAbs() || parsed.Host != "" {
		return nil, "", nil, errors.New("invalid origin target")
	}
	for _, b := range []byte(req.RequestURI) {
		if b <= 32 || b == 127 {
			return nil, "", nil, errors.New("invalid request target")
		}
	}
	if req.ProtoMinor == 0 {
		for _, line := range strings.Split(string(raw), "\r\n")[1:] {
			key, _, ok := strings.Cut(line, ":")
			if ok && strings.EqualFold(key, "Transfer-Encoding") {
				return nil, "", nil, errors.New("HTTP/1.0 transfer coding is unsupported")
			}
		}
	}
	host, err := httpHost(req.Host)
	if err != nil {
		return nil, "", nil, err
	}
	if len(req.TransferEncoding) > 1 || len(req.TransferEncoding) == 1 && req.TransferEncoding[0] != "chunked" {
		return nil, "", nil, errors.New("unsupported transfer coding")
	}
	return req, host, raw, nil
}
func headerToken(h http.Header, key, token string) bool {
	for _, v := range h.Values(key) {
		for _, s := range strings.Split(v, ",") {
			if strings.EqualFold(strings.TrimSpace(s), token) {
				return true
			}
		}
	}
	return false
}

// copyHTTPBody preserves framing bytes while stopping exactly at the first
// message boundary. Buffered pipelined bytes stay in r and are never relayed.
func copyHTTPBody(w io.Writer, r *bufio.Reader, length int64, chunked bool) error {
	if !chunked {
		if length < 0 {
			_, err := io.Copy(w, r)
			if err != nil {
				return fmt.Errorf("copy HTTP body: %w", err)
			}
			return nil
		}
		_, err := io.CopyN(w, r, length)
		if err != nil {
			return fmt.Errorf("copy fixed-length HTTP body: %w", err)
		}
		return nil
	}
	for {
		line, err := readHTTPLine(r, 8192)
		if err != nil {
			return err
		}
		text := string(line[:len(line)-2])
		sizeText, _, _ := strings.Cut(text, ";")
		if sizeText == "" {
			return errors.New("empty chunk size")
		}
		for _, c := range sizeText {
			if (c < '0' || c > '9') && (c < 'a' || c > 'f') && (c < 'A' || c > 'F') {
				return errors.New("invalid chunk size")
			}
		}
		for _, b := range []byte(text) {
			if b < 32 || b == 127 {
				return errors.New("invalid chunk extension")
			}
		}
		size, err := strconv.ParseUint(sizeText, 16, 63)
		if err != nil {
			return fmt.Errorf("parse chunk size: %w", err)
		}
		if _, err = w.Write(line); err != nil {
			return fmt.Errorf("write chunk header: %w", err)
		}
		if size == 0 {
			total := 0
			for {
				trailer, err := readHTTPLine(r, maxHTTPHeader-total)
				if err != nil {
					return err
				}
				total += len(trailer)
				if len(trailer) > 2 {
					key, value, ok := strings.Cut(string(trailer[:len(trailer)-2]), ":")
					for _, b := range []byte(value) {
						if b < 32 && b != '\t' || b == 127 {
							return errors.New("invalid trailer value")
						}
					}
					if !ok || !httpToken(key) || strings.EqualFold(key, "Host") || strings.EqualFold(key, "Content-Length") || strings.EqualFold(key, "Transfer-Encoding") {
						return errors.New("invalid chunk trailer")
					}
				}
				if _, err = w.Write(trailer); err != nil {
					return fmt.Errorf("write chunk trailer: %w", err)
				}
				if len(trailer) == 2 {
					return nil
				}
			}
		}
		if _, err = io.CopyN(w, r, int64(size)); err != nil {
			return fmt.Errorf("copy chunk body: %w", err)
		}
		var end [2]byte
		if _, err = io.ReadFull(r, end[:]); err != nil {
			return fmt.Errorf("read chunk ending: %w", err)
		}
		if end != [2]byte{'\r', '\n'} {
			return errors.New("invalid chunk ending")
		}
		if _, err = w.Write(end[:]); err != nil {
			return fmt.Errorf("write chunk ending: %w", err)
		}
	}
}
func copyHTTPResponse(public io.Writer, r *bufio.Reader, request *http.Request) error {
	for count := 0; count < 16; count++ {
		raw, err := readHTTPHeader(r)
		if err != nil {
			return err
		}
		headerReader := getHTTPReader(bytes.NewReader(raw))
		response, err := http.ReadResponse(headerReader, request)
		putHTTPReader(headerReader)
		if err != nil {
			return fmt.Errorf("parse HTTP response: %w", err)
		}
		if response.ProtoMajor != 1 || response.ProtoMinor > 1 || response.StatusCode == http.StatusSwitchingProtocols {
			_ = response.Body.Close()
			return errors.New("unsupported HTTP response")
		}
		if _, err = public.Write(raw); err != nil {
			return fmt.Errorf("write public HTTP response header: %w", err)
		}
		if response.StatusCode < 200 {
			if err := response.Body.Close(); err != nil {
				return fmt.Errorf("close informational HTTP response body: %w", err)
			}
			continue
		}
		if request.Method == http.MethodHead || response.StatusCode == http.StatusNoContent || response.StatusCode == http.StatusNotModified {
			if err := response.Body.Close(); err != nil {
				return fmt.Errorf("close empty HTTP response body: %w", err)
			}
			return nil
		}
		return copyHTTPBody(public, r, response.ContentLength, len(response.TransferEncoding) > 0)
	}
	return errors.New("too many informational responses")
}
func (s *Server) serveHTTP(ctx context.Context, public net.Conn) {
	if err := public.SetReadDeadline(time.Now().Add(10 * time.Second)); err != nil {
		return
	}
	reader := getHTTPReader(public)
	defer putHTTPReader(reader)
	request, host, raw, err := readPublicRequest(reader)
	if err != nil {
		httpEdgeError(public, 400)
		return
	}
	if err := public.SetReadDeadline(time.Time{}); err != nil {
		return
	}
	stream, release, stats, err := s.openForward(public, host, "http")
	if errors.Is(err, errNoPool) {
		if err := public.SetWriteDeadline(time.Now().Add(10 * time.Second)); err != nil {
			return
		}
		_, _ = fmt.Fprintf(public, "HTTP/1.1 308 Permanent Redirect\r\nLocation: https://%s%s\r\nConnection: close\r\nContent-Length: 0\r\n\r\n", host, request.RequestURI)
		return
	}
	if err != nil {
		httpEdgeError(public, 503)
		return
	}
	defer release()
	defer stream.CancelRead(0)
	defer stream.CancelWrite(0)
	// Bound stalled body/response I/O. Server/edge cancellation closes public too.
	if err := public.SetDeadline(time.Now().Add(2 * time.Minute)); err != nil {
		return
	}
	if err := stream.SetDeadline(time.Now().Add(2 * time.Minute)); err != nil {
		return
	}
	stop := context.AfterFunc(ctx, func() { _ = public.Close(); stream.CancelRead(5); stream.CancelWrite(5) })
	defer stop()
	requestDone := make(chan error, 1)
	go func() {
		writer := io.Writer(stream)
		if stats != nil {
			writer = countingWriter{writer: stream, total: &stats.rxBytes}
		}
		_, err := writer.Write(raw)
		if err == nil {
			err = copyHTTPBody(writer, reader, request.ContentLength, len(request.TransferEncoding) > 0)
		}
		if err == nil {
			err = stream.Close()
		} else {
			stream.CancelWrite(5)
			stream.CancelRead(5)
			_ = public.Close()
		}
		requestDone <- err
	}()
	// Read responses concurrently: Expect: 100-continue must not deadlock uploads.
	responseReader := getHTTPReader(stream)
	responseWriter := io.Writer(public)
	if stats != nil {
		responseWriter = countingWriter{writer: public, total: &stats.txBytes}
	}
	_ = copyHTTPResponse(responseWriter, responseReader, request)
	putHTTPReader(responseReader)
	// One final response completes the exchange even if the backend keeps alive
	// or responds before finishing the request body. Never read a second request.
	_ = public.Close()
	stream.CancelWrite(0)
	stream.CancelRead(0)
	<-requestDone
}
func httpEdgeError(public net.Conn, status int) {
	if err := public.SetWriteDeadline(time.Now().Add(10 * time.Second)); err != nil {
		return
	}
	_, _ = fmt.Fprintf(public, "HTTP/1.1 %d %s\r\nConnection: close\r\nContent-Length: 0\r\n\r\n", status, http.StatusText(status))
}

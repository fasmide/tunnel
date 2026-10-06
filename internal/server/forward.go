package server

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"strconv"
	"sync/atomic"
	"time"

	"github.com/fasmide/tunnel/internal/wire"
	quic "github.com/quic-go/quic-go"
)

type forwarding struct {
	host, listenerID string
	initializing     bool
	public           net.Conn
	stream           *quic.Stream
}

type countingWriter struct {
	writer io.Writer
	total  *atomic.Uint64
}

func (w countingWriter) write(p []byte) (int, error) {
	n, err := w.writer.Write(p)
	if n > 0 {
		w.total.Add(uint64(n))
	}
	if err != nil {
		return n, fmt.Errorf("counted write: %w", err)
	}
	return n, nil
}

func (w countingWriter) Write(p []byte) (int, error) {
	return w.write(p)
}

// Called under manager.mu; cancel operations never wait for I/O completion.
func (f *forwarding) abort() {
	if f.stream != nil {
		f.stream.CancelRead(2)
		f.stream.CancelWrite(2)
	}
	_ = f.public.Close()
}

// Forward owns public and closes it on return. host must already have been
// determined by the public edge; prefix is the bytes consumed while peeking.
// This stage supports TLS/raw bytes only, not one-shot HTTP framing.
func (s *Server) Forward(ctx context.Context, public net.Conn, host string, prefix []byte) error {
	defer func() { _ = public.Close() }()
	if err := ctx.Err(); err != nil {
		return fmt.Errorf("forward context: %w", err)
	}
	if !ValidName(host) {
		return errors.New("invalid public host")
	}
	stream, release, stats, err := s.openForward(public, host, "tls")
	if err != nil {
		return err
	}
	defer release()
	return relayRaw(ctx, public, stream, prefix, stats)
}

var errNoPool = errors.New("no eligible tunnel pool")

func (s *Server) openForward(public net.Conn, host, class string) (*quic.Stream, func(), *routeStats, error) {
	m := s.manager
	// Stream opening is nonblocking under the same lock as pool removal. A
	// concurrent unadvertise cancels pending header writes before acknowledging.
	m.mu.Lock()
	owner := m.ownerLocked(host)
	var member Selection
	var target *session
	for _, parent := range parents(host) {
		p := m.pools[poolKey{parent, class}]
		if p == nil || p.owner != owner || len(p.members) == 0 {
			continue
		}
		member = p.members[p.next%uint64(len(p.members))]
		p.next++
		target = m.sessions[member.SessionID]
		break
	}
	if target == nil {
		m.mu.Unlock()
		return nil, nil, nil, errNoPool
	}
	if target.conn == nil || len(target.active) >= 256 || m.stateErr != nil {
		m.mu.Unlock()
		return nil, nil, nil, errors.New("tunnel pool unavailable")
	}
	stream, err := target.conn.OpenStream()
	if err != nil {
		m.mu.Unlock()
		return nil, nil, nil, fmt.Errorf("open tunnel stream: %w", err)
	}
	stats := m.routeStatsLocked(host)
	stats.connections.Add(1)
	f := &forwarding{host: host, listenerID: member.ListenerID, initializing: true, public: public, stream: stream}
	target.active[f] = true
	target.lastStreamID = int64(stream.StreamID())
	h := wire.DataHeader{Name: host, RemoteAddr: public.RemoteAddr().String(), Scheme: class, ListenerID: member.ListenerID, Revision: strconv.FormatUint(m.revision, 10)}
	m.mu.Unlock()
	if err := stream.SetWriteDeadline(time.Now().Add(10 * time.Second)); err != nil {
		m.mu.Unlock()
		return nil, nil, nil, fmt.Errorf("set data header deadline: %w", err)
	}
	err = wire.WriteDataHeader(stream, h)
	if clearErr := stream.SetWriteDeadline(time.Time{}); clearErr != nil && err == nil {
		err = clearErr
	}
	m.mu.Lock()
	f.initializing = false
	m.mu.Unlock()
	release := func() { stream.CancelRead(0); m.mu.Lock(); delete(target.active, f); m.mu.Unlock() }
	if err != nil {
		stream.CancelRead(5)
		stream.CancelWrite(5)
		release()
		return nil, nil, nil, err
	}
	return stream, release, stats, nil
}

func relayRaw(ctx context.Context, public net.Conn, stream *quic.Stream, prefix []byte, stats *routeStats) error {
	done := make(chan struct{})
	go func() {
		select {
		case <-ctx.Done():
			_ = public.Close()
			stream.CancelRead(5)
			stream.CancelWrite(5)
		case <-done:
		}
	}()
	defer close(done)
	results := make(chan error, 2)
	go func() {
		var err error
		writer := io.Writer(stream)
		if stats != nil {
			writer = countingWriter{writer: stream, total: &stats.rxBytes}
		}
		if len(prefix) > 0 {
			_, err = writer.Write(prefix)
		} else {
			err = nil
		}
		if err == nil {
			_, err = io.Copy(writer, public)
		}
		if err == nil {
			err = stream.Close()
		} else {
			stream.CancelWrite(5)
			stream.CancelRead(5)
			_ = public.Close()
		}
		results <- err
	}()
	go func() {
		reader := io.Reader(stream)
		if stats != nil {
			reader = io.TeeReader(stream, countingWriter{writer: io.Discard, total: &stats.txBytes})
		}
		_, e := io.Copy(public, reader)
		if e == nil {
			if half, ok := public.(interface{ CloseWrite() error }); ok {
				e = half.CloseWrite()
			} else {
				_ = public.Close()
			}
		} else {
			_ = public.Close()
			stream.CancelRead(5)
		}
		results <- e
	}()
	first, second := <-results, <-results
	if first != nil {
		return first
	}
	return second
}

// Package streamconn adapts QUIC bidirectional streams to net.Conn.
package streamconn

import (
	"errors"
	"fmt"
	"io"
	"net"
	"sync"
	"time"

	quic "github.com/quic-go/quic-go"
)

type Conn struct {
	Stream              *quic.Stream
	Local, Remote       net.Addr
	OnClose             func()
	once                sync.Once
	mu                  sync.Mutex
	readDone, writeDone bool
}

func (c *Conn) directionDone(read bool) {
	c.mu.Lock()
	if read {
		c.readDone = true
	} else {
		c.writeDone = true
	}
	finished := c.readDone && c.writeDone
	c.mu.Unlock()
	if finished {
		c.once.Do(func() {
			if c.OnClose != nil {
				c.OnClose()
			}
		})
	}
}

func (c *Conn) Read(p []byte) (int, error) {
	n, err := c.Stream.Read(p)
	if err != nil {
		var timeout net.Error
		isTimeout := errors.As(err, &timeout) && timeout.Timeout()
		if !isTimeout {
			c.directionDone(true)
		}
		if errors.Is(err, io.EOF) || isTimeout {
			// Preserve plain EOF/timeout semantics for net.Conn callers.
			return n, err //nolint:wrapcheck
		}
		return n, fmt.Errorf("read stream: %w", err)
	}
	return n, nil
}
func (c *Conn) Write(p []byte) (int, error) {
	n, err := c.Stream.Write(p)
	if err != nil {
		var timeout net.Error
		if !errors.As(err, &timeout) || !timeout.Timeout() {
			c.directionDone(false)
		}
		return n, fmt.Errorf("write stream: %w", err)
	}
	return n, nil
}
func (c *Conn) Close() error {
	err := c.Stream.Close()
	c.Stream.CancelRead(0)
	c.once.Do(func() {
		if c.OnClose != nil {
			c.OnClose()
		}
	})
	if err != nil {
		return fmt.Errorf("close stream: %w", err)
	}
	return nil
}
func (c *Conn) Abort() {
	c.Stream.CancelWrite(5)
	c.Stream.CancelRead(5)
	c.once.Do(func() {
		if c.OnClose != nil {
			c.OnClose()
		}
	})
}
func (c *Conn) CloseWrite() error {
	err := c.Stream.Close()
	c.directionDone(false)
	if err != nil {
		return fmt.Errorf("close stream write side: %w", err)
	}
	return nil
}
func (c *Conn) LocalAddr() net.Addr  { return c.Local }
func (c *Conn) RemoteAddr() net.Addr { return c.Remote }
func (c *Conn) SetDeadline(t time.Time) error {
	if err := c.Stream.SetDeadline(t); err != nil {
		return fmt.Errorf("set stream deadline: %w", err)
	}
	return nil
}
func (c *Conn) SetReadDeadline(t time.Time) error {
	if err := c.Stream.SetReadDeadline(t); err != nil {
		return fmt.Errorf("set stream read deadline: %w", err)
	}
	return nil
}
func (c *Conn) SetWriteDeadline(t time.Time) error {
	if err := c.Stream.SetWriteDeadline(t); err != nil {
		return fmt.Errorf("set stream write deadline: %w", err)
	}
	return nil
}

var _ net.Conn = (*Conn)(nil)

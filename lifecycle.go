package tunnel

import (
	"context"
	"errors"
	"fmt"
	"net"
	"strconv"
	"time"

	"github.com/fasmide/tunnel/internal/wire"
)

func (c *Client) unadvertise(ctx context.Context, s *clientSession, id string) (int64, error) {
	data, err := c.rpcSession(ctx, s, &wire.Unadvertise{Envelope: wire.Envelope{Type: "Unadvertise"}, ListenerID: id})
	if err != nil {
		return -1, err
	}
	var ack wire.Unadvertise
	if err := wire.DecodeFrame(data, &ack, "type", "id", "listener_id", "ack", "last_stream_id"); err != nil {
		return -1, fmt.Errorf("decode unadvertise acknowledgement: %w", err)
	}
	if !ack.Ack || ack.ListenerID != id {
		return -1, errors.New("invalid Unadvertise acknowledgement")
	}
	last, err := strconv.ParseInt(ack.LastStreamID, 10, 64)
	if err != nil || strconv.FormatInt(last, 10) != ack.LastStreamID || last < -1 || last >= 0 && last%4 != 1 {
		return -1, errors.New("invalid stream watermark")
	}
	return last, nil
}

// CloseGracefully removes all pool members, allows allocated streams to be
// accepted and finish, then closes the transport. Deadline/cancellation aborts
// the remainder. No reconnect or new listeners are started during draining.
func (c *Client) CloseGracefully(ctx context.Context) error {
	// Interrupt an RPC/re-advertise already holding ops when the drain deadline
	// expires. Closing Client is safe without acquiring ops.
	stop := context.AfterFunc(ctx, func() { c.fail(ctx.Err()) })
	defer stop()
	c.ops.Lock()
	defer c.ops.Unlock()
	if err := ctx.Err(); err != nil {
		wrapped := fmt.Errorf("graceful close canceled before start: %w", err)
		c.fail(wrapped)
		return wrapped
	}
	c.mu.Lock()
	if c.terminal != nil {
		err := c.terminal
		c.mu.Unlock()
		if errors.Is(err, net.ErrClosed) {
			return nil
		}
		return err
	}
	s := c.session
	if c.status != "connected" {
		c.mu.Unlock()
		c.fail(net.ErrClosed)
		return errors.New("cannot drain disconnected tunnel")
	}
	c.status = "draining"
	c.signalLocked()
	listeners := []*rawListener{}
	for _, l := range c.listeners {
		listeners = append(listeners, l)
	}
	c.mu.Unlock()
	last := int64(-1)
	for _, l := range listeners {
		watermark, err := c.unadvertise(ctx, s, l.id)
		if err != nil {
			c.fail(err)
			if ctx.Err() != nil {
				return fmt.Errorf("graceful close canceled during unadvertise: %w", ctx.Err())
			}
			return err
		}
		if watermark > last {
			last = watermark
		}
	}
	// Keep Accept queues open until all allocated headers/handshakes have been
	// processed. Only then can an empty queue return net.ErrClosed safely.
	for {
		c.mu.Lock()
		if c.terminal != nil {
			err := c.terminal
			c.mu.Unlock()
			if ctx.Err() != nil {
				return fmt.Errorf("graceful close canceled while waiting for drain: %w", ctx.Err())
			}
			return err
		}
		barrier := c.acceptedStream >= last && c.receiving == 0
		active := len(c.active)
		changed := c.changed
		c.mu.Unlock()
		if barrier {
			for _, l := range listeners {
				l.mu.Lock()
				l.draining = true
				l.signal()
				l.mu.Unlock()
			}
			if active == 0 {
				// QUIC Close queues FIN but does not wait for delivery. Ask the server
				// whether its forwarding copies have finished before closing transport.
				data, err := c.rpcSession(ctx, s, &wire.Envelope{Type: "Ping"})
				if err != nil {
					c.fail(err)
					if ctx.Err() != nil {
						return fmt.Errorf("graceful close canceled while waiting for remote drain: %w", ctx.Err())
					}
					return err
				}
				var pong wire.Pong
				if err := wire.DecodeFrame(data, &pong, "type", "id", "active_streams"); err != nil {
					wrapped := fmt.Errorf("decode drain ping response: %w", err)
					c.fail(wrapped)
					return wrapped
				}
				remote, err := wire.Counter(pong.ActiveStreams)
				if err != nil {
					wrapped := fmt.Errorf("parse remote active stream count: %w", err)
					c.fail(wrapped)
					return wrapped
				}
				if remote == 0 {
					c.fail(net.ErrClosed)
					return nil
				}
			}
		}
		select {
		case <-ctx.Done():
			wrapped := fmt.Errorf("graceful close canceled while waiting for local drain: %w", ctx.Err())
			c.fail(wrapped)
			return wrapped
		case <-changed:
		case <-time.After(10 * time.Millisecond):
		case <-s.done:
			c.fail(s.err)
			return s.err
		case <-c.done:
		}
	}
}

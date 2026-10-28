package server

import (
	"context"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/fasmide/tunnel/internal/wire"
	quic "github.com/quic-go/quic-go"
)

type headerTestStream struct {
	deadlineCalls int
	failDeadline  int
	writeErr      error
	readCanceled  bool
	writeCanceled bool
	readCode      quic.StreamErrorCode
	writeCode     quic.StreamErrorCode
	err           error
}

func (s *headerTestStream) SetWriteDeadline(time.Time) error {
	s.deadlineCalls++
	if s.deadlineCalls == s.failDeadline {
		return s.err
	}
	return nil
}
func (s *headerTestStream) Write(p []byte) (int, error) {
	if s.writeErr != nil {
		return 0, s.writeErr
	}
	return len(p), nil
}
func (s *headerTestStream) CancelRead(code quic.StreamErrorCode) {
	s.readCanceled, s.readCode = true, code
}
func (s *headerTestStream) CancelWrite(code quic.StreamErrorCode) {
	s.writeCanceled, s.writeCode = true, code
}

func TestForwardStatsFollowServingListener(t *testing.T) {
	m := NewManager()
	cert, pub := testCertificate(t, false)
	approve(t, m, pub, "example.net", "exact.example.net")
	s, roots := testServer(t, m)
	conn, control := dialTest(t, s, roots, cert)
	request(t, control, wire.Envelope{Type: "RouteList", ID: "1"}, "1")
	data := request(t, control, wire.Advertise{
		Envelope:   wire.Envelope{Type: "Advertise", ID: "2"},
		ListenerID: strings.Repeat("a", 32), Name: "example.net", Mode: "raw", Revision: m.Revision(),
	}, "2")
	var ack wire.AdvertiseAck
	if err := json.Unmarshal(data, &ack); err != nil || !ack.OK {
		t.Fatalf("advertise: %s, %v", data, err)
	}

	listener, err := net.ListenTCP("tcp", &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	const payload, response = "request bytes", "response bytes"
	forward := func(host string) {
		t.Helper()
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		visitor, err := net.DialTCP("tcp", nil, listener.Addr().(*net.TCPAddr))
		if err != nil {
			t.Fatal(err)
		}
		defer visitor.Close()
		public, err := listener.AcceptTCP()
		if err != nil {
			t.Fatal(err)
		}
		defer public.Close()
		if err := visitor.SetDeadline(time.Now().Add(3 * time.Second)); err != nil {
			t.Fatal(err)
		}
		backendDone := make(chan error, 1)
		go func() {
			backendDone <- func() error {
				stream, err := conn.AcceptStream(ctx)
				if err != nil {
					return err
				}
				defer stream.CancelRead(0)
				if err := stream.SetDeadline(time.Now().Add(3 * time.Second)); err != nil {
					return err
				}
				header, err := wire.ReadDataHeader(stream)
				if err != nil {
					return err
				}
				if header.Name != host || header.Scheme != "tls" {
					return fmt.Errorf("unexpected forwarded header: %+v", header)
				}
				body, err := io.ReadAll(stream)
				if err != nil {
					return err
				}
				if string(body) != payload {
					return fmt.Errorf("unexpected forwarded body: %q", body)
				}
				if _, err := io.WriteString(stream, response); err != nil {
					return err
				}
				return stream.Close()
			}()
		}()
		if _, err := io.WriteString(visitor, payload); err != nil {
			t.Fatal(err)
		}
		if err := visitor.CloseWrite(); err != nil {
			t.Fatal(err)
		}
		if err := s.Forward(ctx, public, host, nil); err != nil {
			t.Fatal(err)
		}
		if err := <-backendDone; err != nil {
			t.Fatal(err)
		}
		body, err := io.ReadAll(visitor)
		if err != nil || string(body) != response {
			t.Fatalf("forwarded response = %q, %v", body, err)
		}
	}
	statsCount := func() int {
		m.mu.Lock()
		defer m.mu.Unlock()
		return len(m.stats)
	}

	// Even an exact grant uses the serving parent's counters, not its own.
	forward("exact.example.net")
	baseline := statsCount()
	if baseline != 1 {
		t.Fatalf("exact grant allocated %d stats entries, want 1", baseline)
	}
	for i := 0; i < 32; i++ {
		var random [8]byte
		if _, err := rand.Read(random[:]); err != nil {
			t.Fatal(err)
		}
		forward(fmt.Sprintf("%x.example.net", random))
		if got := statsCount(); got != baseline {
			t.Fatalf("subtree forwarding grew stats from %d to %d", baseline, got)
		}
	}
	forward("exact.example.net")
	for _, route := range m.Routes() {
		switch route.Name {
		case "exact.example.net":
			if !route.Online || route.Type != "grant" || route.Connections != 0 {
				t.Fatalf("grant served by parent should be online without double counting: %+v", route)
			}
		case "example.net":
			if route.Connections != 34 || route.RXBytes != 34*uint64(len(payload)) || route.TXBytes != 34*uint64(len(response)) {
				t.Fatalf("unexpected serving-listener counters: %+v", route)
			}
		}
	}
	data = request(t, control, wire.Advertise{
		Envelope:   wire.Envelope{Type: "Advertise", ID: "3"},
		ListenerID: strings.Repeat("b", 32), Name: "child.example.net", Mode: "raw", Revision: m.Revision(),
	}, "3")
	if err := json.Unmarshal(data, &ack); err != nil || !ack.OK {
		t.Fatalf("advertise child: %s, %v", data, err)
	}
	forward("child.example.net")
	forward("nested.child.example.net")
	found := false
	for _, route := range m.Routes() {
		if route.Name == "child.example.net" {
			found = true
			if route.Type != "listener" || !route.Online || route.Connections != 2 || route.RXBytes != 2*uint64(len(payload)) || route.TXBytes != 2*uint64(len(response)) {
				t.Fatalf("unexpected descendant counters: %+v", route)
			}
		}
	}
	if !found || statsCount() != 2 {
		t.Fatal("missing descendant listener counters")
	}
	m.mu.Lock()
	var sessionID uint64
	for id := range m.sessions {
		sessionID = id
	}
	m.mu.Unlock()
	m.Unadvertise(sessionID, strings.Repeat("b", 32))
	if statsCount() != 1 {
		t.Fatal("descendant counters retained after last listener removed")
	}
	m.Unadvertise(sessionID, strings.Repeat("a", 32))
	if statsCount() != 1 {
		t.Fatal("grant counters lost after listener removed")
	}
}

func TestInitializeForwardCleanup(t *testing.T) {
	failure := errors.New("stream torn down")
	for _, stage := range []string{"set deadline", "write header", "clear deadline", "success"} {
		t.Run(stage, func(t *testing.T) {
			m := NewManager()
			s := &Server{manager: m}
			f := &forwarding{initializing: true}
			target := &session{active: map[*forwarding]bool{f: true}}
			stream := &headerTestStream{err: failure}
			switch stage {
			case "set deadline":
				stream.failDeadline = 1
			case "write header":
				stream.writeErr = failure
			case "clear deadline":
				stream.failDeadline = 2
			}
			release, err := s.initializeForward(target, f, stream, wire.DataHeader{Name: "app.example.com", Scheme: "tls"})
			if stage == "success" {
				if err != nil || release == nil {
					t.Fatalf("initialize: release=%v err=%v", release != nil, err)
				}
				if f.initializing || !target.active[f] {
					t.Fatal("successful forward must remain registered and finish initialization")
				}
				release()
				if !stream.readCanceled || stream.readCode != 0 || stream.writeCanceled {
					t.Fatal("release must cancel only reads with code 0")
				}
			} else {
				if !errors.Is(err, failure) || release != nil {
					t.Fatalf("expected setup failure, got release=%v err=%v", release != nil, err)
				}
				if stage == "set deadline" && !strings.Contains(err.Error(), "set data header deadline: ") {
					t.Fatalf("missing deadline error context: %v", err)
				}
				if !stream.readCanceled || !stream.writeCanceled || stream.readCode != 5 || stream.writeCode != 5 {
					t.Fatal("failed setup must cancel both stream directions with code 5")
				}
			}
			m.mu.Lock()
			remaining := len(target.active)
			m.mu.Unlock()
			if remaining != 0 {
				t.Fatalf("leaked %d active forwards", remaining)
			}
		})
	}
}

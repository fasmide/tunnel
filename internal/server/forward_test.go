package server

import (
	"errors"
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

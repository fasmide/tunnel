package wire

import (
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
)

type Envelope struct {
	Type string `json:"type"`
	ID   string `json:"id"`
}
type Advertise struct {
	Envelope
	ListenerID string `json:"listener_id"`
	Name       string `json:"name"`
	Mode       string `json:"mode"`
	Revision   string `json:"revision"`
}
type AdvertiseAck struct {
	Advertise
	OK    bool   `json:"ok"`
	Code  string `json:"code"`
	Error string `json:"error"`
}
type Unadvertise struct {
	Envelope
	ListenerID string `json:"listener_id"`
	Ack        bool   `json:"ack"`
	// Server data-stream allocation watermark; ACK only, -1 means none.
	LastStreamID string `json:"last_stream_id,omitempty"`
}

// Pong also reports drain state; no new traffic is admitted by this message.
type Pong struct {
	Envelope
	ActiveStreams string `json:"active_streams"`
}
type RouteList struct {
	Envelope
	Identity   string   `json:"identity"`
	Status     string   `json:"status"`
	Routes     []string `json:"routes"`
	Exclusions []string `json:"exclusions"`
	Revision   string   `json:"revision"`
	Withdrawn  []string `json:"withdrawn"`
	Error      string   `json:"error"`
}

// IssueCertificate carries a DER PKCS#10 CSR as standard padded base64.
type IssueCertificate struct {
	Envelope
	Name string `json:"name"`
	CSR  string `json:"csr"`
}
type CertificateResult struct {
	Envelope
	Name  string   `json:"name"`
	Code  string   `json:"code"`
	Error string   `json:"error"`
	Chain []string `json:"chain"`
}

type Revoked struct {
	Envelope
	Identity string `json:"identity"`
	Revision string `json:"revision"`
	Reason   string `json:"reason"`
}

// Decode requires named fields to be present and non-null. Unknown fields are
// allowed for unsigned messages as specified by v1.
func Decode(data []byte, dst any, required ...string) error {
	return decode(data, dst, true, required...)
}

// DecodeFrame decodes bytes already validated by ReadFrame / ReadAdminFrame.
func DecodeFrame(data []byte, dst any, required ...string) error {
	return decode(data, dst, false, required...)
}

func decode(data []byte, dst any, validate bool, required ...string) error {
	if validate {
		if err := ValidateJSON(data); err != nil {
			return fmt.Errorf("validate JSON message: %w", err)
		}
	}
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(data, &fields); err != nil {
		return fmt.Errorf("unmarshal message fields: %w", err)
	}
	for _, key := range required {
		value, ok := fields[key]
		if !ok || string(value) == "null" {
			return errors.New("missing or null field: " + key)
		}
	}
	if err := json.Unmarshal(data, dst); err != nil {
		return fmt.Errorf("unmarshal typed message: %w", err)
	}
	return nil
}

func Counter(s string) (uint64, error) {
	value, err := strconv.ParseUint(s, 10, 64)
	if err != nil || strconv.FormatUint(value, 10) != s {
		return 0, errors.New("invalid decimal counter")
	}
	return value, nil
}

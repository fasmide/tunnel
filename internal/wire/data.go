package wire

import "io"

const MaxDataHeader = 4096

type DataHeader struct {
	Name       string `json:"name"`
	RemoteAddr string `json:"remote_addr"`
	Scheme     string `json:"scheme"`
	ListenerID string `json:"listener_id"`
	Revision   string `json:"revision"`
}

func ReadDataHeader(r io.Reader) (DataHeader, error) {
	data, err := readFrame(r, MaxDataHeader)
	if err != nil {
		return DataHeader{}, err
	}
	var h DataHeader
	err = decode(data, &h, false, "name", "remote_addr", "scheme", "listener_id", "revision")
	return h, err
}
func WriteDataHeader(w io.Writer, h DataHeader) error { return writeFrame(w, h, MaxDataHeader) }

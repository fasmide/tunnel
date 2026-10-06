package cli

import (
	"errors"
	"fmt"
	"net"
	"net/netip"
	"strconv"
	"strings"
)

// ServerAddress normalizes endpoints before deriving saved trust/join keys.
// Bare IPv6 uses port 7443; use brackets to specify an explicit IPv6 port.
func ServerAddress(address string) (string, error) {
	host, port, err := net.SplitHostPort(address)
	if err != nil {
		switch {
		case strings.HasPrefix(address, "[") && strings.HasSuffix(address, "]"):
			host = strings.TrimSuffix(strings.TrimPrefix(address, "["), "]")
			ip, e := netip.ParseAddr(host)
			if e != nil || !ip.Is6() {
				return "", errors.New("invalid bracketed IPv6 address")
			}
		case !strings.Contains(address, ":"):
			host = address
		default:
			if _, e := netip.ParseAddr(address); e != nil {
				return "", fmt.Errorf("split server host/port: %w", err)
			}
			host = address
		}
		port = "7443"
	}
	if host == "" || strings.ContainsAny(host, " /\\\t\r\n?#[]") {
		return "", errors.New("invalid server host")
	}
	n, err := strconv.Atoi(port)
	if err != nil || n < 1 || n > 65535 {
		return "", errors.New("server port must be 1..65535")
	}
	return net.JoinHostPort(host, strconv.Itoa(n)), nil
}

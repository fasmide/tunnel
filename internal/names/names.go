// Package names contains shared DNS-label validation and subtree matching.
package names

import (
	"net"
	"strings"
)

func Valid(name string) bool {
	if len(name) == 0 || len(name) > 253 || net.ParseIP(name) != nil {
		return false
	}
	for _, label := range strings.Split(name, ".") {
		if len(label) == 0 || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return false
		}
		for _, c := range label {
			if (c < 'a' || c > 'z') && (c < '0' || c > '9') && c != '-' {
				return false
			}
		}
	}
	return true
}
func Covers(host, root string) bool { return host == root || strings.HasSuffix(host, "."+root) }

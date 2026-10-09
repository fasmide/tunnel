//go:build linux

package main

import (
	"strings"
	"unsafe"
)

// privateProcessArgs copies arguments before overwriting the original Linux
// argv storage exposed through /proc/PID/cmdline. Assigning new os.Args strings
// alone would not change what ps sees. Call only at startup, before other users
// of os.Args, and never on string literals or arbitrary Go strings.
func privateProcessArgs(args []string) []string {
	private := make([]string, len(args))
	for i, arg := range args {
		private[i] = strings.Clone(arg)
	}
	for _, arg := range args {
		if arg == "--" {
			break
		}
		name, value, ok := strings.Cut(arg, "=")
		if !ok || value == "" {
			continue
		}
		switch name {
		case "--basicauth", "--cookieauth", "--bearerauth":
		default:
			continue
		}
		// Linux's initial argv strings point to writable process stack memory.
		// Keep each argument's size and NUL terminator intact. Short values get
		// a truncated marker; longer values are padded, never partially retained.
		storage := unsafe.Slice(unsafe.StringData(arg), len(arg))
		start := len(name) + 1
		for j := start; j < len(storage); j++ {
			storage[j] = ' '
		}
		copy(storage[start:], "<hidden>")
	}
	return private
}

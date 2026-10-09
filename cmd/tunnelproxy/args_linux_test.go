//go:build linux

package main

import (
	"bytes"
	"os"
	"os/exec"
	"strings"
	"testing"
)

func TestProcessArgsRedaction(t *testing.T) {
	args := []string{"serve", "--basicauth=peter:password", "--basicauth=x", "--cookieauth=alice:another-secret", "--bearerauth=long-random-token", "--basicauth", "--basicauth=", "--cookieauth-duration=12h", "--", "--bearerauth=positional"}
	cmd := exec.Command(os.Args[0], append([]string{"-test.run=^TestProcessArgsRedactionHelper$", "--"}, args...)...)
	cmd.Env = append(os.Environ(), "TUNNELPROXY_ARGS_HELPER=1")
	if output, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("helper failed: %v\n%s", err, output)
	}
}

func TestProcessArgsRedactionHelper(t *testing.T) {
	if os.Getenv("TUNNELPROXY_ARGS_HELPER") != "1" {
		return
	}
	// Skip the test runner's separator; the remaining arguments are real,
	// writable Linux argv storage, just as they are in the application.
	original := os.Args[3:]
	want := make([]string, len(original))
	for i, arg := range original {
		want[i] = strings.Clone(arg)
	}
	private := privateProcessArgs(original)
	for i := range want {
		if private[i] != want[i] {
			t.Fatalf("private argument %d changed", i)
		}
	}
	cmdline, err := os.ReadFile("/proc/self/cmdline")
	if err != nil {
		t.Fatal(err)
	}
	for _, secret := range []string{"peter:password", "alice:another-secret", "long-random-token", "--basicauth=x"} {
		if bytes.Contains(cmdline, []byte(secret)) {
			t.Fatalf("credential remains visible: %q", secret)
		}
	}
	for _, visible := range []string{"--basicauth=<hidden>", "--basicauth=<", "--cookieauth=<hidden>", "--bearerauth=<hidden>", "--cookieauth-duration=12h", "--bearerauth=positional"} {
		if !bytes.Contains(cmdline, []byte(visible)) {
			t.Fatalf("expected argument not visible: %q", visible)
		}
	}
}

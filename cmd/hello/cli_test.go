package main

import (
	"bytes"
	"strings"
	"testing"
)

func TestCLIHelpAndCompletion(t *testing.T) {
	for _, args := range [][]string{{"version"}, {"--help"}, {"help"}, {"completion", "bash"}, {"completion", "zsh"}, {"completion", "fish"}, {"completion", "powershell"}} {
		t.Run(strings.Join(args, " "), func(t *testing.T) {
			cmd := newCommand()
			var out bytes.Buffer
			cmd.SetOut(&out)
			cmd.SetErr(&out)
			cmd.SetArgs(args)
			if err := cmd.Execute(); err != nil {
				t.Fatal(err)
			}
			if !strings.Contains(out.String(), "hello") {
				t.Fatalf("output=%q", out.String())
			}
		})
	}
}

func TestServerDefaultPort(t *testing.T) {
	for input, want := range map[string]string{
		"tunnel.mide.dk":      "tunnel.mide.dk:7443",
		"tunnel.mide.dk:8443": "tunnel.mide.dk:8443",
		"::1":                 "[::1]:7443",
		"[::1]":               "[::1]:7443",
		"[::1]:8443":          "[::1]:8443",
	} {
		cmd := newCommand()
		// Empty storage fails locally after address normalization, before any network call.
		cmd.SetArgs([]string{"--server", input, "--name", "app.example.net", "--state", t.TempDir()})
		err := cmd.Execute()
		if err == nil || !strings.Contains(err.Error(), "load identity") {
			t.Fatalf("%s: %v", input, err)
		}
		got, err := cmd.Flags().GetString("server")
		if err != nil || got != want {
			t.Fatalf("%s: got %s %v, want %s", input, got, err, want)
		}
	}
}

func TestCLIValidation(t *testing.T) {
	for _, args := range [][]string{{}, {"unexpected"}, {"--name", "app.example.net", "--mode", "unknown"}, {"--name", "app.example.net", "--fingerprint", "abc", "--tofu"}} {
		cmd := newCommand()
		cmd.SetArgs(args)
		if err := cmd.Execute(); err == nil {
			t.Fatalf("accepted %v", args)
		}
	}
}

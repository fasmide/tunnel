package main

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
)

func TestRoutesFlagsRejectedElsewhere(t *testing.T) {
	for _, command := range []string{"", "invites", "approve", "reject", "revoke", "set-routes", "fingerprint"} {
		for _, flag := range []string{"--all", "-a", "--full-id"} {
			args := []string{flag}
			if command != "" {
				args = []string{command, flag}
			}
			if _, err := parse(args); err == nil {
				t.Fatalf("accepted routes-only flag: %v", args)
			}
		}
	}
}

func TestJSONAndReplaceFlagScope(t *testing.T) {
	for _, args := range [][]string{{}, {"routes"}, {"invites"}, {"approve", "id"}, {"reject", "id"}, {"revoke", "id"}, {"set-routes", "id"}, {"fingerprint"}} {
		cfg, err := parse(append(append([]string{}, args...), "--json"))
		if err != nil || !cfg.jsonOutput {
			t.Fatalf("JSON flag for %v: %+v %v", args, cfg, err)
		}
		cfg, err = parse(append(append([]string{}, args...), "--replace"))
		approve := len(args) > 0 && args[0] == "approve"
		if approve && (err != nil || !cfg.replace) {
			t.Fatalf("approve --replace: %+v %v", cfg, err)
		}
		if !approve && err == nil {
			t.Fatalf("accepted --replace for %v", args)
		}
	}
}

func TestFingerprintOutput(t *testing.T) {
	for _, jsonOutput := range []bool{false, true} {
		var out bytes.Buffer
		if err := writeFingerprint(&out, "abc123", jsonOutput); err != nil {
			t.Fatal(err)
		}
		if jsonOutput {
			var result map[string]string
			if err := json.Unmarshal(out.Bytes(), &result); err != nil {
				t.Fatal(err)
			}
			if result["fingerprint"] != "abc123" {
				t.Fatalf("unexpected JSON: %s", out.String())
			}
		} else if out.String() != "abc123\n" {
			t.Fatalf("unexpected text: %q", out.String())
		}
	}
}

func TestCLIHelpAndCompletion(t *testing.T) {
	for _, args := range [][]string{{"version"}, {"--help"}, {"help", "approve"}, {"routes", "--help"}, {"fingerprint", "--help"}, {"completion", "bash"}, {"completion", "zsh"}, {"completion", "fish"}, {"completion", "powershell"}} {
		t.Run(strings.Join(args, " "), func(t *testing.T) {
			var c config
			called := false
			cmd := newCommand(&c, func(config) error { called = true; return nil })
			var out bytes.Buffer
			cmd.SetOut(&out)
			cmd.SetErr(&out)
			cmd.SetArgs(args)
			if err := cmd.Execute(); err != nil {
				t.Fatal(err)
			}
			if called || !strings.Contains(out.String(), "tunnelctl") {
				t.Fatalf("called=%v output=%q", called, out.String())
			}
			if args[0] != "completion" && args[0] != "version" {
				_, flagHelp, _ := strings.Cut(out.String(), "Flags:")
				if !strings.Contains(flagHelp, "--json") || strings.Contains(flagHelp, "for routes:") {
					t.Fatalf("JSON should be global: %s", out.String())
				}
				if strings.Contains(flagHelp, "--replace") != (args[0] == "help" && args[1] == "approve") {
					t.Fatalf("replace should be approve-only: %s", out.String())
				}
				for _, flag := range []string{"--all", "--full-id"} {
					if strings.Contains(flagHelp, flag) != (args[0] == "routes") {
						t.Fatalf("incorrect scope for %s: %s", flag, out.String())
					}
				}
			}
		})
	}
}

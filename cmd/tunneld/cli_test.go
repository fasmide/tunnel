package main

import (
	"bytes"
	"strings"
	"testing"
)

func TestCLIHelpAndCompletion(t *testing.T) {
	for _, args := range [][]string{{"--help"}, {"help"}, {"completion", "bash"}, {"completion", "zsh"}, {"completion", "fish"}, {"completion", "powershell"}} {
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
			if called || !strings.Contains(out.String(), "tunneld") {
				t.Fatalf("called=%v output=%q", called, out.String())
			}
		})
	}
}

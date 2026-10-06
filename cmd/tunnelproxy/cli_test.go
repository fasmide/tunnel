package main

import (
	"bytes"
	"strings"
	"testing"
)

func TestCLIHelpAndCompletion(t *testing.T) {
	for _, args := range [][]string{{"--help"}, {"help", "joinserve"}, {"join", "--help"}, {"serve", "--help"}, {"completion", "bash"}, {"completion", "zsh"}, {"completion", "fish"}, {"completion", "powershell"}} {
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
			if called || !strings.Contains(out.String(), "tunnelproxy") {
				t.Fatalf("called=%v output=%q", called, out.String())
			}
			if args[0] == "join" && strings.Contains(out.String(), "--target") {
				t.Fatal("join help advertises serving flags")
			}
		})
	}
}

func TestCLIModeCompletion(t *testing.T) {
	var c config
	cmd := newCommand(&c, func(config) error { t.Fatal("completion ran application"); return nil })
	var out bytes.Buffer
	cmd.SetOut(&out)
	cmd.SetArgs([]string{"__complete", "serve", "--mode", ""})
	if err := cmd.Execute(); err != nil {
		t.Fatal(err)
	}
	for _, mode := range []string{"acme", "private", "byo", "raw", "http"} {
		if !strings.Contains(out.String(), mode+"\n") {
			t.Fatalf("missing %s: %q", mode, out.String())
		}
	}
}

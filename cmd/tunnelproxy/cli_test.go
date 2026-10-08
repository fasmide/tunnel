package main

import (
	"bytes"
	"crypto/x509"
	"log"
	"strings"
	"testing"
)

func TestACMEErrorLog(t *testing.T) {
	var out bytes.Buffer
	previous := log.Writer()
	log.SetOutput(&out)
	t.Cleanup(func() { log.SetOutput(previous) })
	logACMEError("app.example.com", x509.UnknownAuthorityError{})
	for _, want := range []string{"ACME certificate", "app.example.com", "certificate signed by unknown authority"} {
		if !strings.Contains(out.String(), want) {
			t.Errorf("ACME log missing %q: %s", want, out.String())
		}
	}
}

func TestCLIHelpAndCompletion(t *testing.T) {
	for _, args := range [][]string{{"version"}, {"--help"}, {"help", "joinserve"}, {"join", "--help"}, {"serve", "--help"}, {"completion", "bash"}, {"completion", "zsh"}, {"completion", "fish"}, {"completion", "powershell"}} {
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

func TestCLIAuthenticationHelp(t *testing.T) {
	for _, name := range []string{"serve", "joinserve"} {
		t.Run(name, func(t *testing.T) {
			var c config
			cmd := newCommand(&c, func(config) error { t.Fatal("help ran application"); return nil })
			child, _, err := cmd.Find([]string{name})
			if err != nil {
				t.Fatal(err)
			}
			for _, name := range []string{"basicauth", "cookieauth", "bearerauth", "clientcertauth", "clientcertauth-ca", "cert", "key"} {
				if usage := child.Flags().Lookup(name).Usage; len(usage) > 75 {
					t.Errorf("%s description is too long: %q", name, usage)
				}
			}
			var out bytes.Buffer
			cmd.SetOut(&out)
			cmd.SetArgs([]string{name, "--help"})
			if err := cmd.Execute(); err != nil {
				t.Fatal(err)
			}
			for _, flag := range []string{"basicauth", "cookieauth", "bearerauth"} {
				if !strings.Contains(out.String(), "--"+flag+" stringArray ") {
					t.Errorf("%s should display only stringArray", flag)
				}
			}
			if strings.Contains(out.String(), "[=<generated>]") || strings.Contains(out.String(), "also --bearerauth=") {
				t.Error("help contains internal generation marker or redundant empty-value example")
			}
			examples := strings.SplitN(out.String(), "Flags:", 2)[0]
			for _, want := range []string{"Examples:", "--basicauth='alice:password'", "--basicauth=':password'", "--basicauth='alice:$2b$…'", "--cookieauth-duration=12h", "--bearerauth=TOKEN1", "--clientcertauth=SHA256", "--clientcertauth-ca=clients.pem", "--mode byo --cert=server.crt --key=server.key", "raw mode", "optional colons"} {
				if !strings.Contains(examples, want) {
					t.Errorf("help examples missing %q", want)
				}
			}
		})
	}
}

func TestCLIAuthenticationGeneration(t *testing.T) {
	for _, command := range []string{"serve", "joinserve"} {
		for _, flag := range []string{"basicauth", "cookieauth", "bearerauth"} {
			t.Run(command+"/"+flag, func(t *testing.T) {
				c, err := parse([]string{command, "--server=tunnel.example.net", "--name=app.tunnel.example.net", "--target=127.0.0.1:8080", "--" + flag, "--" + flag + "="})
				if err != nil {
					t.Fatal(err)
				}
				values := map[string][]string{"basicauth": c.basicAuth, "cookieauth": c.cookieAuth, "bearerauth": c.bearerAuth}[flag]
				if len(values) != 2 || values[0] != "" || values[1] != "" {
					t.Fatalf("bare and empty flags did not request generation: %q", values)
				}
			})
		}
	}
}

func TestCLIFlagValidation(t *testing.T) {
	base := []string{"serve", "--server=tunnel.example.net", "--name=app.tunnel.example.net", "--target=127.0.0.1:8080"}
	for _, flags := range [][]string{
		{"--mode=byo", "--cert=server.pem"},
		{"--mode=byo", "--key=server.key"},
		{"--mode=byo", "--cert=", "--key="},
		{"--fingerprint=abc", "--tofu"},
		{"--basicauth=", "--cookieauth="},
		{"--cookieauth-duration=1h"},
		{"--clientcertauth-ca="},
	} {
		t.Run(strings.Join(flags, " "), func(t *testing.T) {
			var c config
			cmd := newCommand(&c, func(config) error { t.Fatal("invalid flags ran application"); return nil })
			cmd.SetOut(&bytes.Buffer{})
			cmd.SetErr(&bytes.Buffer{})
			cmd.SetArgs(append(append([]string{}, base...), flags...))
			if err := cmd.Execute(); err == nil {
				t.Fatal("invalid flags accepted")
			}
		})
	}
	for _, args := range [][]string{
		{"serve", "--name=app.tunnel.example.net", "--target=127.0.0.1:8080"},
		{"serve", "--server=tunnel.example.net", "--target=127.0.0.1:8080"},
		{"serve", "--server=tunnel.example.net", "--name=app.tunnel.example.net"},
	} {
		if _, err := parse(args); err == nil {
			t.Fatalf("missing required flag accepted: %v", args)
		}
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

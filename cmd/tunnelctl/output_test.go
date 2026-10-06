package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"github.com/fasmide/tunnel/internal/server"
	"github.com/fasmide/tunnel/internal/wire"
)

func TestInvitesOutput(t *testing.T) {
	invite := server.Invite{ID: "14ca1bb76d17d6db6d821f8d899c902f", Identity: strings.Repeat("a", 64), Status: "pending",
		Join: wire.Join{Request: wire.JoinPayload{Routes: []string{"karl.tunnel.mide.dk", "other.tunnel.mide.dk"}, Nonce: "secret-nonce"}, Signature: "signature-data"}}
	result := server.AdminResult{Invites: []server.Invite{invite}}
	for _, jsonOutput := range []bool{false, true} {
		var out bytes.Buffer
		c := config{jsonOutput: jsonOutput, request: server.AdminRequest{Command: "invites"}}
		if err := writeAdminResult(&out, c, result); err != nil {
			t.Fatal(err)
		}
		if jsonOutput {
			var got server.AdminResult
			if err := json.Unmarshal(out.Bytes(), &got); err != nil {
				t.Fatal(err)
			}
			if len(got.Invites) != 1 || got.Invites[0].Join.Request.Nonce != "secret-nonce" {
				t.Fatalf("lost JSON details: %s", out.String())
			}
		} else {
			for _, want := range []string{invite.ID, "pending", shortIdentity(invite.Identity), "karl.tunnel.mide.dk", "other.tunnel.mide.dk", "tunnelctl approve INVITE_ID", "tunnelctl reject INVITE_ID"} {
				if !strings.Contains(out.String(), want) {
					t.Fatalf("missing %s: %s", want, out.String())
				}
			}
			for _, unwanted := range []string{"secret-nonce", "signature-data", invite.Identity} {
				if strings.Contains(out.String(), unwanted) {
					t.Fatalf("unexpected %s: %s", unwanted, out.String())
				}
			}
		}
	}
	var out bytes.Buffer
	if err := writeInvites(&out, nil); err != nil {
		t.Fatal(err)
	}
	if out.String() != "No access requests.\n" {
		t.Fatalf("empty output: %q", out.String())
	}
}

func TestAdminConfirmations(t *testing.T) {
	for _, tc := range []struct {
		command, want string
		routes        []string
	}{
		{"approve", "Approved invite id.", nil},
		{"reject", "Rejected invite id.", nil},
		{"revoke", "Revoked identity id.", nil},
		{"set-routes", "Cleared routes for identity id.", nil},
		{"set-routes", "Updated routes for identity id: app.example.net", []string{"app.example.net"}},
	} {
		var out bytes.Buffer
		c := config{request: server.AdminRequest{Command: tc.command, ID: "id", Routes: tc.routes}}
		if err := writeAdminResult(&out, c, server.AdminResult{}); err != nil {
			t.Fatal(err)
		}
		if strings.TrimSpace(out.String()) != tc.want {
			t.Fatalf("%s: %q", tc.command, out.String())
		}
		out.Reset()
		c.jsonOutput = true
		if err := writeAdminResult(&out, c, server.AdminResult{}); err != nil {
			t.Fatal(err)
		}
		if !json.Valid(out.Bytes()) {
			t.Fatalf("invalid JSON: %s", out.String())
		}
	}
}

type failingOutput struct{}

func (failingOutput) Write([]byte) (int, error) { return 0, errors.New("write failed") }

func TestAdminOutputErrors(t *testing.T) {
	for _, c := range []config{{request: server.AdminRequest{Command: "invites"}}, {request: server.AdminRequest{Command: "approve"}}, {jsonOutput: true}} {
		if err := writeAdminResult(failingOutput{}, c, server.AdminResult{}); err == nil {
			t.Fatal("ignored output error")
		}
	}
	if err := writeInvites(failingOutput{}, []server.Invite{{ID: "id"}}); err == nil {
		t.Fatal("ignored table flush error")
	}
}

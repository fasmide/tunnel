package main

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"strings"
	"testing"

	"tunnel/internal/server"
)

func TestAdminSocketSelection(t *testing.T) {
	for _, tc := range []struct {
		socket, state string
		explicit      bool
		want          string
	}{{"/run/tunneld/admin.sock", "", false, "/run/tunneld/admin.sock"}, {"/custom/admin.sock", "", true, "/custom/admin.sock"}, {"/run/tunneld/admin.sock", "/legacy/state", false, "/legacy/state/admin.sock"}} {
		got, err := adminSocketPath(tc.socket, tc.state, tc.explicit)
		if err != nil || got != tc.want {
			t.Fatalf("got %s %v want %s", got, err, tc.want)
		}
	}
	if _, err := adminSocketPath("/custom/socket", "/legacy", true); err == nil {
		t.Fatal("ambiguous flags accepted")
	}
	if _, err := adminSocketPath("", "", true); err == nil {
		t.Fatal("empty socket accepted")
	}
}

func TestParse(t *testing.T) {
	cfg, err := parse([]string{"-s", "/tmp/admin.sock", "invites"})
	if err != nil {
		t.Fatal(err)
	}
	if cfg.socket != "/tmp/admin.sock" || cfg.request.Command != "invites" {
		t.Fatalf("unexpected config: %+v", cfg)
	}
	cfg, err = parse([]string{"--state", "/legacy", "approve", "abc"})
	if err != nil {
		t.Fatal(err)
	}
	if cfg.socket != "/legacy/admin.sock" || cfg.request.Command != "approve" || cfg.request.ID != "abc" {
		t.Fatalf("unexpected config: %+v", cfg)
	}
	cfg, err = parse([]string{"-a", "routes"})
	if err != nil {
		t.Fatal(err)
	}
	if !cfg.all || cfg.request.Command != "routes" {
		t.Fatalf("unexpected routes --all config: %+v", cfg)
	}
	cfg, err = parse([]string{"routes", "--all"})
	if err != nil {
		t.Fatal(err)
	}
	if !cfg.all || cfg.request.Command != "routes" {
		t.Fatalf("unexpected post-command routes --all config: %+v", cfg)
	}
	cfg, err = parse([]string{"routes", "-a"})
	if err != nil {
		t.Fatal(err)
	}
	if !cfg.all || cfg.request.Command != "routes" {
		t.Fatalf("unexpected post-command routes -a config: %+v", cfg)
	}
	cfg, err = parse([]string{"routes", "--full-id"})
	if err != nil {
		t.Fatal(err)
	}
	if !cfg.fullID || cfg.request.Command != "routes" {
		t.Fatalf("unexpected routes --full-id config: %+v", cfg)
	}
	cfg, err = parse([]string{"routes", "--json"})
	if err != nil {
		t.Fatal(err)
	}
	if !cfg.jsonOutput || cfg.request.Command != "routes" {
		t.Fatalf("unexpected routes --json config: %+v", cfg)
	}
	cfg, err = parse([]string{"fingerprint"})
	if err != nil {
		t.Fatal(err)
	}
	if cfg.request.Command != "fingerprint" || cfg.server != "" {
		t.Fatalf("unexpected local fingerprint config: %+v", cfg)
	}
	cfg, err = parse(nil)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.request.Command != "routes" {
		t.Fatalf("unexpected default command config: %+v", cfg)
	}
	cfg, err = parse([]string{"--server", "tunnel.example.com", "fingerprint"})
	if err != nil {
		t.Fatal(err)
	}
	if cfg.request.Command != "fingerprint" || cfg.server != "tunnel.example.com:7443" {
		t.Fatalf("unexpected remote fingerprint config: %+v", cfg)
	}
	for _, args := range [][]string{{"-s", "/tmp/admin.sock", "approve"}, {"approve"}, {"routes", "extra"}, {"set-routes"}} {
		if _, err := parse(args); err == nil {
			t.Fatalf("accepted %v", args)
		}
	}
	cfg, err = parse([]string{"--replace", "approve", "abc"})
	if err != nil {
		t.Fatal(err)
	}
	if !cfg.replace || cfg.request.Command != "approve" {
		t.Fatalf("unexpected replace config: %+v", cfg)
	}
}

func TestParseOwnerConflict(t *testing.T) {
	route, identity, ok := parseOwnerConflict("route hello.example.com already owned by deadbeef")
	if !ok || route != "hello.example.com" || identity != "deadbeef" {
		t.Fatalf("got %q %q %v", route, identity, ok)
	}
	if _, _, ok := parseOwnerConflict("different error"); ok {
		t.Fatal("parsed unrelated error")
	}
}

func TestReadConfirmation(t *testing.T) {
	ok, err := readConfirmation(strings.NewReader("yes\n"))
	if err != nil || !ok {
		t.Fatalf("yes: %v %v", ok, err)
	}
	ok, err = readConfirmation(strings.NewReader("no\n"))
	if err != nil || ok {
		t.Fatalf("no: %v %v", ok, err)
	}
}

func TestAdminRunReplaceConflictWithoutTTY(t *testing.T) {
	ctx := context.Background()
	cfg := config{socket: "/run/tunneld/admin.sock", request: server.AdminRequest{Command: "approve", ID: "invite"}}
	_, err := adminRun(ctx, cfg, nil, strings.NewReader(""))
	if err == nil || !strings.Contains(err.Error(), "dial unix") {
		// Only verifies non-conflict path is returned unchanged without a live socket.
		t.Fatalf("got %v", err)
	}
}

func TestCanPrompt(t *testing.T) {
	if canPrompt(nil, strings.NewReader("")) {
		t.Fatal("prompt enabled without tty")
	}
	if canPrompt(os.Stderr, bytes.NewBuffer(nil)) {
		t.Fatal("prompt enabled for non-stdin reader")
	}
}

func TestRouteStatus(t *testing.T) {
	for _, tc := range []struct {
		name       string
		online     bool
		connected  string
		offline    string
		revoked    bool
		wantStatus string
		wantAge    string
	}{{
		name:       "online",
		online:     true,
		connected:  "12s",
		wantStatus: "online",
		wantAge:    "12s",
	}, {
		name:       "offline",
		offline:    "2m3s",
		wantStatus: "offline",
		wantAge:    "2m3s",
	}, {
		name:       "revoked offline",
		offline:    "9m",
		revoked:    true,
		wantStatus: "revoked",
		wantAge:    "9m",
	}, {
		name:       "never connected",
		wantStatus: "offline",
		wantAge:    "never connected",
	}, {
		name:       "revoked never connected",
		revoked:    true,
		wantStatus: "revoked",
		wantAge:    "never connected",
	}} {
		t.Run(tc.name, func(t *testing.T) {
			gotStatus, gotAge := routeStatus(tc.online, tc.connected, tc.offline, tc.revoked)
			if gotStatus != tc.wantStatus || gotAge != tc.wantAge {
				t.Fatalf("got %q %q want %q %q", gotStatus, gotAge, tc.wantStatus, tc.wantAge)
			}
		})
	}
}

func TestShortIdentity(t *testing.T) {
	if got := shortIdentity("short"); got != "short" {
		t.Fatalf("short id changed: %q", got)
	}
	got := shortIdentity("0123456789abcdef")
	if got != "0123456789abcdef" {
		t.Fatalf("boundary id changed: %q", got)
	}
	got = shortIdentity("0123456789abcdef0123456789abcdef")
	if got != "01234567…89abcdef" {
		t.Fatalf("unexpected shortened id: %q", got)
	}
}

func TestHumanBytes(t *testing.T) {
	for _, tc := range []struct {
		value uint64
		want  string
	}{{0, "0 B"}, {999, "999 B"}, {1024, "1.0 KiB"}, {1536, "1.5 KiB"}, {1024 * 1024, "1.0 MiB"}} {
		if got := humanBytes(tc.value); got != tc.want {
			t.Fatalf("humanBytes(%d) = %q want %q", tc.value, got, tc.want)
		}
	}
}

func TestWriteRoutes(t *testing.T) {
	routes := []server.RouteRecord{
		{Identity: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", Name: "alt.a.tunnel.example.net", Online: true, ConnectedFor: "15s", Connections: 3, RXBytes: 1536, TXBytes: 2048, LatestRTT: "12ms", SmoothedRTT: "10ms", MinRTT: "8ms"},
		{Identity: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", Name: "a.tunnel.example.net", Online: true, ConnectedFor: "15s", Connections: 12, RXBytes: 1024 * 1024, TXBytes: 3 * 1024 * 1024, LatestRTT: "20ms", SmoothedRTT: "18ms", MinRTT: "9ms"},
		{Identity: "bbbbbbbbbbbbbbbb", Name: "b.tunnel.example.net", OfflineFor: "3m", Connections: 1, RXBytes: 999, TXBytes: 0},
		{Identity: "cccccccccccccccccccccccccccccccc", Revoked: true},
	}
	t.Run("short", func(t *testing.T) {
		var out bytes.Buffer
		if err := writeRoutes(&out, routes, false); err != nil {
			t.Fatal(err)
		}
		text := out.String()
		for _, want := range []string{
			"IDENTITY",
			"STATUS",
			"AGE",
			"LATEST",
			"SMOOTHED",
			"MIN",
			"CONNS",
			"RX",
			"TX",
			"ROUTE",
			"aaaaaaaa…aaaaaaaa",
			"online",
			"15s",
			"20ms",
			"18ms",
			"9ms",
			"12",
			"1.0 MiB",
			"3.0 MiB",
			"a.tunnel.example.net",
			"alt.a.tunnel.example.net",
			"12ms",
			"10ms",
			"8ms",
			"3",
			"1.5 KiB",
			"2.0 KiB",
			"bbbbbbbbbbbbbbbb",
			"offline",
			"3m",
			"999 B",
			"0 B",
			"b.tunnel.example.net",
			"cccccccc…cccccccc",
			"revoked",
			"never connected",
			"-",
		} {
			if !strings.Contains(text, want) {
				t.Fatalf("table missing %q in:\n%s", want, text)
			}
		}
		if strings.Index(text, "aaaaaaaa…aaaaaaaa") > strings.Index(text, "bbbbbbbbbbbbbbbb") {
			t.Fatalf("expected sorted identities, got:\n%s", text)
		}
	})
	t.Run("full", func(t *testing.T) {
		var out bytes.Buffer
		if err := writeRoutes(&out, routes, true); err != nil {
			t.Fatal(err)
		}
		text := out.String()
		if !strings.Contains(text, "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa") {
			t.Fatalf("full identity missing in:\n%s", text)
		}
		if strings.Contains(text, "aaaaaaaa…aaaaaaaa") {
			t.Fatalf("shortened identity unexpectedly present in:\n%s", text)
		}
	})
}

func TestRoutesJSONEncoding(t *testing.T) {
	routes := []server.RouteRecord{{
		Identity:     "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
		Name:         "a.tunnel.example.net",
		Online:       true,
		ConnectedFor: "15s",
		Connections:  12,
		RXBytes:      1024,
		TXBytes:      2048,
		LatestRTT:    "20ms",
		SmoothedRTT:  "18ms",
		MinRTT:       "9ms",
	}}
	var out bytes.Buffer
	encoder := json.NewEncoder(&out)
	encoder.SetIndent("", "  ")
	if err := encoder.Encode(routes); err != nil {
		t.Fatal(err)
	}
	text := out.String()
	for _, want := range []string{
		"\"identity\": \"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\"",
		"\"name\": \"a.tunnel.example.net\"",
		"\"online\": true",
		"\"connections\": 12",
		"\"rx_bytes\": 1024",
		"\"tx_bytes\": 2048",
		"\"latest_rtt\": \"20ms\"",
		"\"smoothed_rtt\": \"18ms\"",
		"\"min_rtt\": \"9ms\"",
	} {
		if !strings.Contains(text, want) {
			t.Fatalf("JSON missing %q in:\n%s", want, text)
		}
	}
}

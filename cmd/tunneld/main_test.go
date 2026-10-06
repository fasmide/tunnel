package main

import "testing"

func TestParse(t *testing.T) {
	cfg, err := parse([]string{"-d", "tunnel.example.com"})
	if err != nil {
		t.Fatal(err)
	}
	if cfg.domain != "tunnel.example.com" || cfg.stateDir != "/var/lib/tunneld" {
		t.Fatalf("unexpected config: %+v", cfg)
	}
	cfg, err = parse([]string{"-s", "/state", "-c", "cert.pem", "-k", "key.pem"})
	if err != nil {
		t.Fatal(err)
	}
	if cfg.stateDir != "/state" || cfg.certPath != "cert.pem" || cfg.keyPath != "key.pem" || cfg.pprofPath != "/run/tunneld/pprof.sock" {
		t.Fatalf("unexpected shorthand config: %+v", cfg)
	}
	for _, args := range [][]string{{}, {"--cert", "cert.pem"}, {"--key", "key.pem"}, {"--domain", "example.com", "extra"}, {"--cert", "cert.pem", "--key", "key.pem", "--domain", "example.com"}, {"--cert", "cert.pem", "--key", "key.pem", "--export-ca"}} {
		if _, err := parse(args); err == nil {
			t.Fatalf("accepted %v", args)
		}
	}
}

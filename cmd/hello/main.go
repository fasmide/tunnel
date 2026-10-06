// hello is a minimal HTTP application exposed using the tunnel Go API.
package main

import (
	"context"
	"crypto/tls"
	"errors"
	"flag"
	"fmt"
	"io/fs"
	"log"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	"golang.org/x/net/http2"
	"tunnel"
)

func main() {
	if err := run(); err != nil {
		log.Print(err)
		os.Exit(1)
	}
}

func run() error {
	server := flag.String("server", "tunnel.example.net:7443", "daemon QUIC host:port")
	name := flag.String("name", "", "public hostname to request/serve")
	state := flag.String("state", "", "private state directory (default user config directory/tunnel-hello)")
	join := flag.Bool("join", false, "submit an access request and exit; administrator approval is required")
	fingerprint := flag.String("fingerprint", "", "verify generated daemon CA using administrator SHA-256 hex")
	tofu := flag.Bool("tofu", false, "explicitly trust first daemon CA (first contact can be intercepted)")
	mode := flag.String("mode", "acme", "HTTPS certificate source: acme or private")
	flag.Parse()
	if *name == "" || flag.NArg() != 0 {
		return errors.New("-name is required; no positional arguments")
	}
	if *mode != "acme" && *mode != "private" {
		return errors.New("-mode must be acme or private")
	}
	if *state == "" {
		dir, err := os.UserConfigDir()
		if err != nil {
			return fmt.Errorf("resolve user config dir: %w", err)
		}
		*state = filepath.Join(dir, "tunnel-hello")
	}
	storage := tunnel.FileStorage(*state)
	life, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	setup, cancel := context.WithTimeout(life, 30*time.Second)
	defer cancel()

	if *fingerprint != "" || *tofu {
		trust, err := tunnel.BootstrapTrust(setup, *server, tunnel.TrustRequest{
			Storage: storage, Fingerprint: *fingerprint, TOFU: *tofu,
		})
		if err != nil {
			return fmt.Errorf("bootstrap transport trust: %w", err)
		}
		if *tofu && trust.FirstUse {
			log.Print("WARNING: TOFU accepted an unverified first-contact CA")
		}
		log.Printf("transport CA SHA-256: %s", trust.Fingerprint)
	}
	transportTLS, err := tunnel.LoadTransportTLS(storage, *server, "")
	if errors.Is(err, fs.ErrNotExist) {
		transportTLS = &tls.Config{MinVersion: tls.VersionTLS13} // normal system trust
	} else if err != nil {
		return fmt.Errorf("load saved transport trust: %w", err)
	}
	if *join {
		creds, err := tunnel.RequestJoin(setup, *server, tunnel.JoinRequest{
			Routes: []string{*name}, Storage: storage, TLSConfig: transportTLS,
		})
		if err != nil {
			return fmt.Errorf("request join: %w", err)
		}
		log.Printf("request submitted for identity %s; get administrator approval, then rerun without -join", creds.Identity())
		return nil
	}

	creds, err := tunnel.LoadCredentials(storage)
	if err != nil {
		return fmt.Errorf("load identity (run with -join first): %w", err)
	}
	client, err := tunnel.Dial(setup, *server, tunnel.WithCredentials(creds), tunnel.WithTLSConfig(transportTLS))
	if err != nil {
		return fmt.Errorf("dial tunnel server: %w", err)
	}
	defer func() { _ = client.Close() }()
	listen := client.Listen // ACME; accepts the CA's terms of service
	if *mode == "private" {
		listen = client.ListenPrivate // browsers must separately trust the daemon CA
	}
	listener, err := listen(setup, *name)
	if err != nil {
		return err
	}
	cancel() // setup context does not control the returned Client's lifetime

	app := &http.Server{Handler: helloHandler(), ReadHeaderTimeout: 10 * time.Second, IdleTimeout: 30 * time.Second}
	// Listener connections have already completed TLS. Serve, not ServeTLS.
	if err := http2.ConfigureServer(app, &http2.Server{}); err != nil {
		return fmt.Errorf("configure HTTP/2 server: %w", err)
	}
	defer func() { _ = app.Close() }()
	served := make(chan error, 1)
	go func() { served <- app.Serve(listener) }()
	log.Printf("hello is available at https://%s/ (%s)", *name, *mode)
	select {
	case err := <-served:
		return err
	case <-life.Done():
		// Immediate shutdown keeps this example small. Applications needing
		// allocated-stream draining can use Client.CloseGracefully(ctx).
		return nil
	}
}

func helloHandler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		_, _ = fmt.Fprintln(w, "Hello, world!")
	})
	return mux
}

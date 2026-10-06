// hello is a minimal HTTP application exposed using the tunnel Go API.
package main

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io/fs"
	"log"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	"github.com/fasmide/tunnel"
	"github.com/fasmide/tunnel/internal/cli"
	"github.com/spf13/cobra"
	"golang.org/x/net/http2"
)

func main() {
	if err := run(); err != nil {
		log.Print(err)
		os.Exit(1)
	}
}

func run() error {
	cmd := newCommand()
	cmd.SetArgs(os.Args[1:])
	if err := cmd.Execute(); err != nil {
		return fmt.Errorf("hello: %w", err)
	}
	return nil
}

func newCommand() *cobra.Command {
	cmd := &cobra.Command{Use: "hello", Short: "Serve a hello-world application through the tunnel Go API",
		Example: "  hello --server tunnel.example.net:7443 --name app.tunnel.example.net --fingerprint SHA256 --join\n  hello --server tunnel.example.net:7443 --name app.tunnel.example.net",
		Args:    cobra.NoArgs, SilenceUsage: true, SilenceErrors: true}
	flags := cmd.Flags()
	server := flags.StringP("server", "s", "tunnel.example.net:7443", "daemon QUIC hostname or host:port (default port 7443)")
	name := flags.StringP("name", "n", "", "public hostname to request/serve")
	state := flags.String("state", "", "private state directory (default user config directory/tunnel-hello)")
	join := flags.Bool("join", false, "submit an access request and exit; administrator approval is required")
	fingerprint := flags.StringP("fingerprint", "f", "", "verify generated daemon CA using administrator SHA-256 hex")
	tofu := flags.Bool("tofu", false, "explicitly trust first daemon CA (first contact can be intercepted)")
	mode := flags.StringP("mode", "m", "acme", "HTTPS certificate source: acme or private")
	_ = cmd.MarkFlagRequired("name")
	cmd.MarkFlagsMutuallyExclusive("fingerprint", "tofu")
	_ = cmd.MarkFlagDirname("state")
	_ = cmd.RegisterFlagCompletionFunc("mode", func(*cobra.Command, []string, string) ([]string, cobra.ShellCompDirective) {
		return []string{"acme", "private"}, cobra.ShellCompDirectiveNoFileComp
	})
	cmd.RunE = func(cmd *cobra.Command, args []string) error {
		if *name == "" {
			return errors.New("--name is required")
		}
		if *mode != "acme" && *mode != "private" {
			return errors.New("--mode must be acme or private")
		}
		address, err := cli.ServerAddress(*server)
		if err != nil {
			return fmt.Errorf("--server: %w", err)
		}
		*server = address
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
			log.Printf("request submitted for identity %s; get administrator approval, then rerun without --join", creds.Identity())
			return nil
		}

		creds, err := tunnel.LoadCredentials(storage)
		if err != nil {
			return fmt.Errorf("load identity (run with --join first): %w", err)
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
	cli.AddCompletion(cmd)
	return cmd
}

func helloHandler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		_, _ = fmt.Fprintln(w, "Hello, world!")
	})
	return mux
}

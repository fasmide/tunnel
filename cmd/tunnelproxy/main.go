// tunnelproxy exposes a loopback TCP service through an approved tunnel identity.
package main

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"log"
	"net"
	"os"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/fasmide/tunnel"
	"github.com/fasmide/tunnel/internal/cli"
	"github.com/spf13/cobra"
)

type config struct {
	command, server, name, state, target, mode, cert, key, serverName, fingerprint, email string
	tofu                                                                                  bool
	basicAuth                                                                             []string
	basicAuthEnabled                                                                      bool
	cookieAuth                                                                            []string
	cookieAuthEnabled                                                                     bool
	cookieAuthDuration                                                                    time.Duration
	setupTimeout, drainTimeout, dialTimeout                                               time.Duration
}

func newCommand(c *config, action func(config) error) *cobra.Command {
	*c = config{mode: "acme", setupTimeout: 30 * time.Second, drainTimeout: 30 * time.Second, dialTimeout: 10 * time.Second}
	root := &cobra.Command{
		Use: "tunnelproxy", Short: "Expose a loopback web service through your tunnel server",
		Long:         "Connect outward to a tunnel daemon and expose a loopback service.\nAccess requires an approved identity; HTTPS terminates on this machine.",
		SilenceUsage: true, SilenceErrors: true,
	}
	flags := root.PersistentFlags()
	flags.StringVarP(&c.server, "server", "s", "", "daemon QUIC hostname or host:port (default port 7443)")
	flags.StringVarP(&c.name, "name", "n", "", "approved public name/subtree")
	flags.StringVar(&c.state, "state", "", "private state directory (Linux: $XDG_CONFIG_HOME/tunnelproxy or ~/.config/tunnelproxy)")
	flags.StringVar(&c.serverName, "server-name", "", "transport TLS DNS name override, e.g. when dialing an IP")
	flags.StringVarP(&c.fingerprint, "fingerprint", "f", "", "bootstrap constrained CA using administrator SHA-256 hex fingerprint")
	flags.BoolVar(&c.tofu, "tofu", false, "explicitly trust first constrained CA; first contact can be intercepted")
	flags.DurationVar(&c.setupTimeout, "setup-timeout", c.setupTimeout, "join/dial setup deadline")
	for _, spec := range []struct{ name, short string }{
		{"join", "Submit an access request and exit"},
		{"serve", "Serve using an existing approved identity"},
		{"joinserve", "Request access, wait for approval, then serve"},
	} {
		child := &cobra.Command{Use: spec.name, Short: spec.short, Args: cobra.NoArgs,
			Example: "  tunnelproxy " + spec.name + " --server tunnel.example.net --name app.tunnel.example.net --fingerprint SHA256"}
		if spec.name != "join" {
			child.Example += " --target 127.0.0.1:8080"
			serving := child.Flags()
			serving.StringArrayVar(&c.basicAuth, "basicauth", nil, "add an allowed Basic auth identity (repeatable): bare flag generates a password; use --basicauth=user:password or user:bcrypt-hash; empty user accepts any username (raw mode cannot enforce auth)")
			serving.StringArrayVar(&c.cookieAuth, "cookieauth", nil, "add a sign-in identity (repeatable): bare flag generates a password; use --cookieauth=user:password or user:bcrypt-hash; empty user accepts any username (raw mode cannot enforce auth)")
			serving.Lookup("cookieauth").NoOptDefVal = "generate"
			serving.DurationVar(&c.cookieAuthDuration, "cookieauth-duration", 24*time.Hour, "session lifetime from login; restarting invalidates all sessions")
			child.MarkFlagsMutuallyExclusive("basicauth", "cookieauth")
			_ = child.RegisterFlagCompletionFunc("cookieauth", func(*cobra.Command, []string, string) ([]string, cobra.ShellCompDirective) {
				return nil, cobra.ShellCompDirectiveNoFileComp
			})
			serving.Lookup("basicauth").NoOptDefVal = "generate"
			_ = child.RegisterFlagCompletionFunc("basicauth", func(*cobra.Command, []string, string) ([]string, cobra.ShellCompDirective) {
				return nil, cobra.ShellCompDirectiveNoFileComp
			})
			serving.StringVarP(&c.target, "target", "t", "", "loopback TCP service, e.g. 127.0.0.1:8080")
			serving.StringVarP(&c.mode, "mode", "m", "acme", "public mode: acme, private, byo, raw, http")
			serving.StringVar(&c.cert, "cert", "", "public certificate PEM for byo mode, not transport TLS")
			serving.StringVar(&c.key, "key", "", "public private-key PEM for byo mode")
			serving.StringVar(&c.email, "acme-email", "", "ACME contact email (acme mode)")
			serving.DurationVar(&c.drainTimeout, "drain-timeout", 30*time.Second, "SIGINT/SIGTERM drain deadline")
			serving.DurationVar(&c.dialTimeout, "target-timeout", 10*time.Second, "local TCP dial deadline")
			_ = child.MarkFlagRequired("target")
			_ = child.MarkFlagFilename("cert", "pem", "crt")
			_ = child.MarkFlagFilename("key", "pem", "key")
			_ = child.RegisterFlagCompletionFunc("mode", func(*cobra.Command, []string, string) ([]string, cobra.ShellCompDirective) {
				return []string{"acme", "private", "byo", "raw", "http"}, cobra.ShellCompDirectiveNoFileComp
			})
		}
		child.RunE = func(cmd *cobra.Command, args []string) error {
			c.command = cmd.Name()
			c.basicAuthEnabled = cmd.Flags().Changed("basicauth")
			c.cookieAuthEnabled = cmd.Flags().Changed("cookieauth")
			if cmd.Flags().Changed("cookieauth-duration") && !c.cookieAuthEnabled {
				return errors.New("--cookieauth-duration requires --cookieauth")
			}
			for _, flag := range []struct {
				name   string
				values []string
			}{{"basicauth", c.basicAuth}, {"cookieauth", c.cookieAuth}} {
				for i, value := range flag.values {
					if value == "" {
						return fmt.Errorf("--%s= requires credentials; use bare --%s to generate a password", flag.name, flag.name)
					}
					if value == "generate" {
						flag.values[i] = ""
					}
				}
			}
			validated, err := validateConfig(*c)
			if err != nil {
				return err
			}
			*c = validated
			return action(validated)
		}
		root.AddCommand(child)
	}
	_ = root.MarkPersistentFlagDirname("state")
	cli.AddCompletion(root)
	return root
}

//nolint:unused // Used by tests, which are excluded from linting.
func parse(args []string) (config, error) {
	var c config
	called := false
	cmd := newCommand(&c, func(config) error { called = true; return nil })
	cmd.SetOut(io.Discard)
	cmd.SetErr(io.Discard)
	cmd.SetArgs(args)
	err := cmd.Execute()
	if err == nil && !called {
		err = errors.New("usage: tunnelproxy join|serve|joinserve [flags]")
	}
	return c, err
}

func validateConfig(c config) (config, error) {
	if c.server == "" || c.name == "" {
		return c, errors.New("-s, --server and -n, --name are required; no positional arguments")
	}
	var err error
	c.server, err = serverAddress(c.server)
	if err != nil {
		return c, fmt.Errorf("-server: %w", err)
	}
	if c.tofu && c.fingerprint != "" {
		return c, errors.New("select --fingerprint or --tofu, not both")
	}
	if c.setupTimeout <= 0 || c.drainTimeout <= 0 || c.dialTimeout <= 0 {
		return c, errors.New("timeouts must be positive")
	}
	if c.state == "" {
		dir, err := os.UserConfigDir()
		if err != nil {
			return c, fmt.Errorf("resolve user config dir: %w", err)
		}
		c.state = filepath.Join(dir, "tunnelproxy")
	}
	if c.basicAuthEnabled && c.cookieAuthEnabled {
		return c, errors.New("--basicauth and --cookieauth are mutually exclusive")
	}
	if c.cookieAuthEnabled && c.cookieAuthDuration < time.Second {
		return c, errors.New("--cookieauth-duration must be at least 1s")
	}
	for _, values := range [][]string{c.basicAuth, c.cookieAuth} {
		for i, value := range values {
			if value != "" {
				if _, err := parseBasicAuth(value); err != nil {
					return c, fmt.Errorf("authentication identity %d: %w", i+1, err)
				}
			}
		}
	}
	if c.command == "join" {
		if c.target != "" || c.cert != "" || c.key != "" || c.mode != "acme" || c.email != "" || c.basicAuthEnabled || c.cookieAuthEnabled {
			return c, errors.New("forwarding options require serve or joinserve")
		}
	} else {
		if c.target == "" {
			return c, errors.New("serve requires -t, --target")
		}
		switch c.mode {
		case "acme", "private", "raw", "http":
			if c.cert != "" || c.key != "" {
				return c, errors.New("--cert/--key require --mode byo")
			}
		case "byo":
			if c.cert == "" || c.key == "" {
				return c, errors.New("byo requires --cert and --key")
			}
		default:
			return c, errors.New("unknown mode; choose acme, private, byo, raw or http")
		}
		if c.mode != "acme" && c.email != "" {
			return c, errors.New("--acme-email requires acme mode")
		}
	}
	return c, nil
}

func serverAddress(address string) (string, error) {
	address, err := cli.ServerAddress(address)
	if err != nil {
		return "", fmt.Errorf("normalize server address: %w", err)
	}
	return address, nil
}

func transportConfig(ctx context.Context, c config, storage tunnel.Storage, out io.Writer) (*tls.Config, error) {
	config, err := tunnel.LoadTransportTLS(storage, c.server, c.serverName)
	if err == nil {
		return config, nil
	}
	if !errors.Is(err, fs.ErrNotExist) {
		return nil, fmt.Errorf("load saved transport trust: %w", err)
	}
	if !c.tofu && c.fingerprint == "" {
		if stdout, ok := out.(*os.File); ok && canPrompt(stdout, os.Stdin) {
			trust, err := tunnel.FetchTransportTrust(ctx, c.server, c.serverName)
			if err != nil {
				return nil, fmt.Errorf("fetch transport trust: %w", err)
			}
			if _, err := fmt.Fprintf(out, "transport CA SHA-256: %s\n", trust.Fingerprint); err != nil {
				return nil, fmt.Errorf("write transport fingerprint: %w", err)
			}
			if _, err := fmt.Fprint(out, "Trust this fingerprint? [y/N] "); err != nil {
				return nil, fmt.Errorf("prompt for trust confirmation: %w", err)
			}
			answer, err := readConfirmation(os.Stdin)
			if err != nil {
				return nil, fmt.Errorf("read trust confirmation: %w", err)
			}
			if !answer {
				return nil, errors.New("transport trust not accepted; rerun with --fingerprint or --tofu")
			}
			c.fingerprint = trust.Fingerprint
		} else {
			return nil, errors.New("no saved transport trust; rerun with --fingerprint or --tofu")
		}
	}
	trust, err := tunnel.BootstrapTrust(ctx, c.server, tunnel.TrustRequest{Storage: storage, ServerName: c.serverName, Fingerprint: c.fingerprint, TOFU: c.tofu})
	if err != nil {
		return nil, fmt.Errorf("bootstrap transport trust: %w", err)
	}
	if c.tofu && trust.FirstUse {
		if _, err := fmt.Fprintln(out, "WARNING: TOFU accepted first-contact CA without out-of-band verification"); err != nil {
			return nil, fmt.Errorf("write TOFU warning: %w", err)
		}
	}
	if _, err := fmt.Fprintf(out, "transport CA SHA-256: %s\n", trust.Fingerprint); err != nil {
		return nil, fmt.Errorf("write transport fingerprint: %w", err)
	}
	config, err = tunnel.LoadTransportTLS(storage, c.server, c.serverName)
	if err != nil {
		return nil, fmt.Errorf("load bootstrapped transport trust: %w", err)
	}
	return config, nil
}
func targets(ctx context.Context, target string) ([]string, error) {
	host, port, err := net.SplitHostPort(target)
	if err != nil {
		return nil, fmt.Errorf("split target host/port: %w", err)
	}
	n, err := strconv.Atoi(port)
	if err != nil || n < 1 || n > 65535 {
		return nil, errors.New("target port must be 1..65535")
	}
	ips := []net.IP{}
	if host == "localhost" {
		resolved, err := net.DefaultResolver.LookupIPAddr(ctx, host)
		if err != nil {
			return nil, fmt.Errorf("resolve target host: %w", err)
		}
		for _, address := range resolved {
			ips = append(ips, address.IP)
		}
	} else {
		ip := net.ParseIP(host)
		if ip == nil {
			return nil, errors.New("target host must be a loopback IP or localhost")
		}
		ips = append(ips, ip)
	}
	addresses := []string{}
	for _, ip := range ips {
		if !ip.IsLoopback() {
			return nil, errors.New("target must resolve exclusively to loopback")
		}
		addresses = append(addresses, net.JoinHostPort(ip.String(), port))
	}
	if len(addresses) == 0 {
		return nil, errors.New("localhost resolved to no addresses")
	}
	return addresses, nil
}
func listener(ctx context.Context, c config, client *tunnel.Client) (net.Listener, error) {
	switch c.mode {
	case "acme":
		listener, err := client.Listen(ctx, c.name)
		if err != nil {
			return nil, fmt.Errorf("listen acme: %w", err)
		}
		return listener, nil
	case "private":
		listener, err := client.ListenPrivate(ctx, c.name)
		if err != nil {
			return nil, fmt.Errorf("listen private: %w", err)
		}
		return listener, nil
	case "raw":
		listener, err := client.ListenRaw(ctx, c.name)
		if err != nil {
			return nil, fmt.Errorf("listen raw: %w", err)
		}
		return listener, nil
	case "http":
		listener, err := client.ListenHTTP(ctx, c.name)
		if err != nil {
			return nil, fmt.Errorf("listen http: %w", err)
		}
		return listener, nil
	case "byo":
		cert, err := tls.LoadX509KeyPair(c.cert, c.key)
		if err != nil {
			return nil, fmt.Errorf("load BYO certificate: %w", err)
		}
		listener, err := client.ListenTLS(ctx, c.name, &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS12, NextProtos: []string{"h2", "http/1.1"}})
		if err != nil {
			return nil, fmt.Errorf("listen byo TLS: %w", err)
		}
		return listener, nil
	}
	return nil, errors.New("invalid listener mode")
}
func canPrompt(stderr *os.File, stdin io.Reader) bool {
	if stdin != os.Stdin {
		return false
	}
	if stderr == nil {
		return false
	}
	if info, err := stderr.Stat(); err != nil || info.Mode()&os.ModeCharDevice == 0 {
		return false
	}
	return true
}

func readConfirmation(r io.Reader) (bool, error) {
	var answer string
	if _, err := fmt.Fscanln(r, &answer); err != nil {
		if errors.Is(err, io.EOF) {
			return false, nil
		}
		return false, fmt.Errorf("read confirmation: %w", err)
	}
	answer = strings.TrimSpace(strings.ToLower(answer))
	return answer == "y" || answer == "yes", nil
}

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	exitCode := 0
	defer func() {
		stop()
		if exitCode != 0 {
			os.Exit(exitCode)
		}
	}()
	if err := run(ctx, os.Args[1:], os.Stdout); err != nil {
		log.Print(err)
		exitCode = 1
	}
}
func run(ctx context.Context, args []string, out io.Writer) error {
	var c config
	cmd := newCommand(&c, func(c config) error { return executeConfig(ctx, c, out) })
	cmd.SetArgs(args)
	cmd.SetOut(out)
	cmd.SetErr(out)
	if err := cmd.ExecuteContext(ctx); err != nil {
		return fmt.Errorf("tunnelproxy: %w", err)
	}
	return nil
}

func executeConfig(ctx context.Context, c config, out io.Writer) error {
	storage := tunnel.FileStorage(c.state)
	setup, cancel := context.WithTimeout(ctx, c.setupTimeout)
	defer cancel()
	trust, err := transportConfig(setup, c, storage, out)
	if err != nil {
		return err
	}
	join := tunnel.JoinWaitOptions{JoinRequest: tunnel.JoinRequest{Storage: storage, Routes: []string{c.name}, TLSConfig: trust}, OnEvent: func(event tunnel.JoinEvent) {
		_, _ = fmt.Fprintln(out, tunnel.FormatJoinEvent(event))
	}}
	switch c.command {
	case "join":
		creds, err := tunnel.RequestJoin(setup, c.server, join.JoinRequest)
		if err != nil {
			return fmt.Errorf("request join: %w", err)
		}
		if _, err = fmt.Fprintf(out, "request submitted; administrator approval required before serving\nidentity: %s\n", creds.Identity()); err != nil {
			return fmt.Errorf("write join result: %w", err)
		}
		return nil
	case "serve":
		return runServe(ctx, setup, c, trust, out, storage)
	case "joinserve":
		return runJoinServe(ctx, c, trust, join, out)
	default:
		return fmt.Errorf("unknown command %s", c.command)
	}
}

func runServe(ctx, setup context.Context, c config, trust *tls.Config, out io.Writer, storage tunnel.Storage) error {
	addresses, err := targets(setup, c.target)
	if err != nil {
		return fmt.Errorf("-target: %w", err)
	}
	creds, err := tunnel.LoadCredentials(storage)
	if err != nil {
		return fmt.Errorf("load identity (run join or joinserve first): %w", err)
	}
	client, err := tunnel.Dial(setup, c.server, tunnel.WithCredentials(creds), tunnel.WithTLSConfig(trust), tunnel.WithACMEEmail(c.email))
	if err != nil {
		return fmt.Errorf("dial tunnel server: %w", err)
	}
	l, err := listener(setup, c, client)
	if err != nil {
		_ = client.Close()
		return fmt.Errorf("create listener: %w", err)
	}
	return serveClient(ctx, c, client, l, addresses, out)
}

func runJoinServe(ctx context.Context, c config, trust *tls.Config, join tunnel.JoinWaitOptions, out io.Writer) error {
	setup, cancel := context.WithTimeout(ctx, c.setupTimeout)
	defer cancel()
	addresses, err := targets(setup, c.target)
	if err != nil {
		return fmt.Errorf("-target: %w", err)
	}
	listen := func(ctx context.Context, client *tunnel.Client) (net.Listener, error) {
		return listener(ctx, c, client)
	}
	l, client, err := tunnel.EnsureJoinedAndListen(ctx, c.server, join, listen, tunnel.WithTLSConfig(trust), tunnel.WithACMEEmail(c.email))
	if err != nil {
		return fmt.Errorf("ensure joined and listen: %w", err)
	}
	return serveClient(ctx, c, client, l, addresses, out)
}

// serveClient owns the client and listener once either setup path succeeds.
func serveClient(ctx context.Context, c config, client *tunnel.Client, l net.Listener, addresses []string, out io.Writer) error {
	defer func() { _ = client.Close() }()
	defer func() { _ = l.Close() }()
	if _, err := fmt.Fprintf(out, "serving %s (%s) -> %s\n", c.name, c.mode, c.target); err != nil {
		return fmt.Errorf("write serve banner: %w", err)
	}
	auth, err := prepareBasicAuth(c, out)
	if err != nil {
		return err
	}
	if c.mode == "raw" {
		return forward(ctx, client, l, addresses, c.dialTimeout, c.drainTimeout, out)
	}
	var cookies *cookieAuth
	if c.cookieAuthEnabled {
		cookies, err = newCookieAuth(auth, c.cookieAuthDuration, c.mode != "http")
		if err != nil {
			return fmt.Errorf("initialize cookie authentication: %w", err)
		}
	}
	return forwardHTTP(ctx, client, l, addresses, c.dialTimeout, c.drainTimeout, c.mode == "http", auth, cookies, out)
}

type pair struct{ public, local net.Conn }
type forwarder struct {
	mu       sync.Mutex
	active   map[*pair]bool
	stopping bool
	wg       sync.WaitGroup
	ctx      context.Context
	cancel   context.CancelFunc
	slots    chan struct{}
}

func (f *forwarder) abort() {
	f.cancel()
	f.mu.Lock()
	f.stopping = true
	for p := range f.active {
		_ = p.public.Close()
		if p.local != nil {
			_ = p.local.Close()
		}
	}
	f.mu.Unlock()
}
func forward(ctx context.Context, client *tunnel.Client, l net.Listener, addresses []string, dialTimeout, drainTimeout time.Duration, out io.Writer) error {
	// Relay cancellation is separate: a termination signal stops admission via
	// CloseGracefully, but allocated streams must continue being accepted/served.
	relayCtx, cancel := context.WithCancel(context.WithoutCancel(ctx))
	defer cancel()
	f := &forwarder{ctx: relayCtx, cancel: cancel, active: map[*pair]bool{}, slots: make(chan struct{}, 128)}
	accepted := make(chan error, 1)
	go func() {
		for {
			conn, err := l.Accept()
			if err != nil {
				accepted <- err
				return
			}
			select {
			case f.slots <- struct{}{}:
			default:
				_ = conn.Close()
				continue
			}
			p := &pair{public: conn}
			f.mu.Lock()
			if f.stopping {
				f.mu.Unlock()
				_ = conn.Close()
				<-f.slots
				continue
			}
			f.active[p] = true
			f.wg.Add(1)
			f.mu.Unlock()
			go func(parent context.Context) {
				defer f.wg.Done()
				defer func() {
					f.mu.Lock()
					delete(f.active, p)
					f.mu.Unlock()
					<-f.slots
					_ = p.public.Close()
					if p.local != nil {
						_ = p.local.Close()
					}
				}()
				dialCtx, stop := context.WithTimeout(parent, dialTimeout)
				defer stop()
				var local net.Conn
				var dialErr error
				for _, address := range addresses {
					local, dialErr = (&net.Dialer{}).DialContext(dialCtx, "tcp", address)
					if dialErr == nil {
						break
					}
				}
				if dialErr != nil {
					log.Printf("local target dial: %v", dialErr)
					return
				}
				f.mu.Lock()
				if f.stopping {
					f.mu.Unlock()
					_ = local.Close()
					return
				}
				p.local = local
				f.mu.Unlock()
				if err := relay(p.public, local); err != nil {
					log.Printf("relay: %v", err)
				}
			}(f.ctx)
		}
	}()
	select {
	case err := <-accepted:
		f.abort()
		f.wg.Wait()
		return fmt.Errorf("tunnel listener: %w", err)
	case <-ctx.Done():
		if _, err := fmt.Fprintln(out, "draining allocated connections"); err != nil {
			return fmt.Errorf("announce connection drain: %w", err)
		}
		drain, stop := context.WithTimeout(context.WithoutCancel(ctx), drainTimeout)
		defer stop()
		err := client.CloseGracefully(drain)
		// CloseGracefully closes listener even on timeout. Stop accept before Wait.
		<-accepted
		f.abort()
		f.wg.Wait()
		if err != nil {
			return fmt.Errorf("drain tunnel connections: %w", err)
		}
		return nil
	}
}
func relay(public, local net.Conn) error {
	done := make(chan error, 2)
	copyDirection := func(dst, src net.Conn) {
		_, err := io.Copy(dst, src)
		if err == nil {
			if half, ok := dst.(interface{ CloseWrite() error }); ok {
				err = half.CloseWrite()
			} else {
				err = errors.New("connection does not support half-close")
			}
		}
		if err != nil {
			_ = public.Close()
			_ = local.Close()
		}
		done <- err
	}
	go copyDirection(local, public)
	go copyDirection(public, local)
	first, second := <-done, <-done
	return errors.Join(first, second)
}

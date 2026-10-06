package main

import (
	"crypto/tls"
	"fmt"
	"io"
	"log"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	"github.com/fasmide/tunnel"
	"github.com/fasmide/tunnel/internal/cli"
	"github.com/fasmide/tunnel/internal/server"
	"github.com/fasmide/tunnel/internal/transportpki"
	"github.com/spf13/cobra"
	"golang.org/x/sys/unix"
)

type config struct {
	stateDir, socketPath, pprofPath, quicAddr, public, plain, certPath, keyPath, domain string
	exportCA                                                                            bool
}

func newCommand(c *config, action func(config) error) *cobra.Command {
	cmd := &cobra.Command{Use: "tunneld", Short: "Run the public reverse tunnel server",
		Long:    "Route public HTTP and TLS traffic to approved clients over QUIC.\nChoose a generated constrained CA (--domain) or a transport certificate (--cert/--key).",
		Example: "  tunneld --domain tunnel.example.net\n  tunneld --domain tunnel.example.net --export-ca",
		Args:    cobra.NoArgs, SilenceUsage: true, SilenceErrors: true}
	flags := cmd.Flags()
	flags.StringVarP(&c.stateDir, "state", "s", "/var/lib/tunneld", "private persistent state directory")
	flags.StringVar(&c.socketPath, "socket", "/run/tunneld/admin.sock", "local admin Unix socket; parent must be private and owned by daemon user")
	flags.StringVar(&c.pprofPath, "pprof-socket", "/run/tunneld/pprof.sock", "local pprof HTTP Unix socket; parent must be private and owned by daemon user")
	flags.StringVar(&c.quicAddr, "quic", ":7443", "tunnel UDP listener")
	flags.StringVar(&c.public, "https", ":443", "public TLS TCP listener; empty disables")
	flags.StringVar(&c.plain, "http", ":80", "public HTTP TCP listener; empty disables")
	flags.StringVarP(&c.certPath, "cert", "c", "", "QUIC transport certificate PEM")
	flags.StringVarP(&c.keyPath, "key", "k", "", "QUIC transport private key PEM")
	flags.StringVarP(&c.domain, "domain", "d", "", "transport DNS base name; generates a constrained CA when --cert/--key are absent")
	flags.BoolVar(&c.exportCA, "export-ca", false, "print saved generated CA as PEM and exit; requires --domain")
	cmd.RunE = func(cmd *cobra.Command, args []string) error {
		if err := validateConfig(*c); err != nil {
			return err
		}
		return action(*c)
	}
	_ = cmd.MarkFlagDirname("state")
	_ = cmd.MarkFlagFilename("cert", "pem", "crt")
	_ = cmd.MarkFlagFilename("key", "pem", "key")
	cli.AddCompletion(cmd)
	return cmd
}

//nolint:unused // Used by tests, which are excluded from linting.
func parse(args []string) (config, error) {
	var c config
	cmd := newCommand(&c, func(config) error { return nil })
	cmd.SetArgs(args)
	cmd.SetOut(io.Discard)
	cmd.SetErr(io.Discard)
	if err := cmd.Execute(); err != nil {
		return c, fmt.Errorf("parse tunneld command: %w", err)
	}
	return c, nil
}

func validateConfig(c config) error {
	if (c.certPath == "") != (c.keyPath == "") {
		return fmt.Errorf("--cert and --key must be supplied together")
	}
	if c.certPath != "" && (c.domain != "" || c.exportCA) {
		return fmt.Errorf("choose --cert/--key or generated --domain mode, not both")
	}
	if c.certPath == "" && c.domain == "" {
		return fmt.Errorf("--domain is required when --cert/--key are absent")
	}
	return nil
}

func main() {
	if err := run(os.Args[1:]); err != nil {
		log.Fatal(err)
	}
}

func run(args []string) error {
	var c config
	cmd := newCommand(&c, func(c config) error { return executeConfig(c, os.Stdout) })
	cmd.SetArgs(args)
	if err := cmd.Execute(); err != nil {
		return fmt.Errorf("tunneld: %w", err)
	}
	return nil
}

func executeConfig(c config, out io.Writer) error {
	if err := os.MkdirAll(c.stateDir, 0700); err != nil {
		return fmt.Errorf("create state directory: %w", err)
	}
	info, err := os.Stat(c.stateDir)
	if err != nil {
		return fmt.Errorf("stat state directory: %w", err)
	}
	if info.Mode().Perm()&0077 != 0 {
		return fmt.Errorf("state directory must not be accessible by group/others")
	}
	if stat, ok := info.Sys().(*syscall.Stat_t); !ok || int(stat.Uid) != os.Geteuid() {
		return fmt.Errorf("state directory must be owned by daemon user")
	}
	lock, err := os.OpenFile(filepath.Join(c.stateDir, "daemon.lock"), os.O_CREATE|os.O_RDWR, 0600)
	if err != nil {
		return fmt.Errorf("open daemon state lock: %w", err)
	}
	defer func() { _ = lock.Close() }()
	if err = unix.Flock(int(lock.Fd()), unix.LOCK_EX|unix.LOCK_NB); err != nil {
		return fmt.Errorf("another daemon owns state: %w", err)
	}
	defer func() { _ = unix.Flock(int(lock.Fd()), unix.LOCK_UN) }()
	storage := tunnel.FileStorage(c.stateDir)
	var tlsConfig *tls.Config
	var issuer *transportpki.Authority
	if c.certPath != "" {
		cert, err := tls.LoadX509KeyPair(c.certPath, c.keyPath)
		if err != nil {
			return fmt.Errorf("load transport certificate/key: %w", err)
		}
		tlsConfig = &tls.Config{Certificates: []tls.Certificate{cert}}
	} else {
		authority, err := transportpki.Open(storage, c.domain, time.Now())
		if err != nil {
			return fmt.Errorf("open generated transport authority: %w", err)
		}
		if c.exportCA {
			if _, err = out.Write(authority.PEM()); err != nil {
				return fmt.Errorf("write generated transport CA: %w", err)
			}
			return nil
		}
		log.Printf("transport CA SHA-256 fingerprint: %s", authority.Fingerprint())
		tlsConfig = authority.Config()
		issuer = authority
	}
	manager, err := server.OpenManager(storage)
	if err != nil {
		return fmt.Errorf("open server state manager: %w", err)
	}
	socket := c.socketPath
	if err := prepareSocketDirectory(socket); err != nil {
		return err
	}
	if err := prepareSocketDirectory(c.pprofPath); err != nil {
		return err
	}
	runtimeLock, err := os.OpenFile(socket+".lock", os.O_CREATE|os.O_RDWR, 0600)
	if err != nil {
		return fmt.Errorf("open admin socket lock: %w", err)
	}
	defer func() { _ = runtimeLock.Close() }()
	if err := unix.Flock(int(runtimeLock.Fd()), unix.LOCK_EX|unix.LOCK_NB); err != nil {
		return fmt.Errorf("admin socket owned by another daemon: %w", err)
	}
	if err := prepareSocketPath(socket, "admin socket"); err != nil {
		return err
	}
	if err := prepareSocketPath(c.pprofPath, "pprof socket"); err != nil {
		return err
	}
	fingerprint, domain := "", ""
	if issuer != nil {
		fingerprint = issuer.Fingerprint()
		domain = c.domain
	}
	admin, err := server.ListenAdmin(socket, manager, fingerprint, domain)
	if err != nil {
		return fmt.Errorf("listen on admin socket: %w", err)
	}
	defer func() { _ = admin.Close() }()
	pprofServer, err := listenPprof(c.pprofPath)
	if err != nil {
		return err
	}
	defer func() { _ = pprofServer.Close() }()
	daemon, err := server.ListenWithAuthority(c.quicAddr, tlsConfig, manager, issuer)
	if err != nil {
		return fmt.Errorf("listen for tunnel QUIC traffic: %w", err)
	}
	defer func() { _ = daemon.Close() }()
	log.Printf("tunnel UDP %s; admin %s; pprof %s", daemon.Addr(), socket, c.pprofPath)
	if c.public != "" {
		edge, err := daemon.ListenTLS(c.public)
		if err != nil {
			return fmt.Errorf("listen for public TLS traffic: %w", err)
		}
		log.Printf("public TLS TCP %s", edge.Addr())
	}
	if c.plain != "" {
		edge, err := daemon.ListenHTTP(c.plain)
		if err != nil {
			return fmt.Errorf("listen for public HTTP traffic: %w", err)
		}
		log.Printf("public HTTP TCP %s", edge.Addr())
	}
	signals := make(chan os.Signal, 1)
	signal.Notify(signals, syscall.SIGINT, syscall.SIGTERM)
	defer signal.Stop(signals)
	<-signals
	return nil
}

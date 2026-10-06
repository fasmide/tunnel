package main

import (
	"crypto/tls"
	"errors"
	"fmt"
	"log"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	"github.com/spf13/pflag"
	"golang.org/x/sys/unix"
	"tunnel"
	"tunnel/internal/server"
	"tunnel/internal/transportpki"
)

type config struct {
	stateDir, socketPath, pprofPath, quicAddr, public, plain, certPath, keyPath, domain string
	exportCA                                                                            bool
}

func parse(args []string) (config, error) {
	c := config{}
	flags := pflag.NewFlagSet("tunneld", pflag.ContinueOnError)
	flags.Usage = func() {}
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
	if err := flags.Parse(args); err != nil {
		return c, fmt.Errorf("parse flags: %w", err)
	}
	if flags.NArg() != 0 {
		return c, fmt.Errorf("no positional arguments expected")
	}
	if (c.certPath == "") != (c.keyPath == "") {
		return c, fmt.Errorf("--cert and --key must be supplied together")
	}
	if c.certPath != "" && (c.domain != "" || c.exportCA) {
		return c, fmt.Errorf("choose --cert/--key or generated --domain mode, not both")
	}
	if c.certPath == "" && c.domain == "" {
		return c, fmt.Errorf("--domain is required when --cert/--key are absent")
	}
	return c, nil
}

func main() {
	if err := run(os.Args[1:]); err != nil {
		if errorsIsHelp(err) {
			return
		}
		log.Fatal(err)
	}
}

func errorsIsHelp(err error) bool { return errors.Is(err, pflag.ErrHelp) }

func run(args []string) error {
	c, err := parse(args)
	if err != nil {
		return err
	}
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
			if _, err = os.Stdout.Write(authority.PEM()); err != nil {
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

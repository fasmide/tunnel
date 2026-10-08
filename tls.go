package tunnel

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"io/fs"
	"net"
	"strings"
	"time"

	"github.com/fasmide/tunnel/internal/names"
	"github.com/fasmide/tunnel/internal/streamconn"
	"golang.org/x/crypto/acme"
	"golang.org/x/crypto/acme/autocert"
)

// WithACMEClient selects an alternate ACME directory/HTTP transport (e.g. a
// staging CA). The client is copied; a nil account Key uses persisted storage.
// Supply this before Dial. Only TLS-ALPN-01 is enabled, regardless of CA offers.
func WithACMEClient(client *acme.Client) Option {
	return func(o *dialOptions) error {
		if client == nil {
			return errors.New("nil ACME client")
		}
		o.acme = &acme.Client{Key: client.Key, HTTPClient: client.HTTPClient, DirectoryURL: client.DirectoryURL, RetryBackoff: client.RetryBackoff, UserAgent: client.UserAgent, KID: client.KID}
		return nil
	}
}
func WithACMEEmail(email string) Option {
	return func(o *dialOptions) error { o.email = email; return nil }
}

// WithACMEErrorHandler reports certificate acquisition errors that otherwise
// only fail the incoming TLS handshake. The handler may be called concurrently
// and should return promptly. A nil handler disables reporting.
func WithACMEErrorHandler(handler func(host string, err error)) Option {
	return func(o *dialOptions) error { o.acmeError = handler; return nil }
}

// ListenTLS terminates public TLS locally with an application-provided config.
// Accepted connections have completed TLS handshakes. The daemon never sees
// this configuration or its certificate private keys.
func (c *Client) ListenTLS(ctx context.Context, name string, config *tls.Config) (net.Listener, error) {
	if config == nil {
		return nil, errors.New("nil listener TLS configuration")
	}
	if len(config.Certificates) == 0 && config.GetCertificate == nil && config.GetConfigForClient == nil {
		return nil, errors.New("listener TLS certificate source required")
	}
	return c.listen(ctx, name, "byo", config.Clone())
}

// Listen terminates TLS locally using on-demand ACME certificates. It accepts
// the configured CA's terms of service. By default the CA is Let's Encrypt and
// only TLS-ALPN-01 is used; DNS must resolve to the daemon on public TCP 443.
// Credential storage also stores the ACME account and cached certificates.
func (c *Client) Listen(ctx context.Context, name string) (net.Listener, error) {
	return c.ListenWithClientAuth(ctx, name, nil)
}

// ClientAuthConfig configures public client-certificate authentication, separate
// from tunnel transport credentials. VerifyConnection also runs on resumption.
type ClientAuthConfig struct {
	ClientAuth       tls.ClientAuthType
	ClientCAs        *x509.CertPool
	VerifyConnection func(tls.ConnectionState) error
}

func applyClientAuth(config *tls.Config, auth *ClientAuthConfig) {
	if auth == nil {
		return
	}
	config.ClientAuth = auth.ClientAuth
	if auth.ClientCAs != nil {
		config.ClientCAs = auth.ClientCAs.Clone()
	}
	config.VerifyConnection = auth.VerifyConnection
}

// ListenWithClientAuth is Listen with public client authentication. ACME
// TLS-ALPN-01 challenge connections are exempt and never reach Accept.
func (c *Client) ListenWithClientAuth(ctx context.Context, name string, auth *ClientAuthConfig) (net.Listener, error) {
	c.acmeMu.Lock()
	defer c.acmeMu.Unlock()
	if c.storage == nil {
		return nil, errors.New("ACME requires credential storage")
	}
	if c.acmeManager == nil {
		client := c.acmeClient
		if client == nil {
			client = &acme.Client{}
		}
		if client.Key == nil {
			key, err := loadACMEAccount(c.storage)
			if err != nil {
				return nil, err
			}
			client.Key = key
		}
		manager := &autocert.Manager{Prompt: autocert.AcceptTOS, Cache: acmeCache{c.storage}, Client: client, Email: c.acmeEmail, HostPolicy: c.acmeHostPolicy}
		c.acmeManager = manager
	}
	config := c.acmeManager.TLSConfig()
	// Check policy even for cached certificates: autocert's HostPolicy is only
	// consulted for issuance and would otherwise allow a stale cached grant.
	get := config.GetCertificate
	// Certificate issuance outlives Listen's setup context, just like the client.
	config.GetCertificate = c.acmeGetCertificate(c.ctx, get) //nolint:contextcheck // Use client lifetime, not the short-lived setup context.
	applyClientAuth(config, auth)
	if auth != nil {
		application := config.Clone()
		challenge := config.Clone()
		challenge.ClientAuth = tls.NoClientCert
		challenge.ClientCAs = nil
		challenge.VerifyConnection = nil
		challenge.NextProtos = []string{acme.ALPNProto}
		config.GetConfigForClient = func(hello *tls.ClientHelloInfo) (*tls.Config, error) {
			// Match autocert's challenge selection: only a sole acme-tls/1 offer
			// is exempt. Negotiating it never grants application access.
			if len(hello.SupportedProtos) == 1 && hello.SupportedProtos[0] == acme.ALPNProto {
				return challenge, nil
			}
			return application, nil
		}
	}
	return c.listen(ctx, name, "acme", config)
}
func (c *Client) acmeGetCertificate(ctx context.Context, get func(*tls.ClientHelloInfo) (*tls.Certificate, error)) func(*tls.ClientHelloInfo) (*tls.Certificate, error) {
	return func(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
		host, err := canonicalName(hello.ServerName)
		if err != nil {
			return nil, err
		}
		if err := c.acmeHostPolicy(ctx, host); err != nil {
			return nil, err
		}
		cert, err := get(hello)
		if err != nil && c.options.acmeError != nil {
			c.options.acmeError(host, err)
		}
		return cert, err
	}
}
func (c *Client) acmeHostPolicy(ctx context.Context, name string) error {
	if err := ctx.Err(); err != nil {
		return fmt.Errorf("ACME host policy canceled: %w", err)
	}
	if !names.Valid(name) {
		return errors.New("invalid ACME host")
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.terminal != nil {
		return c.terminal
	}
	if !allowed(c.routes, name) {
		return errors.New("ACME name is not currently authorized")
	}
	return nil
}

func (l *rawListener) receive(ctx context.Context, conn *streamconn.Conn, host string) {
	if l.tlsConfig == nil {
		if !l.deliver(conn) {
			conn.Abort()
		}
		return
	}
	l.mu.Lock()
	if l.closed || len(l.handshakes) >= 64 {
		l.mu.Unlock()
		conn.Abort()
		return
	}
	l.handshakes[conn] = true
	l.mu.Unlock()
	defer func() { l.mu.Lock(); delete(l.handshakes, conn); l.mu.Unlock() }()
	local := tls.Server(conn, l.tlsConfig)
	if err := local.SetDeadline(time.Now().Add(2 * time.Minute)); err != nil {
		conn.Abort()
		return
	}
	handshakeCtx, cancel := context.WithTimeout(ctx, 2*time.Minute)
	defer cancel()
	if err := local.HandshakeContext(handshakeCtx); err != nil {
		conn.Abort()
		return
	}
	actual, err := canonicalName(local.ConnectionState().ServerName)
	if err != nil || actual != host {
		conn.Abort()
		return
	}
	if err := local.SetDeadline(time.Time{}); err != nil {
		conn.Abort()
		return
	}
	// Answer validation inside the library, even if application Accept is idle.
	// Neither challenge connections nor failed handshakes reach HTTP handlers.
	if l.mode == "acme" && local.ConnectionState().NegotiatedProtocol == acme.ALPNProto {
		_ = local.Close()
		return
	}
	// Remove from handshake tracking before publishing to Accept, so listener
	// Close cannot abort a connection already handed to the application.
	l.mu.Lock()
	delete(l.handshakes, conn)
	l.mu.Unlock()
	if !l.deliver(local) {
		conn.Abort()
	}
}

// Initialize/persist account material ourselves: autocert's lazy account cache
// tolerates write errors, which is unsuitable for a durable identity setup.
func loadACMEAccount(storage Storage) (*ecdsa.PrivateKey, error) {
	credentialInitMu.Lock()
	defer credentialInitMu.Unlock()
	data, err := storage.Get("acme/account")
	if errors.Is(err, fs.ErrNotExist) {
		key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			return nil, fmt.Errorf("generate ACME account key: %w", err)
		}
		der, err := x509.MarshalECPrivateKey(key)
		if err != nil {
			return nil, fmt.Errorf("marshal ACME account key: %w", err)
		}
		data = pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: der})
		if err := storage.Put("acme/account", data); err != nil {
			return nil, fmt.Errorf("persist ACME account key: %w", err)
		}
		data, err = storage.Get("acme/account")
		if err != nil {
			return nil, fmt.Errorf("reload ACME account key: %w", err)
		}
	} else if err != nil {
		return nil, fmt.Errorf("load ACME account key: %w", err)
	}
	block, _ := pem.Decode(data)
	if block == nil {
		return nil, errors.New("invalid ACME account key")
	}
	key, err := x509.ParseECPrivateKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parse ACME account key: %w", err)
	}
	return key, nil
}

type acmeCache struct{ storage Storage }

func acmeCacheKey(key string) (string, error) {
	if key == "acme_account+key" || key == "acme_account.key" {
		return "acme/account", nil
	}
	base := key
	prefix := "acme/cert/"
	if strings.HasSuffix(base, "+token") {
		base = strings.TrimSuffix(base, "+token")
		prefix = "acme/challenge/"
	}
	rsa := false
	if strings.HasSuffix(base, "+rsa") {
		base = strings.TrimSuffix(base, "+rsa")
		rsa = true
	}
	if !names.Valid(base) {
		return "", errors.New("invalid ACME cache key")
	}
	if rsa {
		return "acme/cert-rsa/" + base, nil
	}
	return prefix + base, nil
}
func (cache acmeCache) Get(ctx context.Context, key string) ([]byte, error) {
	if err := ctx.Err(); err != nil {
		return nil, fmt.Errorf("ACME cache get canceled: %w", err)
	}
	key, err := acmeCacheKey(key)
	if err != nil {
		return nil, err
	}
	data, err := cache.storage.Get(key)
	if errors.Is(err, fs.ErrNotExist) {
		err = autocert.ErrCacheMiss
	} else if err != nil {
		return nil, fmt.Errorf("load ACME cache entry %q: %w", key, err)
	}
	return data, err
}
func (cache acmeCache) Put(ctx context.Context, key string, data []byte) error {
	if err := ctx.Err(); err != nil {
		return fmt.Errorf("ACME cache put canceled: %w", err)
	}
	key, err := acmeCacheKey(key)
	if err != nil {
		return err
	}
	if err := cache.storage.Put(key, data); err != nil {
		return fmt.Errorf("store ACME cache entry %q: %w", key, err)
	}
	return nil
}
func (cache acmeCache) Delete(ctx context.Context, key string) error {
	if err := ctx.Err(); err != nil {
		return fmt.Errorf("ACME cache delete canceled: %w", err)
	}
	key, err := acmeCacheKey(key)
	if err != nil {
		return err
	}
	if err := cache.storage.Delete(key); err != nil {
		return fmt.Errorf("delete ACME cache entry %q: %w", key, err)
	}
	return nil
}

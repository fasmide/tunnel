# tunnel

Expose a Go application through a server you control—even when the application
is behind NAT or has no public listening port.

Your application makes an outbound QUIC connection to `tunneld`. The daemon
routes incoming connections to it, and the Go package presents them as ordinary
`net.Listener` connections. Your application serves them with `http.Serve` or
its own server code.

```text
Browser ── HTTPS ──> your public tunneld ── QUIC tunnel ──> your Go application
                    routes by hostname                    terminates public TLS
```

- **`tunnel`**: Go listeners, persistent identity, reconnect, and graceful drain.
- **`tunneld`**: public entry point and hostname routing; does not decrypt public TLS.
- **`tunnelctl`**: local administration: approve identities, change grants, revoke access.
- **`tunnelproxy`**: expose an existing localhost TCP service without Go integration.

An approved name also grants its descendants. More-specific owners and listeners
win; multiple instances using the same identity share a round-robin pool.

**Pre-release.** Requires Go 1.25+; the daemon targets Linux. The module currently
uses the local import path `tunnel`, not a published `go get` path. Public ACME
issuance, long-running renewal, and adverse-network/load behavior still need
validation. See [conformance evidence](CONFORMANCE.md) for tested guarantees and limits.

## 1. Run your public server

Build from this checkout:

```sh
go build -o bin/tunneld ./cmd/tunneld
go build -o bin/tunnelctl ./cmd/tunnelctl
bin/tunneld --state /var/lib/tunneld --domain tunnel.example.com
```

Without `--cert`/`--key`, the daemon generates and persists a private transport CA
constrained to `tunnel.example.com` and its descendants. It prints the CA's
SHA-256 fingerprint and automatically renews short-lived transport certificates
for the base name and `*.tunnel.example.com`. The CA lasts 25 years; rotation
is explicit. Keep state backed up: changing the CA changes client trust.

Administrators can instead supply normal publicly trusted or private-PKI PEM
certificates (renewed externally), without generated-CA bootstrap:

```sh
bin/tunneld --state /var/lib/tunneld --cert transport.crt --key transport.key
```

These secure the **application-to-daemon connection**, not application HTTPS.
Supply both files; do not combine them with `--domain`. The certificate must cover
the daemon hostname. Clients use normal system trust unless configured otherwise.

Point application DNS names at this server. Allow UDP **7443** for tunnels,
TCP **443** for public TLS, and TCP **80** for HTTP/HTTPS redirects. The daemon
needs permission to bind those ports and a private, writable state directory
owned by its user. Defaults above can be changed with `--quic`, `--https`, and
`--http`; an empty `--https` or `--http` disables that edge.

For a managed Linux deployment, use the [hardened systemd unit](deploy/systemd/README.md)
with a dynamic user, private persistent state, and systemd credentials. For
application-side `tunnelproxy` deployments under a normal account, see the
[user-mode systemd examples](deploy/systemd/user/README.md).

The admin socket defaults to `/run/tunneld/admin.sock`, in a private systemd
RuntimeDirectory separate from persistent state. `tunneld` also exposes standard
Go pprof handlers on `/run/tunneld/pprof.sock` by default, over a local Unix
socket rather than a TCP port. `tunnelctl` defaults to the admin socket; use
`-s PATH` or `--socket PATH` for a custom location. Outside systemd the daemon
creates/validates its private socket directory; non-root users should choose an
owned runtime path with `--socket` / `--pprof-socket` rather than trying to
create `/run/tunneld`.

For example:

```sh
curl --unix-socket /run/tunneld/pprof.sock http://localhost/debug/pprof/heap > heap.pprof
curl --unix-socket /run/tunneld/pprof.sock 'http://localhost/debug/pprof/profile?seconds=30' > cpu.pprof
go tool pprof /usr/local/bin/tunneld cpu.pprof
```

## 2. Request and approve access

For generated-CA mode, bootstrap endpoint-local trust first. Imports in these
snippets are `context`, `log`, `time`, and `tunnel`:

```go
storage := tunnel.FileStorage("./tunnel-state")
addr := "tunnel.example.com:7443"
ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
defer cancel()
trust, err := tunnel.BootstrapTrust(ctx, addr, tunnel.TrustRequest{
    Storage: storage,
    Fingerprint: "ADMINISTRATOR_SUPPLIED_64_CHARACTER_LOWERCASE_HEX_SHA256",
})
if err != nil {
    log.Fatal(err)
}
log.Printf("trusted transport CA %s", trust.Fingerprint)
transportTLS, err := tunnel.LoadTransportTLS(storage, addr, "")
if err != nil {
    log.Fatal(err)
}
```

The CA is downloaded from the QUIC TLS certificate chain on UDP 7443; no extra
HTTP endpoint or system-wide CA installation is needed. Verify the fingerprint
through a trusted channel. Alternatively select **explicit TOFU** by replacing
`Fingerprint` with `TOFU: true`: the first connection can be intercepted, but
subsequent calls reject a changed CA. There is no silent trust reset.
For an IP endpoint, set `ServerName` to its certified DNS name during bootstrap
and pass that same name to `LoadTransportTLS`; generated CAs exclude all IP SANs.
The CA permits all descendants, but the supplied wildcard leaf covers only one
level. Do not install the CA system-wide: trust-anchor constraint enforcement
varies between platforms.

Then create/persist the application identity and submit a signed request. Add
`TLSConfig: transportTLS` to the request below in generated-CA mode. With a
publicly trusted administrator certificate, skip bootstrap and use system trust.

```go
ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
defer cancel()

creds, err := tunnel.RequestJoin(ctx, "tunnel.example.com:7443", tunnel.JoinRequest{
    Routes:  []string{"app.example.com"},
    Storage: tunnel.FileStorage("./tunnel-state"),
})
if err != nil {
    log.Fatal(err)
}
log.Printf("requested access for identity %s", creds.Identity())
```

A successful request is **pending**, not approved. On the public server, run
these as the daemon user (or root):

```sh
bin/tunnelctl invites
bin/tunnelctl approve INVITE_ID
# If a route is already owned and you want to replace that identity:
bin/tunnelctl --replace approve INVITE_ID
```

Keep the application state directory private and durable: it holds its identity
key and, when using ACME, certificate keys. Never commit it to source control.

## 3. Serve HTTPS from Go

After approval, this program loads the same identity and serves HTTPS through
the tunnel. `Listen` obtains certificates on demand using ACME, with Let's
Encrypt by default. Application DNS must point to the daemon, publicly reachable
on TCP 443; `Listen` accepts the configured CA's terms of service.

```go
package main

import (
    "context"
    "log"
    "net/http"
    "time"

    "tunnel"
)

func main() {
    creds, err := tunnel.LoadCredentials(tunnel.FileStorage("./tunnel-state"))
    if err != nil {
        log.Fatal(err)
    }

    ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
    defer cancel()
    client, err := tunnel.Dial(ctx, "tunnel.example.com:7443",
        tunnel.WithCredentials(creds))
    if err != nil {
        log.Fatal(err)
    }
    defer client.Close()

    listener, err := client.Listen("app.example.com")
    if err != nil {
        log.Fatal(err)
    }
    defer listener.Close()

    mux := http.NewServeMux()
    mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
        _, _ = w.Write([]byte("Hello through the tunnel!\n"))
    })
    if err := http.Serve(listener, mux); err != nil {
        log.Printf("HTTP server stopped: %v", err)
    }
}
```

In generated-CA mode, also load the saved trust with `LoadTransportTLS` and pass
`tunnel.WithTLSConfig(transportTLS)` to Dial. Trust loading is explicit; saving a
CA does not change the system trust store or make Dial automatically use it.

Visit `https://app.example.com`. The initial dial context bounds setup; after
Dial succeeds, the client reconnects independently. Existing listeners survive
outages, but interrupted connections fail—request bytes are never replayed.

### Runnable Go API example

[`cmd/hello`](cmd/hello/main.go) is a standalone “Hello, world!” web server using
the package directly, with HTTP/2 support and no localhost proxy:

```sh
go run ./cmd/hello -join -name hello.tunnel.example.net -tofu
# On the daemon: tunnelctl invites
# Then: tunnelctl approve INVITE_ID
go run ./cmd/hello -name hello.tunnel.example.net -mode private
```

Use `-fingerprint SHA256_HEX` instead of `-tofu` for verified first contact.
The server defaults to `tunnel.example.net:7443`; override with `-server HOST:PORT`.
State defaults to `$XDG_CONFIG_HOME/tunnel-hello` or `~/.config/tunnel-hello` on
Linux, independently of tunnelproxy; override with `-state`. Private mode needs
browser trust in the daemon CA. Omit `-mode private` for default ACME HTTPS.
The example closes immediately on SIGINT/SIGTERM to keep it simple; it is not a
graceful-drain reference. Do not run it alongside another listener for the same
name unless intentionally configuring an authorized same-key pool.

## Existing software: tunnelproxy

For an existing web server on `127.0.0.1:8080`, build the standalone client:

```sh
go build -o bin/tunnelproxy ./cmd/tunnelproxy
bin/tunnelproxy join --server tunnel.example.net:7443 --name app.tunnel.example.net \
  --state ./proxy-state --fingerprint ADMINISTRATOR_CA_SHA256_HEX
```

Approve the invite with `tunnelctl` on the daemon, then start forwarding:

```sh
bin/tunnelproxy serve --server tunnel.example.net:7443 --name app.tunnel.example.net \
  --state ./proxy-state --target 127.0.0.1:8080
```

Or combine both steps with `joinserve`, which submits a join request when needed,
waits for administrator approval, then starts forwarding:

```sh
bin/tunnelproxy joinserve --server tunnel.example.net:7443 --name app.tunnel.example.net \
  --state ./proxy-state --target 127.0.0.1:8080 \
  --fingerprint ADMINISTRATOR_CA_SHA256_HEX
```

Default mode is **ACME HTTPS**: tunnelproxy terminates public TLS locally and
reverse-proxies browser HTTP/2 or HTTP/1.1 to **HTTP/1.1** on your loopback service.
Python's HTTP server and other HTTP/1-only services work without protocol flags.
HTTP/3 is not supported. It accepts the CA's terms;
DNS/public TCP 443 must reach the daemon. Public issuance has not yet been
validated in this environment. The constrained transport CA is separate from
these browser-facing certificates.

For explicit first-use trust, replace `--fingerprint ...` with `--tofu` (first
contact can be intercepted). Saved transport trust is reused by later `serve`
or `joinserve` runs and is never silently replaced. `serve` requires an existing
approved identity in state; `joinserve` can create or reuse the local identity,
wait for approval, then continue automatically. If the daemon uses a normal
system-trusted certificate, omit both bootstrap flags. `--server-name` supplies
a certified DNS name when dialing an IP. `--server` accepts a hostname without
a port and defaults to **7443**; explicit `host:port` and bracketed IPv6 with a
port also work. On Linux, state defaults to **`$XDG_CONFIG_HOME/tunnelproxy`**,
or **`~/.config/tunnelproxy`** when XDG_CONFIG_HOME is unset. Override with
`--state`; keep it private and durable. Do not concurrently initialize shared
state. Short forms `-s`, `-n`, `-t`, `-m`, and `-f` are also available. For
example, with explicit TOFU:

```sh
bin/tunnelproxy join --server tunnel.example.net --name hello.tunnel.example.net --tofu
# After approval, saved identity and trust are reused:
bin/tunnelproxy serve --server tunnel.example.net --name hello.tunnel.example.net --target 127.0.0.1:8080
# Or wait for approval and start serving in one command:
bin/tunnelproxy joinserve --server tunnel.example.net --name hello.tunnel.example.net \
  --target 127.0.0.1:8080 --tofu
```

Other modes are explicit:

```sh
# Local HTTPS service owns public TLS: encrypted bytes passed through unchanged.
bin/tunnelproxy serve --server tunnel.example.net:7443 --name app.tunnel.example.net \
  --state ./proxy-state --target 127.0.0.1:8443 --mode raw

# Terminate public TLS in tunnelproxy using your certificate, forward to HTTP.
bin/tunnelproxy serve --server tunnel.example.net:7443 --name app.tunnel.example.net \
  --state ./proxy-state --target 127.0.0.1:8080 --mode byo --cert app.crt --key app.key

# Explicit public plaintext HTTP exception.
bin/tunnelproxy serve --server tunnel.example.net:7443 --name app.tunnel.example.net \
  --state ./proxy-state --target 127.0.0.1:8080 --mode http
```

### Benchmarking and profiling

There are end-to-end Go benchmarks that exercise real QUIC transport and edge
forwarding paths. Run them from the module root, for example:

```sh
go test -run '^$' -bench BenchmarkE2E -benchmem ./...
go test -run '^$' -bench BenchmarkE2ETLSRequest -cpuprofile cpu.out -memprofile mem.out .
go tool pprof -http=:0 cpu.out
```

The focused benchmarks currently cover:

- TLS edge request through the public listener
- TLS edge request over a reused keep-alive connection
- plaintext HTTP listener path
- raw stream round-trip through the tunnel
- approved Dial without join work
- join + approve + dial lifecycle

Use these first to separate handshake cost from steady-state forwarding cost,
then spot obvious allocation, routing, or relay hot paths before moving on to
finer-grained microbenchmarks.

### Private HTTPS without ACME

For approved names within the daemon's constrained CA namespace:

```sh
bin/tunnelproxy serve --server tunnel.example.net --name hello.tunnel.example.net \
  --target 127.0.0.1:8000 --mode private
```

`tunneld` signs a CSR; tunnelproxy keeps its private key and terminates public TLS
locally, translating browser HTTP/2 to backend HTTP/1.1. No ACME or public CA is
involved. **Browsers must separately trust the daemon CA**; `join --tofu` or
`joinserve --tofu` only trusts transport in tunnelproxy's own state, not your
browser. `BootstrapTrust` returns public CA PEM for export, or use the
documented daemon `--export-ca` path.
Verify its fingerprint before trusting it. System/browser root-constraint
handling varies; use this for controlled private clients, not publicly trusted
websites. Administrator-supplied transport certificate mode cannot issue these
certificates and returns an error.

Go applications use `listener, err := client.ListenPrivate("hello.tunnel.example.net")`
then `http.Serve(listener, handler)`. Certificates are exact-name, seven-day
server leaves offered as **both Ed25519 and ECDSA P-256**, selected according to
the client's TLS capabilities. Keys persist under `private/cert/<name>` and
`private/cert-p256/<name>` respectively. New CAs use P-256 for browser-compatible
signatures; existing Ed25519 CA state is retained, not silently replaced, and may
still be rejected by browsers. Tunnel identity keys remain Ed25519. Descendants
issue individually on demand (no wildcard); renewal occurs on handshakes below
24 hours remaining. Per-listener cache is bounded at 512 certificates; each
algorithm issuance counts separately toward limits. Daemon issuance
limits are 30/minute/identity and 300/minute globally. Revocation stops live tunnel
traffic immediately but does **not** invalidate already issued certificates
outside the tunnel before their expiry. Back up and protect client state.

One hostname/subtree and target per process. Targets must be loopback IPs or
`localhost` (resolved once and checked); no arbitrary remote destinations.
ACME/private/BYO/plain-HTTP modes are HTTP reverse proxies: Host is preserved, hop-by-hop
headers are handled by Go's ReverseProxy, and incoming Forwarded/X-Forwarded-*
are replaced with X-Forwarded-For/Host/Proto based on the actual public connection.
Backends should trust these headers only from the local proxy. The TCP peer is
still loopback; no PROXY protocol is injected. Configure the application's
external URL if needed. HTTP/1.1 WebSocket upgrades work on TLS paths (not on
the daemon's one-shot plaintext HTTP path); HTTP/2 extended CONNECT is not supported.
Raw mode alone preserves arbitrary bytes and leaves TLS/ALPN to the backend.
SIGINT/SIGTERM drains for `-drain-timeout` (default 30 seconds), then aborts
remaining connections, including upgraded connections. Reconnect uses the client
library; failed streams are never replayed. Raw relay admission and HTTP backend
connections are bounded at 128; response-header wait is 30 seconds.
All flags follow the `join` or `serve` subcommand; `serve -h` lists them.

## How TLS works

There are **two separate TLS connections**:

1. **Tunnel transport:** QUIC/TLS 1.3 between the application and `tunneld`.
   The application verifies the daemon certificate; its persistent Ed25519
   identity authenticates it to the daemon. Signed joins and administrator
   grants decide which names it may serve.
2. **Public application TLS:** between the browser and your Go application.
   The daemon reads the visible ClientHello hostname (SNI) to choose a tunnel,
   then forwards bytes unchanged. It never terminates this TLS connection or
   receives the application's certificate private keys.

Choose a listener according to who manages public TLS:

| Method | Public TLS handling |
|---|---|
| `client.Listen(name)` | Library terminates TLS locally; on-demand ACME certificates |
| `client.ListenPrivate(name)` | Library terminates TLS locally; daemon-issued private-CA certificates |
| `client.ListenTLS(name, config)` | Library terminates TLS locally with your certificate/config |
| `client.ListenRaw(name)` | Unmodified bytes; your application must handle TLS |
| `client.ListenHTTP(name)` | Explicit **plaintext** HTTP; the daemon can read it |

`Listen`, `ListenPrivate`, and `ListenTLS` already return handshaken connections. Use `http.Serve`,
not `ServeTLS`, and do not add another TLS wrapper.

### Bring your own application certificate

Replace the `client.Listen(...)` call above with this (`crypto/tls` is required):

```go
cert, err := tls.LoadX509KeyPair("app.crt", "app.key")
if err != nil {
    log.Fatal(err)
}
listener, err := client.ListenTLS("app.example.com", &tls.Config{
    Certificates: []tls.Certificate{cert},
    MinVersion:   tls.VersionTLS12,
})
if err != nil {
    log.Fatal(err)
}
// Serve with http.Serve(listener, mux), just as above.
```

The certificate must cover the names you serve, including any descendants you
accept. `ListenRaw` can instead be wrapped with `tls.NewListener` if you want
full control of TLS. Raw still uses public SNI routing; it is not a generic
plaintext public TCP port.

For a private **transport** CA, pass verified roots and/or ServerName using
`WithTLSConfig` to Dial, and `JoinRequest.TLSConfig` when joining. These configure
daemon trust—not public application TLS. Skipping certificate verification is
not supported.

ACME uses TLS-ALPN-01 only. Descendants receive individual certificates, not a
wildcard. Independent ACME issuance in HA pools is **best-effort**: validation
can reach a different instance from the one requesting the certificate. See
[the protocol](PROTOCOL.md) for the challenge-routing limitation.

## Plain HTTP, access changes, and shutdown

Use `client.ListenHTTP("app.example.com")` with `http.Serve` only when you want
the plaintext exception. The daemon forwards one HTTP/1 request per connection;
WebSocket upgrades and CONNECT are not supported on this path. Without an
explicit HTTP listener, port 80 redirects to HTTPS.

```sh
bin/tunnelctl routes
bin/tunnelctl set-routes IDENTITY_ID app.example.com
bin/tunnelctl revoke IDENTITY_ID
```

Revocation removes all instances of that identity and aborts active traffic.
It is permanent in the current administrative API.

`client.Close()` aborts immediately. For a bounded drain:

```go
ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
defer cancel()
if err := client.CloseGracefully(ctx); err != nil {
    log.Printf("tunnel drain: %v", err)
}
```

Keep your accept/serve loop running while this call drains: it first removes
listeners from routing, then waits for allocated connections to finish. The
deadline aborts anything left. No reconnect or new Listen starts during drain.

## Development and details

```sh
make test
make conformance
make vet
make fuzz
```

- [Implementation and operational notes](IMPLEMENTATION.md): storage, credentials,
  implementation history, and operational caveats.
- [Conformance evidence](CONFORMANCE.md): tests mapped to requirements and remaining gaps.
- [Protocol](PROTOCOL.md): wire format, routing, authorization, and ACME HA limitations.
- [Project brief](AGENT_BRIEF.md): the decided design.

# tunnel

**Put your local web service on an HTTPS URL—through a server you control.**

Your application machine connects outward over QUIC, so it needs no inbound port forwarding. The public server routes connections by hostname while HTTPS terminates on your application machine: its certificate private keys stay with you.

Publish an existing service with `tunnelproxy`, or give your Go application a tunnel-backed `net.Listener`. Leave a site public or protect it with Basic authentication, a browser sign-in page, or client certificates.

```text
Browser ── HTTPS ──▶ public server ── QUIC tunnel ──▶ application machine
                    tunneld                          tunnelproxy → local service
                                                     or your Go application
```

You'll need a public server and a domain you control. Building from source requires Go 1.27.1 or newer.

## Meet the tools

### tunneld — your public entry point

Runs on the public server, accepts outbound tunnels, and routes public connections to approved clients by hostname. You control who may publish which names; application HTTPS keys never need to reach the daemon.

[Server setup and deployment →](https://github.com/fasmide/tunnel/blob/main/cmd/tunneld/README.md)

### tunnelctl — access administration

Inspect access requests, approve or reject clients, manage hostname grants, and revoke access through the daemon's local admin socket.

[Administration guide →](https://github.com/fasmide/tunnel/blob/main/cmd/tunnelctl/README.md)

### tunnelproxy — publish an existing service

Expose a loopback web service without modifying the application. Choose local HTTPS termination or TLS passthrough, and optionally restrict visitors with passwords, cookie-based sign-in, or client certificates.

[Proxy setup, serving modes, and authentication →](https://github.com/fasmide/tunnel/blob/main/cmd/tunnelproxy/README.md)

### hello — a working Go example

A small HTTP application served directly through the tunnel API. Use it to try the connection and approval flow or as a starting point for your own application.

[Run the example →](https://github.com/fasmide/tunnel/blob/main/cmd/hello/README.md)

### The tunnel package — integrate directly

Use `github.com/fasmide/tunnel` to obtain a `net.Listener` for your Go server, with persistent credentials, approval workflows, local TLS, reconnection, and graceful draining.

[Go package guide →](https://github.com/fasmide/tunnel/blob/main/docs/README.md)

Each command-line tool supports `--help`; subcommands have their own help too.

## Where things happen

Serving modes configure the **application side**. In every mode, `tunneld` authenticates tunnel clients, enforces approved hostname grants, and forwards traffic over encrypted QUIC. This transport security is separate from the browser's HTTPS connection.

For public TLS, the daemon reads the hostname from SNI and relays the TLS bytes without decrypting application traffic:

| Mode | What `tunneld` does | Where public TLS terminates | HTTPS certificate source |
| --- | --- | --- | --- |
| `acme` (default) | Reads SNI and relays TLS bytes, including ACME validation traffic | `tunnelproxy` | ACME CA; obtained and cached on the application machine |
| `private` | Reads SNI and relays TLS bytes; also signs authorized certificate requests | `tunnelproxy` | Daemon's generated constrained CA |
| `byo` | Reads SNI and relays TLS bytes | `tunnelproxy` | Operator-supplied certificate and key |
| `raw` | Reads SNI and relays TLS bytes | Local target service | Managed by the target service |
| `http` | Parses HTTP and routes by Host | No public TLS | None |

With the Go package, your application takes the place of `tunnelproxy` and chooses the corresponding listener API.

### Certificates and trust

- **ACME happens locally:** the application-side client obtains and renews certificates. The daemon forwards TLS-ALPN-01 validation connections; it does not manage the ACME account or hold application HTTPS keys.
- **Private mode adds a signing role:** the application generates its key locally and submits a CSR. The daemon checks hostname ownership and signs it. This requires the daemon's generated CA, which browsers must separately trust. The CA is a trust authority for these sites: its holder can issue other certificates for the same names even though application keys remain local.
- **BYO and raw need no daemon certificate management:** BYO loads keys in the proxy; raw leaves all TLS handling to the target. Public HTTPS certificates are distinct from the daemon's QUIC transport certificate.

### Authentication and plain HTTP

Daemon approval controls **who may publish a hostname**, not who may visit it. Optional Basic, cookie, and public client-certificate authentication run locally in `tunnelproxy`, never in `tunneld`. In raw mode, configure visitor authentication on the target instead.

HTTP mode is the exception to encrypted public traffic: the browser-to-daemon leg is plaintext, so the daemon can see requests, responses, and credentials. It forwards one HTTP/1.x request/response exchange per connection, without CONNECT or upgrades such as WebSockets. If no eligible HTTP listener exists, the daemon returns a **308 redirect to HTTPS**.

The daemon records the advertised mode but groups `acme`, `private`, `byo`, and `raw` into the same TLS forwarding class; `http` uses a separate HTTP class. The mode changes where certificates and application protocols are handled—not whether the tunnel itself is encrypted.

## Downloads and releases

Download prebuilt archives from [GitHub Releases](https://github.com/fasmide/tunnel/releases). Linux and macOS archives contain `tunneld`, `tunnelctl`, and `tunnelproxy`; Windows archives contain only `tunnelproxy`. All three platforms have amd64 and arm64 builds. Releases include a `checksums.txt` file with SHA-256 checksums.

Binaries are built without cgo. ACME mode still requires a system CA trust bundle; install `ca-certificates` in minimal Linux containers.

Every tool supports `<tool> version` (including the `hello` example). GoReleaser builds report the Git tag, full source revision, and UTC compile date:

```text
tunnelproxy
tag: v0.1.0
srcrev: <full Git commit hash>
compile date: <RFC3339 UTC timestamp>
```

Plain `go build` defaults to `dev` / `unknown` / `unknown`. Custom builds can populate `github.com/fasmide/tunnel/internal/cli.Tag`, `.SourceRevision`, and `.BuildDate` using `go build -ldflags` with `-X` assignments.

### Publishing a release

GitHub Actions runs static checks and race-enabled tests on branch pushes and pull requests, and builds downloadable GoReleaser snapshot archives. Pushing a semantic-version tag runs the checks again and publishes a GitHub Release with archives, checksums, and generated release notes:

```sh
git tag -a v0.1.0 -m "Release v0.1.0"
git push origin v0.1.0
```

Use a tag such as `v0.1.0-rc.1` for a prerelease. No additional token secret is required: the release workflow uses GitHub's built-in `GITHUB_TOKEN` with release-job-only write permission.

To validate or build locally with [GoReleaser v2](https://goreleaser.com/install/):

```sh
goreleaser check
goreleaser release --snapshot --clean
```

Output is written to `dist/`. The `hello` command remains a source example and is not included in release archives.

## Development

Run `make test` for race-enabled tests or `make vet` for static checks. Tests require curl and OpenSSL 3+ for the [client-certificate interoperability test](https://github.com/fasmide/tunnel/blob/main/cmd/tunnelproxy/README.md#interoperability-test).

## How does it compare?

All of these can make a private service publicly reachable. Key differences are who operates the public endpoint, where TLS terminates, and which protocols they support.

| Tool | Good fit | Trade-off |
| --- | --- | --- |
| **tunnel** | Self-hosted SNI routing for web services, HTTPS termination on the application machine, or Go `net.Listener` integration. | You manage the public server, DNS, firewall, and access approvals. Supports SNI-routed TLS and opt-in plain HTTP, not arbitrary public TCP/UDP forwarding. |
| **[ngrok](https://ngrok.com/)** | A managed public endpoint with minimal setup and traffic-management features. | The usual hosted workflow depends on ngrok's service; features and limits vary by plan. |
| **[Cloudflare Tunnel](https://developers.cloudflare.com/cloudflare-one/networks/connectors/cloudflare-tunnel/)** (`cloudflared`) | Publishing applications through Cloudflare, with optional Cloudflare Access policies. | The standard public-hostname workflow uses Cloudflare's DNS and edge; public HTTPS terminates there. |
| **[frp](https://github.com/fatedier/frp)** | Self-hosted forwarding across a broader range of protocols, including TCP and UDP. | You operate the server and configure forwarding; its model is broader than this project's web-service and Go-listener focus. |

Choose **tunnel** if you want to own the public endpoint and keep application TLS termination on your machine. Choose a managed service if you'd rather avoid operating that endpoint, or a general-purpose forwarder if you need other protocols. TLS behavior depends on the product and mode—ngrok, for example, also supports TLS passthrough.

# tunnel

A self-hosted SNI router for publishing web services over outbound QUIC tunnels.

Bring your own server and HTTPS hostname. Your application machine connects outward—no inbound port forwarding needed there. The public server routes TLS connections by hostname (SNI), while HTTPS terminates on the application machine. Application certificate private keys stay on that machine.

```text
Browser ── HTTPS ──▶ public server ── QUIC tunnel ──▶ application machine
                    tunneld                          tunnelproxy → local service
```

Use `tunnelproxy` with an existing loopback web service, or use the Go package to give your application a `net.Listener` directly.

## Try it

You'll need Go 1.27.1 or newer, a public Linux server, and a hostname you control. This walkthrough uses:

- `tunnel.example.net` for the public server.
- `app.tunnel.example.net` for your application.
- `127.0.0.1:8080` for a web service already running on the application machine.

Replace those names with yours. Point both DNS names at the public server, and allow **UDP 7443** and **TCP 443/80** through its firewall. Let's Encrypt needs public TCP 443 for certificate validation.

### 1. Build the tools

From a checkout on each machine:

```sh
go build -o bin/ ./cmd/tunneld ./cmd/tunnelctl ./cmd/tunnelproxy
```

### 2. Start the public server

On the public server, run as root for this initial walkthrough (the default ports and directories require it):

```sh
./bin/tunneld --domain tunnel.example.net
```

This creates persistent state and a private certificate authority (CA), restricted to your domain, to secure the QUIC tunnels. This CA is separate from your application's public HTTPS certificates. Leave the daemon running. In another root shell, get the CA's fingerprint:

```sh
./bin/tunnelctl fingerprint
```

Share that fingerprint with the application operator through a trusted channel. It lets the client verify that it's connecting to your daemon.

### 3. Request access and wait

On the application machine, with your local web service running:

```sh
./bin/tunnelproxy joinserve \
  --server tunnel.example.net \
  --name app.tunnel.example.net \
  --target 127.0.0.1:8080 \
  --fingerprint YOUR_DAEMON_CA_SHA256
```

The client saves its credentials and the trusted daemon CA, requests access to the hostname, and waits for approval. Keep it running.

### 4. Approve the request

In the public server's root shell:

```sh
./bin/tunnelctl invites
./bin/tunnelctl approve INVITE_ID
```

Check the requested hostname before approving. The client will start serving automatically. Open **https://app.tunnel.example.net/**.

The default mode obtains and caches Let's Encrypt certificates on the application machine; it accepts the CA's terms of service. The first HTTPS request may take longer while a certificate is issued.

## Share a development site

Add `--basicauth` to `tunnelproxy serve` or `joinserve` to require a password before requests reach your local web service:

```sh
./bin/tunnelproxy serve \
  --server tunnel.example.net \
  --name app.tunnel.example.net \
  --target 127.0.0.1:8080 \
  --basicauth
```

The proxy prints a random password; share it with colleagues through a separate, trusted channel. Any username is accepted. The password is not saved: restarting the process generates a new one, but tunnel reconnects do not. Anyone who can read the proxy's logs can read this password too.

For credentials that survive restarts, use `--basicauth='user:password'`. To avoid storing the password in plaintext, use `--basicauth='user:$2b$…'` with a complete bcrypt hash (`$2a$`, `$2b$`, and `$2y$` are supported). Quote hashes to prevent shell expansion. A nonempty username must match exactly. Use `--basicauth=':password'` or `--basicauth=':$2b$…'` to accept any username, just like generated-password mode. `nouser:password` requires the literal username `nouser`. Passwords may contain colons. Passwords beginning with `$2` are reserved for bcrypt hashes. Use the `=` spelling for explicit values, not a separate argument.

Repeat `--basicauth` to allow multiple identities:

```sh
# Add these flags to serve or joinserve:
--basicauth='alice:alice-password' --basicauth='bob:bob-password'
```

A request is accepted if its username and password match the same entry. You can mix plaintext, bcrypt, password-only, and generated entries; repeated usernames may have different passwords. Each bare `--basicauth` generates another independent password. A password-only entry accepts any username with that entry's password, even when named entries are also configured. Commas in passwords are literal, not separators. Every entry is validated; a later valid entry does not hide an earlier invalid one. Each configured bcrypt identity adds verification work per request, so use sensible hash costs and list sizes.

Authentication is enforced locally by `tunnelproxy`, not `tunneld`. It applies to every HTTP request, including WebSocket upgrade requests. The proxy removes the accepted `Authorization` header before forwarding, so this feature cannot be combined with an application's own Authorization-based authentication on the same requests. Explicit plaintext passwords are not logged. For generated or plaintext passwords, the proxy prints a ready-to-copy bcrypt flag to reuse the password without configuring it in plaintext; passwords longer than bcrypt's 72-byte limit get a notice instead. Already-hashed credentials are not logged. Command-line values may be visible in process listings or shell history; treat the printed hashes as sensitive too, since they allow offline password guessing.

All modes accept the flag, with two important caveats:

- **`http`:** authentication works, but credentials travel unencrypted between the browser and public server. The encrypted QUIC tunnel does not protect that leg; the proxy prints a warning.
- **`raw`:** the proxy cannot inspect HTTP inside the passed-through TLS connection. It prints a warning and does **not** enforce Basic authentication or generate a password. Configure authentication on your target service instead.

### Browser sign-in with cookie authentication

Use `--cookieauth` instead of `--basicauth` to present a local sign-in page with Username and Password fields. The flags are mutually exclusive. Cookie authentication supports the same repeatable identities, plaintext passwords, bcrypt hashes, empty usernames, generated passwords, and bcrypt suggestions:

```sh
./bin/tunnelproxy serve \
  --server tunnel.example.net \
  --name app.tunnel.example.net \
  --target 127.0.0.1:8080 \
  --cookieauth='alice:password' \
  --cookieauth='bob:$2b$…' \
  --cookieauth-duration=12h
```

Use a complete bcrypt hash in place of the abbreviated example. Bare `--cookieauth` generates a password; `--cookieauth=':password'` ignores the submitted username. The default session lifetime is **24 hours**, measured from successful sign-in (not sliding). `--cookieauth-duration` accepts Go durations such as `30m` or `12h`, requires cookie authentication, and must be at least one second.

Browser HTML requests redirect to `/_tunnelproxy/auth/login`, then return to their original local URL after successful sign-in. Unauthenticated API requests, POSTs, and WebSocket upgrades receive `401`; submitted requests are not replayed. Visit `/_tunnelproxy/auth/logout` for a sign-out confirmation form. These two paths are reserved by the proxy.

Sessions use HMAC-SHA-256 signed tokens, not JWTs, with a random in-memory signing key. Restarting invalidates every session; tunnel reconnects do not. Tokens are host-bound, contain no passwords or password hashes, and expire server-side. Cookies are host-only, HttpOnly, SameSite=Lax, and Secure in HTTPS modes. The proxy strips its session and CSRF cookies before forwarding and blocks the backend from setting those reserved cookies, while preserving application cookies and Authorization headers.

Login and logout use CSRF tokens and same-origin checks. Forms have bounded sizes and password verification has a concurrency limit, but there is no per-client brute-force rate limiter. In `http` mode passwords and session cookies are exposed on the browser-to-server leg; the proxy warns and uses non-Secure cookies. In `raw` mode cookie authentication cannot be enforced and the proxy warns without generating passwords. Cookie authentication does not replace the application's own CSRF protection. Sign-out clears browser cookies but does not revoke a copied token before its expiry; restarting revokes all tokens. Expiry does not close an already-established WebSocket connection.

## Help and completion

Every tool supports `--help`; subcommands have their own help too:

```sh
./bin/tunnelproxy serve --help
./bin/tunnelctl help approve
```

For Bash, with bash-completion installed, enable completion in your current shell:

```sh
source <(./bin/tunnelproxy completion bash)
```

Use `completion bash --help` for installation guidance. Zsh, Fish, and PowerShell are supported too; each tool generates its own script.

## Dig deeper

- **Run it again:** use `tunnelproxy serve` with the same server, name, and target. Saved credentials and daemon trust are reused; no fingerprint is needed.
- **Manage access:** `tunnelctl routes` lists routes; `tunnelctl revoke IDENTITY_ID` revokes a client's access. A hostname grant also covers subdomains beneath it.
- **Choose certificates:** `--mode byo --cert ... --key ...` uses your own HTTPS certificate. `--mode private` uses a certificate issued by the daemon's CA; browsers must trust that CA too.
- **Let your service handle TLS:** `--mode raw` passes the TLS connection unchanged to your loopback service, which handles certificates and TLS termination. Routing still requires SNI; this is not arbitrary public TCP forwarding.
- **Serve plain HTTP:** `--mode http` forwards public HTTP requests by hostname, without browser-to-application TLS. The QUIC tunnel remains encrypted. Otherwise, valid public HTTP requests redirect to HTTPS.
- **Integrate with Go:** start with [`cmd/hello/main.go`](https://github.com/fasmide/tunnel/blob/main/cmd/hello/main.go), then explore [`doc.go`](https://github.com/fasmide/tunnel/blob/main/doc.go), [`ensure.go`](https://github.com/fasmide/tunnel/blob/main/ensure.go), and [`tls.go`](https://github.com/fasmide/tunnel/blob/main/tls.go).
- **Deploy as services:** explore the units and configuration examples in [`deploy/systemd/`](https://github.com/fasmide/tunnel/tree/main/deploy/systemd). Keep state directories private and persistent.

Clients reconnect automatically, but interrupted requests aren't replayed. On SIGINT/SIGTERM, `tunnelproxy` stops accepting new traffic and lets active connections finish, up to a configurable deadline.

## Explore the code

The public Go API lives at the repository root. [`cmd/`](https://github.com/fasmide/tunnel/tree/main/cmd) contains the tools; [`internal/server/`](https://github.com/fasmide/tunnel/tree/main/internal/server) handles routing and authorization; [`internal/wire/`](https://github.com/fasmide/tunnel/tree/main/internal/wire) defines the tunnel protocol.

Run `make test` for race-enabled tests, or `make vet` for static checks.

## How does it compare?

All of these can make a private service publicly reachable. Key differences are who operates the public endpoint, where TLS terminates, and which protocols they support.

| Tool | Good fit | Trade-off |
| --- | --- | --- |
| **tunnel** | Self-hosted SNI routing for web services, HTTPS termination on the application machine, or Go `net.Listener` integration. | You manage the public server, DNS, firewall, and access approvals. Supports SNI-routed TLS and opt-in plain HTTP, not arbitrary public TCP/UDP forwarding. |
| **[ngrok](https://ngrok.com/)** | A managed public endpoint with minimal setup and traffic-management features. | The usual hosted workflow depends on ngrok's service; features and limits vary by plan. |
| **[Cloudflare Tunnel](https://developers.cloudflare.com/cloudflare-one/networks/connectors/cloudflare-tunnel/)** (`cloudflared`) | Publishing applications through Cloudflare, with optional Cloudflare Access policies. | The standard public-hostname workflow uses Cloudflare's DNS and edge; public HTTPS terminates there. |
| **[frp](https://github.com/fatedier/frp)** | Self-hosted forwarding across a broader range of protocols, including TCP and UDP. | You operate the server and configure forwarding; its model is broader than this project's web-service and Go-listener focus. |

Choose **tunnel** if you want to own the public endpoint and keep application TLS termination on your machine. Choose a managed service if you'd rather avoid operating that endpoint, or a general-purpose forwarder if you need other protocols. TLS behavior depends on the product and mode—ngrok, for example, also supports TLS passthrough.

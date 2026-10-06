# tunnel

Expose a local web service at your own HTTPS hostname, using a server you control.

Your application machine connects outward over QUIC—no inbound port forwarding needed there. The public server routes traffic to it, while HTTPS terminates on the application machine. Application certificate private keys stay on that machine.

```text
Browser ── HTTPS ──▶ public server ── QUIC tunnel ──▶ application machine
                    tunneld                          tunnelproxy → local service
```

Use `tunnelproxy` with an existing loopback web service, or use the Go package to give your application a `net.Listener` directly.

## Try it

You'll need Go 1.25 or newer, a public Linux server, and a hostname you control. This walkthrough uses:

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

This creates persistent state and a private, DNS-constrained certificate authority for tunnel transport. Leave the daemon running. In another root shell, get its fingerprint:

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

The client saves its identity and transport trust, submits an access request, and waits for approval. Keep it running.

### 4. Approve the request

In the public server's root shell:

```sh
./bin/tunnelctl invites
./bin/tunnelctl approve INVITE_ID
```

Check the requested hostname before approving. The client will start serving automatically. Open **https://app.tunnel.example.net/**.

The default mode obtains and caches Let's Encrypt certificates on the application machine; it accepts the CA's terms of service. The first HTTPS request may take longer while a certificate is issued.

## Dig deeper

- **Run it again:** use `tunnelproxy serve` with the same server, name, and target. Saved identity and trust are reused; no fingerprint is needed.
- **Manage access:** `tunnelctl routes` shows routes and `tunnelctl revoke IDENTITY_ID` revokes an identity. Route grants cover the named hostname and its descendants.
- **Choose certificates:** `--mode byo --cert ... --key ...` uses your own certificate. `--mode private` uses the daemon's CA; browsers must separately trust it.
- **Own TLS yourself:** `--mode raw` passes the original TLS bytes to your loopback service. This is hostname-routed TLS, not arbitrary public TCP forwarding.
- **Opt into plaintext:** `--mode http` forwards HTTP without TLS. Otherwise, valid public HTTP requests redirect to HTTPS.
- **Integrate with Go:** start with [`cmd/hello/main.go`](https://github.com/fasmide/tunnel/blob/main/cmd/hello/main.go), then explore [`doc.go`](https://github.com/fasmide/tunnel/blob/main/doc.go), [`ensure.go`](https://github.com/fasmide/tunnel/blob/main/ensure.go), and [`tls.go`](https://github.com/fasmide/tunnel/blob/main/tls.go).
- **Deploy as services:** explore the units and configuration examples in [`deploy/systemd/`](https://github.com/fasmide/tunnel/tree/main/deploy/systemd). Keep state directories private and persistent.

Clients reconnect automatically, but interrupted requests aren't replayed. `tunnelproxy` drains active traffic on SIGINT/SIGTERM, with a configurable deadline.

## Explore the code

The public Go API lives at the repository root. [`cmd/`](https://github.com/fasmide/tunnel/tree/main/cmd) contains the tools; [`internal/server/`](https://github.com/fasmide/tunnel/tree/main/internal/server) handles routing and authorization; [`internal/wire/`](https://github.com/fasmide/tunnel/tree/main/internal/wire) defines the tunnel protocol.

Run `make test` for race-enabled tests, or `make vet` for static checks.

## How does it compare?

All of these can connect a private service to a reachable endpoint. The main difference is who runs that endpoint and how much infrastructure you want to own.

| Tool | Good fit | Trade-off |
| --- | --- | --- |
| **tunnel** | Your own server and hostname, client-side HTTPS termination, or a Go `net.Listener` integration. | You operate the public server, DNS, firewall, and access approvals. Focused on HTTP and hostname-routed TLS, not arbitrary public TCP/UDP. |
| **[ngrok](https://ngrok.com/)** | A managed public endpoint with minimal setup and traffic-management features. | The usual hosted workflow depends on ngrok's service; features and limits vary by plan. |
| **[Cloudflare Tunnel](https://developers.cloudflare.com/cloudflare-one/networks/connectors/cloudflare-tunnel/)** (`cloudflared`) | Publishing applications through Cloudflare, with optional Cloudflare Access policies. | The standard public-hostname workflow uses Cloudflare's DNS and edge; public HTTPS terminates there. |
| **[frp](https://github.com/fatedier/frp)** | Self-hosted forwarding across a broader range of protocols, including TCP and UDP. | You operate the server and configure forwarding; its model is broader than this project's web-service and Go-listener focus. |

Choose **tunnel** if you want to own the public endpoint and keep application TLS termination on your machine. Choose a managed service if you'd rather avoid operating that endpoint, or a general-purpose forwarder if you need other protocols. TLS behavior depends on the product and mode—ngrok, for example, also supports TLS passthrough.

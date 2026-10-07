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

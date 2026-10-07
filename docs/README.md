# The tunnel Go package

Import `github.com/fasmide/tunnel` to serve a Go application through an outbound QUIC tunnel using a `net.Listener`. The public API lives at the repository root; [hello](https://github.com/fasmide/tunnel/blob/main/cmd/hello/README.md) provides a runnable example.

```go
import "github.com/fasmide/tunnel"
```

## Connection and approval

Persist identity and trust using `FileStorage`. Bootstrap daemon trust with an administrator-provided fingerprint, and load transport TLS settings for subsequent connections. The daemon must approve the client's identity and hostname grants before it can serve.

`Dial` connects with an existing approved identity. `EnsureJoined` and `EnsureJoinedAndListen` support requesting access and waiting for approval, with optional event callbacks. See [hello/main.go](https://github.com/fasmide/tunnel/blob/main/cmd/hello/main.go) for credential loading, trust bootstrap, joining, and signal handling.

## Listeners

| API | Public connection handling |
| --- | --- |
| `Listen` | Local HTTPS termination with on-demand ACME certificates. |
| `ListenPrivate` | Local HTTPS termination with certificates issued by the daemon's constrained CA. |
| `ListenTLS` | Local HTTPS termination using an application-supplied `tls.Config`. |
| `ListenRaw` | Unmodified TLS bytes; the application owns TLS termination. |
| `ListenHTTP` | Plain HTTP, using one-shot public connections. |

Pass the listener to your server, such as `http.Server.Serve`. TLS listeners return connections whose handshakes have already completed. `ListenWithClientAuth` and `ListenPrivateWithClientAuth` add public client-certificate authentication; this is separate from tunnel transport authentication.

Clients reconnect automatically without replaying interrupted requests. `CloseGracefully` stops advertising and drains allocated streams within the supplied context. Applications should coordinate their own server shutdown and resource cleanup.

## Reference

- [Package documentation](https://pkg.go.dev/github.com/fasmide/tunnel)
- [Package overview](https://github.com/fasmide/tunnel/blob/main/doc.go)
- [Join workflows](https://github.com/fasmide/tunnel/blob/main/ensure.go)
- [TLS and ACME](https://github.com/fasmide/tunnel/blob/main/tls.go)
- [Private certificates](https://github.com/fasmide/tunnel/blob/main/private.go)

For server operation, see [tunneld](https://github.com/fasmide/tunnel/blob/main/cmd/tunneld/README.md); for exposing an existing service without writing Go code, see [tunnelproxy](https://github.com/fasmide/tunnel/blob/main/cmd/tunnelproxy/README.md).

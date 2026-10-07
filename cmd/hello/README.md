# hello

`hello` is a minimal HTTP application using the [tunnel Go package](https://github.com/fasmide/tunnel/blob/main/docs/README.md) directly. Unlike `tunnelproxy`, it does not forward to an existing local service: it serves HTTP on a tunnel-provided listener. See [main.go](https://github.com/fasmide/tunnel/blob/main/cmd/hello/main.go) for the example implementation.

## Build and run

From the repository root:

```sh
go build -o bin/ ./cmd/hello
```

With a running daemon and its CA fingerprint obtained through a trusted channel, submit an access request:

```sh
./bin/hello --server tunnel.example.net \
  --name app.tunnel.example.net \
  --fingerprint YOUR_DAEMON_CA_SHA256 --join
```

The join command submits the request and exits. Once the administrator approves it using [tunnelctl](https://github.com/fasmide/tunnel/blob/main/cmd/tunnelctl/README.md), start the application using its saved credentials and trust:

```sh
./bin/hello --server tunnel.example.net --name app.tunnel.example.net
```

Open `https://app.tunnel.example.net/`. Default `--mode acme` obtains public HTTPS certificates locally. `--mode private` instead uses the daemon's CA; browsers must separately trust that CA. Keys and credentials are stored in the user configuration directory under `tunnel-hello`, or a directory selected with `--state`.

Run `hello --help` for available options. For publishing an existing service rather than writing a Go application, use [tunnelproxy](https://github.com/fasmide/tunnel/blob/main/cmd/tunnelproxy/README.md).

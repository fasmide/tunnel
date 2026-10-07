# tunneld

`tunneld` is the public entry point for outbound QUIC tunnels. It routes browser connections by hostname to approved application clients without terminating their public HTTPS. Application certificate private keys remain on the application machines.

## Start a server

You need Go 1.27.1 or newer, a public Linux server, and a domain you control. Point the daemon hostname and application hostnames at the server. Allow UDP 7443 and TCP 443/80 through its firewall. Default ACME certificate validation requires public TCP 443.

From the repository root:

```sh
go build -o bin/ ./cmd/tunneld ./cmd/tunnelctl
```

For an initial walkthrough, run as root because the default ports and directories require it:

```sh
./bin/tunneld --domain tunnel.example.net
```

Without `--cert`/`--key`, the daemon creates a persistent private CA constrained to this domain for QUIC transport trust. This is separate from applications' public HTTPS certificates.

In another root shell:

```sh
./bin/tunnelctl fingerprint
```

Share the fingerprint with application operators through a trusted channel. They can then follow the [tunnelproxy guide](https://github.com/fasmide/tunnel/blob/main/cmd/tunnelproxy/README.md) to request access. Use [tunnelctl](https://github.com/fasmide/tunnel/blob/main/cmd/tunnelctl/README.md) to inspect and approve requests.

## Configuration and deployment

Defaults are `/var/lib/tunneld` for private persistent state, `/run/tunneld/admin.sock` for administration, UDP `:7443` for QUIC, TCP `:443` for public TLS, and TCP `:80` for public HTTP. Flags can override these. Keep state persistent and private, and protect the local admin socket: it grants control over identities and routes.

See [systemd deployment examples](https://github.com/fasmide/tunnel/tree/main/deploy/systemd) for service installation. Run `tunneld --help` for available options.

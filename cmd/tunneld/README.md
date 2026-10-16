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

For applications using `--mode private`, export the public CA for browser import
without stopping the daemon:

```sh
./bin/tunnelctl extract-public-ca > tunneld-ca.crt
```

This exports only the original public certificate, preserving its signed DNS/IP
constraints and excluding private keys. See the tunnelctl guide for inspection
and browser-import instructions. Default ACME application certificates do not
require importing this CA.

## Invite expiry

Pending access requests expire after **7 days**, using server-recorded timestamps.
Expired requests cannot be approved; the client must submit a fresh request.
Approval and rejection results, and expired requests, are retained for **24 hours**
for idempotent retries and then deleted. This cleanup never removes route grants
or revocations. Legacy pending requests receive a one-time seven-day grace period
when first loaded by this version.

Cleanup is durable and runs on startup, every minute while serving, and before
new submissions or decisions. `tunnelctl invites` lists only unexpired pending
requests. Invite storage is bounded to 10,000 records and an 8 MiB admission
budget, separately from the 32 MiB authorization snapshot limit. Capacity errors
are temporary: abandoned requests and retained decisions age out automatically.
These lifetimes and limits are currently server constants, not CLI flags.

Clients refresh an unresolved saved request once when the server explicitly
reports expiration. An approval wait that observes expiry returns
`ErrJoinExpired`; rerun the client (or call `EnsureJoined` again) to submit a fresh
request rather than automatically resubmitting indefinitely.

## Configuration and deployment

Defaults are `/var/lib/tunneld` for private persistent state, `/run/tunneld/admin.sock` for administration, UDP `:7443` for QUIC, TCP `:443` for public TLS, and TCP `:80` for public HTTP. Flags can override these. Keep state persistent and private, and protect the local admin socket: it grants control over identities and routes.

See the example [tunneld.service](https://github.com/fasmide/tunnel/blob/main/deploy/systemd/tunneld.service); set its transport DNS domain before starting. Run `tunneld --help` for available options.

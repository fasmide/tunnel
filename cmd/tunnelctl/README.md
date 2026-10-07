# tunnelctl

`tunnelctl` administers a running [tunneld](https://github.com/fasmide/tunnel/blob/main/cmd/tunneld/README.md): inspect join requests, approve clients, manage hostname grants, and revoke access. Most commands use the local admin Unix socket, not a public administrative endpoint.

## Build and use

From the repository root:

```sh
go build -o bin/ ./cmd/tunnelctl
```

Run on the daemon machine with permission to access its admin socket (default `/run/tunneld/admin.sock`):

```sh
./bin/tunnelctl fingerprint
./bin/tunnelctl invites
./bin/tunnelctl approve INVITE_ID
./bin/tunnelctl routes
```

Check the requested hostname before approving. Share the daemon CA fingerprint with application operators through a trusted channel so they can verify first contact.

Other access-management commands:

```sh
./bin/tunnelctl reject INVITE_ID
./bin/tunnelctl revoke IDENTITY_ID
./bin/tunnelctl set-routes IDENTITY_ID app.tunnel.example.net
```

Revocation disconnects the identity's clients. `set-routes` replaces the hostname grants; omit hostnames to clear them. A hostname grant includes descendants beneath it.

Use `--socket` for an alternate admin socket. `fingerprint --server HOST` can inspect a remote daemon's presented fingerprint, but retrieving it over that same connection does not independently authenticate the daemon.

Run `tunnelctl --help` or `tunnelctl help approve` for command-specific guidance.

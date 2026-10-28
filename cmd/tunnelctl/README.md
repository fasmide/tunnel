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

## Route status and counters

`routes` includes a `TYPE` column: `grant` denotes an approved hostname;
`listener` denotes an actively advertised descendant without its own exact
grant. An exact grant with a listener appears once, as `grant`.

`online` means an eligible listener can serve that hostname, not merely that the
identity is connected. A grant can be online through its own listener or an
ancestor listener; a descendant listener does not make its parent grant online.
This describes tunnel routing availability, not application health. With multiple
eligible sessions, age and RTT describe the oldest connected eligible session
(across HTTP/TLS pools), not an average. Offline routes without a known
route-specific offline age show `-`.

Counters belong to the **serving listener hostname**, aggregated across its
instances and HTTP/TLS pools. Descendant requests count against the selected
ancestor listener, not against the requested hostname or its grant. Thus an
online grant served by an ancestor can have zero counters of its own. `CONNS`
counts forwarded connections, not currently open connections; RX/TX count public
request/response bytes relayed through that listener.

Counters are in memory. Exact-grant counters survive listener disconnects until
daemon restart; descendant-only counters are discarded when the last listener
for that hostname is removed. Arbitrary visitor-supplied hostnames never allocate
counter entries. The JSON output includes the same row classification as `type`.

## Export the public CA for browsers

When applications use `tunnelproxy --mode private`, export the running daemon's
public CA on the daemon machine:

```sh
sudo ./bin/tunnelctl extract-public-ca > tunneld-ca.crt
openssl x509 -in tunneld-ca.crt -noout -subject -dates -fingerprint -sha256
# Inspect the critical DNS/IP constraints:
openssl x509 -in tunneld-ca.crt -noout -text
```

Use `--socket PATH` for a custom admin socket. No daemon restart or direct access
to its private state is needed. This requires generated `tunneld --domain` mode;
`--cert`/`--key` mode has no generated CA to export. The command is local-only,
rejects `--server`/`--server-name` and `--json`, and writes only a PEM certificate
to stdout, never a private key. Errors go to stderr.

Copy `tunneld-ca.crt` to your browser machine and import it as a trusted authority
for identifying websites (Firefox: Settings → Privacy & Security → Certificates
→ View Certificates → Authorities → Import; Chromium: Manage certificates,
with OS-dependent options). Compare its SHA-256 fingerprint with
`tunnelctl fingerprint` through a trusted channel before trusting it.

The exported certificate is the original signed CA, unchanged: its critical DNS
name constraint limits it to the configured domain and descendants, all IP names
are excluded, and subordinate CAs are forbidden. Extraction validates these
constraints rather than creating a new or unconstrained root. Install it only
where needed; browsers/OS trust stores may differ in how they enforce constraints
on manually installed roots. The default `acme` application mode uses public
certificates and does not need this import.

Run `tunnelctl --help` or `tunnelctl help approve` for command-specific guidance.

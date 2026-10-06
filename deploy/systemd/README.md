# Running tunneld with systemd

`tunneld.service` is a hardened system service for Linux with systemd **247+**.
Use a maintained distribution; sandbox availability also depends on its kernel
and systemd build. The supplied unit uses UDP 7443, TCP 443, and TCP 80.
It does not change public TLS passthrough or add public HTTP/3.

## Install

Build in the project checkout, then install as root (or use sudo):

```sh
go build -o /tmp/tunneld ./cmd/tunneld
go build -o /tmp/tunnelctl ./cmd/tunnelctl
sudo install -o root -g root -m 0755 /tmp/tunneld /usr/local/bin/tunneld
sudo install -o root -g root -m 0755 /tmp/tunnelctl /usr/local/bin/tunnelctl
sudo install -d -o root -g root -m 0700 /etc/tunneld
sudo install -o root -g root -m 0600 transport.crt /etc/tunneld/transport.crt
sudo install -o root -g root -m 0600 transport.key /etc/tunneld/transport.key
sudo install -o root -g root -m 0644 deploy/systemd/tunneld.service /etc/systemd/system/tunneld.service
sudo systemd-analyze verify /etc/systemd/system/tunneld.service
sudo systemctl daemon-reload
sudo systemctl enable --now tunneld.service
sudo journalctl -u tunneld.service -f
```

The transport certificate must cover the daemon hostname and be trusted by
clients. It is **not** an application HTTPS certificate. Only transport keys go
in `/etc/tunneld`; application TLS/ACME keys remain at applications.
Open the matching firewall ports and configure application DNS separately.
Installing this unit does not configure either.

Do not create a permanent `tunneld` user: `DynamicUser=yes` allocates a transient
identity. If a static user of that name already exists, systemd will use it;
use a different unused service user name if a truly dynamic identity is needed.

## Generated constrained-CA mode

The base unit retains externally supplied certificates for compatibility. To use
private PKI instead, install `generated-ca.conf.example` as a drop-in after
replacing its example domain with your transport DNS base. Do this **before**
starting the service; skip installing transport.crt/key in this mode:

```sh
sudo install -d -m 0755 /etc/systemd/system/tunneld.service.d
# Edit a copy: replace tunnel.example.com with your real transport domain.
sudo install -m 0644 transport.conf /etc/systemd/system/tunneld.service.d/transport.conf
sudo systemctl daemon-reload
sudo systemctl restart tunneld.service
sudo journalctl -u tunneld.service -n 30
```

The drop-in resets LoadCredential and ExecStart; all sandboxing stays intact.
The CA certificate/key are one atomic state value in `server/transport-ca`,
protected by StateDirectory. The fingerprint appears in the journal; clients
retrieve the CA over QUIC using BootstrapTrust (fingerprint or explicit TOFU),
then LoadTransportTLS. See the main README. Do not trust an unverified download.
To export public PEM manually, while the daemon is stopped run the following
as the state owner (not host root with an id-mapped DynamicUser directory):
`tunneld --state DIR --domain BASE --export-ca`. This command takes the exclusive
state lock and must not be run against a live daemon. It can initialize a new
CA when none exists; back up state and preserve the identity.

Generated leaves renew automatically; the 25-year CA does not. CA/domain
migration or switching between generated trust and public PKI is deliberate
client trust reprovisioning, never an automatic fallback. The existing VM
installation has not been switched by these source changes.

## State and administration

`StateDirectory=tunneld` creates and preserves private state across service
restarts. `${STATE_DIRECTORY}` is passed explicitly to the daemon's `--state`
flag; it is not an environment variable interpreted by the Go daemon itself.
With DynamicUser, systemd manages `/var/lib/private/tunneld` and exposes it as
`/var/lib/tunneld` in the service. Host ownership may vary with id-mapped mount
support; do not manually chown the directory or depend on the transient UID.

`RuntimeDirectory=tunneld` separately creates `/run/tunneld` with mode 0700;
`${RUNTIME_DIRECTORY}/admin.sock` is passed to `--socket`, and `tunneld` also
creates `${RUNTIME_DIRECTORY}/pprof.sock` for standard Go pprof HTTP handlers
on a local Unix socket. Systemd removes the runtime directory on stop, without
deleting persistent grants/CA state. `/var/run` normally points to `/run`;
prefer the canonical `/run/tunneld/admin.sock` and `/run/tunneld/pprof.sock`
paths. Both sockets are 0600. Use root for host-side admin/profile access
rather than granting broad directory/socket access. tunnelctl defaults to the
admin socket and never reads state files; `-s PATH` / `--socket PATH` overrides
it:


```sh
sudo /usr/local/bin/tunnelctl invites
sudo /usr/local/bin/tunnelctl approve INVITE_ID
# Non-interactive replacement of a conflicting owner:
sudo /usr/local/bin/tunnelctl --replace approve INVITE_ID
sudo /usr/local/bin/tunnelctl routes
sudo /usr/local/bin/tunnelctl revoke IDENTITY_ID

# Local-only profiling over a Unix socket:
curl --unix-socket /run/tunneld/pprof.sock http://localhost/debug/pprof/heap > heap.pprof
curl --unix-socket /run/tunneld/pprof.sock 'http://localhost/debug/pprof/profile?seconds=30' > cpu.pprof
go tool pprof /usr/local/bin/tunneld cpu.pprof
```

Back up the persistent state, including invite history and revocation tombstones.
For a consistent filesystem backup or migration from a manually run daemon,
stop the service first. Never edit `server/state` while the daemon is running.
`systemctl stop` does not remove state; do not use `systemctl clean --what=state`
unless intentionally destroying it.

## Credentials and rotation

`LoadCredential` lets PID 1 read root-only files and provide private read-only
copies through `${CREDENTIALS_DIRECTORY}`. The dynamic user does not need access
to `/etc/tunneld`. Do not put PEM contents in Environment/EnvironmentFile or make
keys world-readable to work around DynamicUser permissions.

Replace the certificate and matching key together while the service is stopped,
then start it; or stage a matching pair and restart during a maintenance window.
Credentials and the daemon's TLS config are loaded at startup, not hot-reloaded.
A restart disconnects existing tunnels/public traffic; clients reconnect without
replaying interrupted requests. Plain `LoadCredential` is not encrypted-at-rest
storage: root-only source files still contain the key. Hosts with systemd
credential encryption can provision `LoadCredentialEncrypted` via a drop-in
instead; key enrollment/TPM policy is operator-specific.

## Security choices

- Dynamic non-root identity, private durable state, and umask 0077.
- Only `CAP_NET_BIND_SERVICE`, in bounding and ambient sets, for TCP 80/443.
  No network-admin, raw-socket, filesystem-override, or UID-changing capabilities.
- Read-only system filesystem; state remains writable through StateDirectory.
  Home directories hidden; private temporary files/devices; kernel, clock,
  hostname and cgroup protections; restricted proc visibility.
- No privilege escalation, new namespaces, realtime scheduling, SUID/SGID files,
  or writable/executable mappings. Native syscalls only, filtered by
  `@system-service`; only Unix/IPv4/IPv6 socket families are allowed.
- Journal logging, bounded failure restarts, and a 30-second stop deadline.
  SIGTERM triggers the daemon's existing shutdown, **not** application-side
  `Client.CloseGracefully`: public traffic is interrupted on daemon stop.

Internet access and AF_UNIX are intentional: arbitrary public clients and QUIC
peers must connect, and local administration uses a Unix socket. PrivateNetwork
or a blanket IPAddressDeny would prevent normal service. No guessed MemoryMax,
CPUQuota, or file-descriptor quotas are imposed: tune these to deployment load
with a drop-in rather than letting an arbitrary cap disrupt live tunnels.

Customize with `sudo systemctl edit tunneld.service`. To change listener addresses,
reset `ExecStart` before supplying the full replacement command. If using only
unprivileged TCP ports (or disabling both public edges), also reset
`AmbientCapabilities=` and `CapabilityBoundingSet=` to empty. Do not disable
sandboxing wholesale to address a single compatibility problem.

## Validation

The unit passes `systemd-analyze verify` using a temporary root with a built
binary, and offline `systemd-analyze security` reports exposure **1.6 (OK)** on
systemd 262. That score is a configuration heuristic, not a security guarantee.
Live smoke testing also passed on an ARM64 Ubuntu 26.04 VM with systemd 259,
using Go 1.25 cross-built static binaries and a temporary private transport CA:
join/approval, public HTTPS passthrough, explicit HTTP, persisted grants across
service restart, client reconnect, and graceful client drain. The live process
had a dynamic non-root UID, NoNewPrivileges=1, seccomp filtering, and only
CAP_NET_BIND_SERVICE in its effective/bounding/ambient sets. State/socket files
were 0600; host-side nobody ownership was expected with id-mapped mounts.
The live exposure score was also 1.6. The test service was stopped and left
disabled at boot; its temporary certificate is not a production credential.

Verify on your own target host too:

```sh
sudo systemctl status tunneld.service
sudo systemd-analyze security tunneld.service
sudo journalctl -u tunneld.service --since '5 minutes ago'
```

Confirm join/admin operations, public HTTPS and HTTP routing, state persistence
across restart, and that the service cannot write outside its state directory.
Go/race tests exercise application behavior but do not run inside this sandbox.

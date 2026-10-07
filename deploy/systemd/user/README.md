# Running tunnelproxy with systemd --user

These examples run `tunnelproxy` as a **user service**, suitable for exposing a
loopback application owned by a normal login account. Unlike `tunneld`, this is
not a privileged system daemon and does not need low ports or root-managed
credentials.

Typical use cases:

- expose a local web app on `127.0.0.1:8080`
- keep the approved tunnel identity and trust state under the user's home
- restart automatically after crashes or logout (with lingering enabled)

## Install

Build and install the binary somewhere on your user PATH, for example:

```sh
go build -o ~/.local/bin/tunnelproxy ./cmd/tunnelproxy
chmod 0755 ~/.local/bin/tunnelproxy
```

Install one of the sample units below:

```sh
install -d ~/.config/systemd/user
install -m 0644 deploy/systemd/user/tunnelproxy@.service ~/.config/systemd/user/
# Optional environment-file based variant:
install -m 0644 deploy/systemd/user/tunnelproxy-env@.service ~/.config/systemd/user/
systemctl --user daemon-reload
```

If the service should survive logout, enable lingering once:

```sh
loginctl enable-linger "$USER"
```

## Templated instance unit

`tunnelproxy@.service` is parameterized by instance name. Each instance uses:

- state: `%h/.config/tunnelproxy/%i`
- environment file: `%h/.config/tunnelproxy/%i.env`

Create an environment file such as `~/.config/tunnelproxy/blog.env`:

```sh
SERVER=tunnel.example.com:7443
NAME=blog.example.com
TARGET=127.0.0.1:8080
MODE=acme
# Required on first startup: full CA SHA-256 from the administrator.
FINGERPRINT=REPLACE_WITH_VERIFIED_64_CHARACTER_LOWERCASE_HEX
# Alternatively, omit FINGERPRINT and explicitly accept first-contact risk:
# TOFU=true
# Omit TOFU entirely to disable it; TOFU=false still enables it in these units.
# SERVER_NAME=tunnel.example.com
# ACME_EMAIL=you@example.com
# SETUP_TIMEOUT=30s
# DRAIN_TIMEOUT=30s
# TARGET_TIMEOUT=10s
```

Then start it:

```sh
systemctl --user enable --now tunnelproxy@blog.service
journalctl --user -u tunnelproxy@blog.service -f
```

The first run can use `joinserve`, which requests approval and begins serving as
soon as an administrator approves the identity. Once approved, switch the unit
or environment to plain `serve` if preferred.

## Example commands

Join and serve until approved:

```sh
systemctl --user edit --full tunnelproxy@blog.service
# Set TUNNELPROXY_COMMAND=joinserve in the unit environment.
systemctl --user restart tunnelproxy@blog.service
```

Serve only after approval already exists:

```sh
systemctl --user set-environment TUNNELPROXY_COMMAND=serve
systemctl --user restart tunnelproxy@blog.service
```

## Modes

The sample units support the same `tunnelproxy` modes as the CLI:

- `acme`
- `private`
- `byo`
- `raw`
- `http`

For `byo`, set certificate paths in the environment file:

```sh
CERT=%h/.config/tunnelproxy/certs/fullchain.pem
KEY=%h/.config/tunnelproxy/certs/privkey.pem
MODE=byo
```

Those files remain user-managed; unlike the root `tunneld` service there is no
`LoadCredential=` indirection here.

## Notes

- User services cannot bind privileged local ports; that does not matter here,
  because `tunnelproxy` only dials loopback targets and makes outbound QUIC
  connections to `tunneld`.
- Keep the target bound to loopback. `tunnelproxy` intentionally rejects
  non-loopback targets.
- Use separate instances for separate names/apps when you want isolated state.
- `%h` and `%i` are expanded by systemd, not by the shell.

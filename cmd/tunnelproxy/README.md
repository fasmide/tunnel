# tunnelproxy

`tunnelproxy` exposes a loopback web service through your tunnel server. It terminates public HTTPS locally and can protect the service with Basic authentication, a browser sign-in page, or TLS client certificates.

See the [project README](https://github.com/fasmide/tunnel/blob/main/README.md) for the architecture and public-server setup.

## Build and connect

You need Go 1.27.1 or newer, a running tunnel daemon, a public hostname pointing at that server, and a loopback web service. The default ACME mode needs public TCP 443 for certificate validation; the daemon normally uses UDP 7443 for QUIC and TCP 443/80 for public traffic.

Build from the repository root:

```sh
go build -o bin/ ./cmd/tunnelproxy
```

The examples below use `tunnel.example.net` for the daemon, `app.tunnel.example.net` for the public application, and `127.0.0.1:8080` for your local service. Replace these with yours.

### Request access and serve

Get the daemon CA's SHA-256 fingerprint from the server administrator through a trusted channel. On the application machine, with the local service running:

```sh
./bin/tunnelproxy joinserve \
  --server tunnel.example.net \
  --name app.tunnel.example.net \
  --target 127.0.0.1:8080 \
  --fingerprint YOUR_DAEMON_CA_SHA256
```

The client saves its credentials and trusted daemon CA, submits the hostname request, and waits for approval. Keep it running. The administrator inspects and approves the request using `tunnelctl invites` and `tunnelctl approve INVITE_ID` on the server.

Once approved, open **https://app.tunnel.example.net/**. The default mode obtains and caches Let's Encrypt certificates on the application machine and accepts the CA's terms of service. The first HTTPS request may take longer while a certificate is issued. Public HTTPS keys remain on this machine; daemon trust is separate from browser HTTPS trust.

Feeling lucky? On first contact in an interactive terminal, you can omit `--fingerprint`: the proxy displays the daemon's fingerprint and asks `Trust this fingerprint? [y/N]`. Answer `yes` to save it and continue. Without checking that fingerprint through a separate trusted channel, you are trusting whoever answers the first connection; an attacker could impersonate the daemon. For noninteractive first-contact use, supply `--fingerprint` or explicitly opt into this risk with `--tofu`.

### Serve again or request access separately

On subsequent runs, use the saved identity and trust:

```sh
./bin/tunnelproxy serve \
  --server tunnel.example.net \
  --name app.tunnel.example.net \
  --target 127.0.0.1:8080
```

No fingerprint is needed once daemon trust has been saved. To submit a request without serving or waiting for approval, use `join`:

```sh
./bin/tunnelproxy join \
  --server tunnel.example.net \
  --name app.tunnel.example.net \
  --fingerprint YOUR_DAEMON_CA_SHA256
```

Keep the private state directory persistent. Use `--state` to select it; by default it is `$XDG_CONFIG_HOME/tunnelproxy` or `~/.config/tunnelproxy` on Linux. A hostname grant also covers its descendants; the administrator can list grants with `tunnelctl routes` and revoke access with `tunnelctl revoke IDENTITY_ID`.

## Serving modes

Choose a public mode with `--mode`:

| Mode | Behavior |
| --- | --- |
| `acme` (default) | Terminates HTTPS locally using on-demand, cached ACME certificates. |
| `private` | Terminates HTTPS locally using certificates issued by the daemon's constrained CA. Browsers must separately trust that CA. |
| `byo` | Terminates HTTPS locally using your certificate and key: `--mode byo --cert server.crt --key server.key`. |
| `raw` | Passes TLS unchanged to the loopback target, which owns certificates and TLS termination. SNI routing is still required; this is not arbitrary TCP forwarding. |
| `http` | Forwards public HTTP by hostname. The QUIC tunnel is encrypted, but the browser-to-server leg is not. |

Outside HTTP mode, valid public HTTP requests redirect to HTTPS. Targets must resolve exclusively to loopback addresses.

## Reconnection, shutdown, and deployment

Clients reconnect automatically, but interrupted requests are not replayed. On SIGINT/SIGTERM, the proxy stops accepting new traffic and lets active connections finish up to `--drain-timeout` (default 30s). `--setup-timeout` controls join/dial setup and `--target-timeout` controls local target dialing.

Keep state directories private and persistent.

## Authentication

Authentication is optional. For a public-facing site, leave the authentication flags out: visitors can reach your local service without signing in to the proxy.

To restrict visitors, choose one method for `serve` or `joinserve`: Basic, cookie, Bearer tokens, certificate fingerprints, or client CA trust. These methods are mutually exclusive. For Basic, cookie, and Bearer authentication, a bare flag or an empty value generates a secret; repeat the flag to generate more. Supplied values use the `--flag=value` spelling.

Daemon approval allows **your tunnel client** to publish a hostname; proxy authentication controls **who can visit** that hostname. Your application can still manage its own accounts and permissions—for example, which signed-in users may edit content.

### Share a development site with Basic authentication

Add `--basicauth` to `tunnelproxy serve` or `joinserve` to require a password before requests reach your local web service:

```sh
./bin/tunnelproxy serve \
  --server tunnel.example.net \
  --name app.tunnel.example.net \
  --target 127.0.0.1:8080 \
  --basicauth
```

The proxy prints a random password; share it with colleagues through a separate, trusted channel. Any username is accepted. The password is not saved: restarting the process generates a new one, but tunnel reconnects do not. Anyone who can read the proxy's logs can read this password too.

For credentials that survive restarts, use `--basicauth='user:password'`. To avoid storing the password in plaintext, use `--basicauth='user:$2b$…'` with a complete bcrypt hash (`$2a$`, `$2b$`, and `$2y$` are supported). Quote hashes to prevent shell expansion. A nonempty username must match exactly. Use `--basicauth=':password'` or `--basicauth=':$2b$…'` to accept any username, just like generated-password mode. `nouser:password` requires the literal username `nouser`. Passwords may contain colons. Passwords beginning with `$2` are reserved for bcrypt hashes. Use the `=` spelling for explicit values, not a separate argument.

Repeat `--basicauth` to allow multiple identities:

```sh
# Add these flags to serve or joinserve:
--basicauth='alice:alice-password' --basicauth='bob:bob-password'
```

A request is accepted if its username and password match the same entry. You can mix plaintext, bcrypt, password-only, and generated entries; repeated usernames may have different passwords. Each bare `--basicauth` generates another independent password. A password-only entry accepts any username with that entry's password, even when named entries are also configured. Commas in passwords are literal, not separators. Every entry is validated; a later valid entry does not hide an earlier invalid one. Each configured bcrypt identity adds verification work per request, so use sensible hash costs and list sizes.

Authentication is enforced locally by `tunnelproxy`, not `tunneld`. It applies to every HTTP request, including WebSocket upgrade requests. The proxy removes the accepted `Authorization` header before forwarding, so this feature cannot be combined with an application's own Authorization-based authentication on the same requests. Explicit plaintext passwords are not logged. For generated or plaintext passwords, the proxy prints a ready-to-copy bcrypt flag to reuse the password without configuring it in plaintext; passwords longer than bcrypt's 72-byte limit get a notice instead. Already-hashed credentials are not logged. Command-line values may be visible in process listings or shell history; treat the printed hashes as sensitive too, since they allow offline password guessing.

All modes accept the flag, with two important caveats:

- **`http`:** authentication works, but credentials travel unencrypted between the browser and public server. The encrypted QUIC tunnel does not protect that leg; the proxy prints a warning.
- **`raw`:** the proxy cannot inspect HTTP inside the passed-through TLS connection. It prints a warning and does **not** enforce Basic authentication or generate a password. Configure authentication on your target service instead.

### Browser sign-in with cookie authentication

Use `--cookieauth` instead of `--basicauth` to present a local sign-in page with Username and Password fields. The flags are mutually exclusive. Cookie authentication supports the same repeatable identities, plaintext passwords, bcrypt hashes, empty usernames, generated passwords, and bcrypt suggestions:

```sh
./bin/tunnelproxy serve \
  --server tunnel.example.net \
  --name app.tunnel.example.net \
  --target 127.0.0.1:8080 \
  --cookieauth='alice:password' \
  --cookieauth='bob:$2b$…' \
  --cookieauth-duration=12h
```

Use a complete bcrypt hash in place of the abbreviated example. Bare `--cookieauth` generates a password; `--cookieauth=':password'` ignores the submitted username. The default session lifetime is **24 hours**, measured from successful sign-in (not sliding). `--cookieauth-duration` accepts Go durations such as `30m` or `12h`, requires cookie authentication, and must be at least one second.

Browser HTML requests redirect to `/_tunnelproxy/auth/login`, then return to their original local URL after successful sign-in. Unauthenticated API requests, POSTs, and WebSocket upgrades receive `401`; submitted requests are not replayed. Visit `/_tunnelproxy/auth/logout` for a sign-out confirmation form. These two paths are reserved by the proxy.

Sessions use HMAC-SHA-256 signed tokens, not JWTs, with a random in-memory signing key. Restarting invalidates every session; tunnel reconnects do not. Tokens are host-bound, contain no passwords or password hashes, and expire server-side. Cookies are host-only, HttpOnly, SameSite=Lax, and Secure in HTTPS modes. The proxy strips its session and CSRF cookies before forwarding and blocks the backend from setting those reserved cookies, while preserving application cookies and Authorization headers.

Login and logout use CSRF tokens and same-origin checks. Forms have bounded sizes and password verification has a concurrency limit, but there is no per-client brute-force rate limiter. In `http` mode passwords and session cookies are exposed on the browser-to-server leg; the proxy warns and uses non-Secure cookies. In `raw` mode cookie authentication cannot be enforced and the proxy warns without generating passwords. Cookie authentication does not replace the application's own CSRF protection. Sign-out clears browser cookies but does not revoke a copied token before its expiry; restarting revokes all tokens. Expiry does not close an already-established WebSocket connection.

### API access with Bearer tokens

Add `--bearerauth` to `serve` or `joinserve` to generate a random token:

```sh
./bin/tunnelproxy serve \
  --server tunnel.example.net \
  --name app.tunnel.example.net \
  --target 127.0.0.1:8080 \
  --bearerauth
```

Both `--bearerauth` and `--bearerauth=` generate a fresh 256-bit token. Each
repeated empty flag generates an independent token. The proxy prints generated
tokens; they are not saved and change on restart, but not on tunnel reconnect.
Anyone with access to these logs can use them. Share tokens through a trusted
channel.

Supply tokens explicitly to keep them across restarts or allow multiple callers:

```sh
# Add these flags to serve or joinserve (replace the example values):
--bearerauth=FIRST_SECRET_TOKEN --bearerauth=SECOND_SECRET_TOKEN

curl -H "Authorization: Bearer $TOKEN" https://app.tunnel.example.net/
```

Use the `=` spelling for supplied values. Tokens are opaque, case-sensitive
shared secrets, not JWTs; there are no claims, expiry, or signature checks.
Allowed characters are letters, digits, `-._~+/`, followed by optional `=`
padding. Whitespace and commas are rejected. Use long randomly generated secrets,
not passwords or guessable strings. Supplied tokens are never logged, but command
lines may expose them through shell history and process listings. The prepared
policy stores SHA-256 digests and compares them in constant time; it does not
provide password stretching or a per-client brute-force rate limiter.

Authentication runs locally before HTTP forwarding, including WebSocket upgrades.
Missing, malformed, duplicate, or incorrect Authorization headers receive `401`
and a Bearer challenge. Tokens are accepted only in `Authorization`, never in
query parameters or cookies. The proxy strips the accepted Authorization header
before forwarding, so backend Authorization-based authentication cannot use the
same request. Bearer authentication is mutually exclusive with the other proxy
authentication methods.

Bearer authentication works in `acme`, `private`, `byo`, and `http` modes. Plain
`http` exposes tokens on the public connection and prints a warning. `raw` mode
is rejected because passthrough TLS cannot be inspected. To revoke a supplied
token, remove it and restart; existing WebSocket connections are not rechecked
per message.

## Client certificates: start with curl

A client certificate contains a public key. During TLS, the client proves that it holds the corresponding private key. The server can authorize that identity by its certificate fingerprint—no client certificate files need to be copied to the proxy.

The client certificate does **not** replace the server's HTTPS certificate. These are separate identities with separate trust decisions.

### 1. Generate a default certificate and key

On the **client's machine**, with OpenSSL installed:

```sh
openssl req -x509 -keyout client.key -out client.crt
```

That's it for the initial experiment: no algorithm, key-size, lifetime, subject, or extension overrides. `-x509` asks for a self-signed certificate; the two output options just name the files.

OpenSSL prompts for a private-key encryption password and certificate subject fields. Choose a recognizable Common Name, such as `Alice curl test`. Keep the password: curl will need it to unlock the key.

This produces:

- `client.key`: your encrypted **private key**; keep it private.
- `client.crt`: your certificate, containing the public key.

Defaults come from your OpenSSL version and configuration. They commonly produce an RSA key and a short-lived certificate; extensions can also be added by the configuration. This is a quick experiment, not a promise of identical output everywhere. If your configuration restricts the certificate to server authentication, use the explicit client-certificate recipe below instead.

### 2. Enroll its fingerprint

Still on the client's machine:

```sh
openssl x509 -in client.crt -noout -fingerprint -sha256
```

The output looks like:

```text
sha256 Fingerprint=AA:BB:…
```

Copy the **complete value after `=`**, not the label or the abbreviated example above. Share that fingerprint with the proxy operator through a trusted channel. Neither the private key nor the certificate file needs to leave the client's machine.

On the machine running the target service, add the fingerprint to your usual `serve` or `joinserve` command:

```sh
./bin/tunnelproxy serve \
  --server tunnel.example.net \
  --name app.tunnel.example.net \
  --target 127.0.0.1:8080 \
  --clientcertauth='PASTE_THE_COMPLETE_SHA256_FINGERPRINT_HERE'
```

This assumes the tunnel identity has already been approved and saved. Replace the server, public name, and target with yours. The default public mode is ACME HTTPS.

`--clientcertauth` accepts 64 hexadecimal digits, with optional colons, in either case. Repeat it to enroll more clients. It pins the **whole certificate**, not just its public key: reissuing or renewing the certificate requires enrolling its new fingerprint.

### 3. Connect with curl

Back on the client's machine:

```sh
curl --cert client.crt --key client.key https://app.tunnel.example.net/
```

Curl prompts for the private-key password when its TLS backend supports interactive unlocking. A modern OpenSSL-backed curl is a good starting point; `curl -V` shows the backend. A build that cannot unlock the encrypted key may require its backend-specific password mechanism—avoid putting passwords in shell history or process arguments.

With the enrolled certificate, you should receive the application's response. Without a client certificate, the TLS connection should fail:

```sh
curl https://app.tunnel.example.net/
```

Keep **server-certificate verification enabled**. For private mode, supply the server's trusted CA with `--cacert server-ca.pem`; that file is unrelated to the client certificate. Do not use `-k` as the normal solution to server-trust errors.

## Moving from curl to a browser

Browsers need an imported **personal identity**: the client certificate together with its private key. Importing just `client.crt` as a trusted authority does not give the browser a usable client identity.

### Make the certificate's purpose explicit

The default OpenSSL recipe is enough to demonstrate fingerprint authentication with curl under normal defaults. For browsers, use a predictable end-user certificate with client-authentication usage rather than depending on local OpenSSL configuration:

```sh
openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 \
  -keyout alice.key -out alice.crt -days 365 -subj '/CN=Alice development tunnel' \
  -addext 'basicConstraints=critical,CA:FALSE' \
  -addext 'keyUsage=critical,digitalSignature' \
  -addext 'extendedKeyUsage=clientAuth'
openssl x509 -in alice.crt -noout -fingerprint -sha256
```

Enroll this new fingerprint before testing it. You can first check it with curl using `alice.crt` and `alice.key`.

The extensions describe the intended role:

- `CA:FALSE`: an end-user certificate, not a certificate authority.
- `digitalSignature`: the key is intended for signing.
- `clientAuth`: the certificate is intended for TLS client authentication.

Our pinned verifier does not require those extensions to be explicitly present. It does enforce certificate validity and client-auth suitability; an EKU that permits only server authentication is rejected. Browsers may also use these fields when deciding which certificates to offer. Explicit extensions remove ambiguity.

**Why P-256?** Browser certificate stores, PKCS#12 importers, and TLS stacks broadly support it. Ed25519 works with Go's verifier and compatible clients, but browser/import support varies. To experiment with Ed25519, replace `-newkey ec -pkeyopt ec_paramgen_curve:P-256` with `-newkey ed25519`. Test both import and actual authentication on your intended browser; a successful import alone is not proof it can use the identity.

### Package it for import

```sh
openssl pkcs12 -export -inkey alice.key -in alice.crt \
  -out alice.p12 -name 'Alice development tunnel'
```

OpenSSL asks for the private-key password, then an export password to protect `alice.p12`. The export password is for importing the file—not a password checked by `tunnelproxy`.

The `.p12` file contains the private key. Protect it like `alice.key`; do not send it to the proxy operator. The friendly name helps identify the certificate in browser dialogs but does not restrict which websites can use it.

### Firefox

1. Open **Settings → Privacy & Security → Certificates → View Certificates** (labels vary by version).
2. Select **Your Certificates → Import**.
3. Choose `alice.p12` and enter its export password.
4. If available, set personal-certificate selection to **Ask you every time** while testing.
5. Visit your protected HTTPS URL and choose the imported identity when prompted.

Do not import the client identity under **Authorities**. If using private public-TLS mode, trusting the server CA is a separate operation.

If no chooser appears, check that the identity is under Your Certificates, has an accessible private key, is unexpired, and allows client authentication. Previously remembered choices or an existing TLS connection may suppress prompting; close connections/restart the browser when testing a different identity.

### Chrome, Edge, Safari, and other browsers

Import the `.p12` as a personal identity through the browser's certificate manager or the operating system's certificate/key store. Depending on platform and browser version, Chromium-based browsers may use OS facilities or their own management UI. Safari normally uses macOS Keychain; allow access to the imported private key when requested.

The underlying requirements are the same: certificate **plus private key**, supported algorithm, acceptable certificate usage, and trust in the server's HTTPS certificate. Import dialogs and selection behavior differ; a certificate that works in curl is not guaranteed to be offered by every browser.

## How does the browser know which certificate to use?

Importing a certificate normally does **not** assign it to a website. During the TLS handshake, the server sends a CertificateRequest containing supported signature algorithms and, optionally, acceptable CA names.

The browser filters its personal identities using their keys, certificate usage, validity, and issuer information. It may prompt you, automatically choose an identity, or reuse a remembered site-specific choice. The certificate's Common Name is a client label, not a website binding.

The two proxy policies affect selection differently:

- **Fingerprint policy:** the proxy knows only certificate hashes, so it sends no CA-name filter. Several eligible identities may appear, including ones the proxy will reject. TLS has no standard request field for a particular SHA-256 certificate fingerprint.
- **CA policy:** the proxy advertises the configured CA names, helping the browser narrow its choices to identities issued under those CAs.

One identity can work on several sites that enroll its fingerprint or trust its issuer. Separate identities with descriptive names can make selection clearer and avoid reusing the same identifying certificate across unrelated sites. The server receives the certificate and proof of key possession, **never the private key**.

## Alternative: trust a dedicated client CA

Instead of maintaining individual pins, add this to your serving command:

```sh
--clientcertauth-ca=team-client-ca.pem
```

This requires the actual CA certificate/bundle on the proxy, **not the CA private key**. Every bundle entry must be a CA certificate with certificate-signing usage. Any eligible client certificate whose chain validates to one of these trust anchors is authorized. Clients should send necessary intermediates; they need not send the root.

Prefer a dedicated client CA. The daemon's transport CA and the server's HTTPS trust roots are not automatically trusted for client authentication. For browser import of a CA-issued identity, include its intermediates in the PKCS#12 export as needed, using OpenSSL's `-certfile` option.

CA trust and fingerprint enrollment are alternative policies; they cannot be combined in one invocation.

## Modes, security, and limitations

- Client-certificate authentication is available on `serve` and `joinserve` in **acme**, **private**, and **byo** modes.
- **http** and **raw** reject it rather than silently exposing an unprotected service. In raw mode, configure client authentication on the target TLS service instead.
- `--clientcertauth`, `--clientcertauth-ca`, `--basicauth`, `--cookieauth`, and `--bearerauth` are mutually exclusive.
- Authentication happens locally before HTTP, including HTTP/2 and WebSocket upgrades. Failures produce TLS errors, not a sign-in page.
- ACME TLS-ALPN-01 validation connections are exempt and never reach the application.
- Certificate checks apply to resumed TLS connections too. Established connections are not rechecked on every HTTP request or closed merely because a certificate expires.
- There is no browser logout and no automatic CRL/OCSP revocation checking. To change authorization, update pins or the CA bundle and restart the proxy.
- No client-identity headers are injected into the backend. Client authentication does not replace application authorization or CSRF protection.

## Interoperability test

The Go test suite includes a local OpenSSL/curl interoperability test. It requires curl and OpenSSL 3+ on PATH, generates temporary identities, and checks fingerprint and CA policies with server verification enabled. It does not contact a public service.

```sh
go test ./cmd/tunnelproxy -run TestClientCertAuthCurlOpenSSL -v -count=1
```

It also runs normally under `go test ./...`.

## Help and shell completion

```sh
./bin/tunnelproxy --help
./bin/tunnelproxy serve --help
./bin/tunnelproxy joinserve --help
```

For Bash with bash-completion installed, enable completion in the current shell:

```sh
source <(./bin/tunnelproxy completion bash)
```

Use `completion bash --help` for installation guidance. Zsh, Fish, and PowerShell are supported too.

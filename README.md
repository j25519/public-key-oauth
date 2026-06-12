# Public Key Cryptography OIDC Identity Provider

A small, self-hosted OpenID Connect identity provider where your cryptographic keys *are* your login. You choose if you want your key to be your login, or if you want your key plus a password as a second factor.

The server stores only your public keys. Your private key for all three cryptographic logic methods stays in your own hands — your PGP keyring, your Nostr signer, or the secure element of a hardware security key.

## Purpose

Initially I built this simply because I love Karakeep but it didn't have any two factor authentication support yet. So I thought, this is open source self-hosted software, I'll just make it myself.

From there it took on a life of its own and became something a little different to your average "enter the code from your authenticator app" layer. Something a little more experimental and opinionated.

Most self-hosted applications bolt authentication on with a username and password, which means another secret to manage, reuse, leak, and reset. This project replaces that with something better: if you already hold a PGP key, a Nostr identity, or a YubiKey, you already have a stronger cryptographic credential that you own. The IdP turns "prove you hold this key" into a standard OIDC login that any compliant application can consume.

It was designed and battle tested against **[Karakeep](https://karakeep.app)** specifically — the configuration examples below wire it to a Karakeep instance — but it is a **standards-compliant OIDC provider** and is interoperable with anything that speaks OpenID Connect: serves a discovery document, issues authorization codes, signs RS256 ID tokens, and exposes a JWKS endpoint. If your app supports "custom OIDC provider," it supports this.

## What the code does

The entire server is a single file (`pgp-oidc-idp.mjs`, ~1,400 lines) with two halves:

1. **Standard OIDC machinery**, delegated to the certified [node-oidc-provider](https://github.com/panva/node-oidc-provider) library: discovery (`/.well-known/openid-configuration`), the authorisation endpoint, token exchange, JWKS, sessions, codes, and grants. All of its state persists in one SQLite file through a custom adapter.

2. **A custom login interaction** — the part that makes this project what it is. When an application redirects a user here to authenticate, the user proves key possession by one of three methods:

   - **PGP challenge-response.** The server generates a one-time code, embeds it in a human-readable message, signs the message with the site's admin key, and encrypts it to the user's enrolled public key. The user decrypts it in their *own* software (Kleopatra, GnuPG, OpenKeychain) — never in the browser — reads the code, and pastes it back. The decrypted message names the site and warns against entering the code anywhere else; verifying the admin signature (import the admin public key into your keyring once) is what makes that warning trustworthy.

   - **Nostr (NIP-07).** A browser extension (Nos2x, Alby, etc) signs a server-issued challenge as a kind-22242 event. The signed event carries the challenge, the **browser-asserted page origin**, and the login-attempt ID; the server verifies the Schnorr signature and all three bindings. Because the origin is what the browser actually sees — not a value echoed by the server — a phishing proxy relaying the login page produces a signature for the wrong hostname and is rejected.

   - **WebAuthn security keys.** A YubiKey or other FIDO2 hardware key, or the device's built-in authenticator backed by its secure element (TPM / Secure Enclave). Registration requires a discoverable credential, so login is usernameless: pick "Passkey," touch the key, done. Origin binding is enforced natively by the browser — a phishing site cannot even request this site's credentials — and signature counters are persisted to detect cloned authenticators.

   Optionally, a **password second factor** can be enabled (see CLI): key proof first, then an Argon2id salted and hashed password. This is currently [recommended by OWASP](https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html) as the first and best option for hashing passwords.

   In addition, the admin can choose which of these services is enabled on their instance. For example you could disable everything except PGP, or only allow Nostr and Yubikeys. The control is in your hands. When a service is disabled, it is not only switched off in the UI - the endpoints of disabled authentication options will return an HTTP 403 if a user tries to access them, thereby reducing attack surface.

**Identity model:** the OIDC `sub` claim is a randomly generated UUID — never a key fingerprint. Keys are interchangeable authenticators attached to one account, so enrolling new methods or rotating keys never changes who you are to downstream applications.

There is deliberately **no web registration**. Users are created from the CLI, and keys are enrolled through single use, expiring links the admin generates. This helps to reduce attack surface as there is no web facing admin panel. This is personal use, self-hosting hobbyist software and it is **not intended for production use.**

## Tech stack

| Component | Role |
| --- | --- |
| Node.js 22 (ESM) | Runtime; single-file server |
| [oidc-provider](https://github.com/panva/node-oidc-provider) | Certified OIDC implementation (discovery, codes, tokens, JWKS) |
| [OpenPGP.js v6](https://openpgpjs.org/) | Server-side sign+encrypt of PGP challenges; key validation at enrollment |
| [nostr-tools](https://github.com/nbd-wtf/nostr-tools) | Schnorr verification of NIP-07 auth events; npub decoding |
| [@simplewebauthn/server](https://simplewebauthn.dev/) | WebAuthn registration/authentication verification (browser side uses the native API — no client library) |
| [argon2](https://github.com/ranisalt/node-argon2) | Argon2id hashing for the optional password factor |
| better-sqlite3 | One SQLite file holds everything: users, keys, challenges, sessions, signing keys |
| Express 4 | The custom interaction and enrollment routes |
| Docker + Compose | Deployment and containterisation |
| Caddy | Reverse proxy and TLS (you can choose your own reverse proxy, but this was tested with Caddy because it's the best) |

ID tokens are signed with **RS256 (RSA-4096)** for maximum client compatibility. The login and enrollment pages are clean, modern, yet simple. Dark theme so your eyes don't burn. Dependency-free HTML — absolutely no external fonts, CSS, or scripts — allowing for a strict `default-src 'none'` CSP. Plus it won't get bogged down with random tracking scripts from third party websites that sell your data. Security *and* privacy, what's not to like?

## Installation

### Prerequisites

A Linux server with Docker Compose, a domain with two subdomains (one for the IdP, one for the application), and Caddy (or equivalent) reverse proxy and TLS.

Tested on an Ubuntu VPS. Also tested to work behind Cloudflare.

This guide will assume your IdP subdomain is `https://idp.[yourdomain.com]`. If you've set it to something else, adjust accordingly.

### 1. Admin signing key

Generate a **dedicated** signing key for the IdP — not your personal key. If the server is ever compromised you revoke a throwaway service key, not your identity.

You can optionally choose to add a passphrase to the key if you wish. You can add it to your `.env` file and it will be unlocked automatically each time it is needed.

```bash
gpg --quick-generate-key "IdP Signing <idp@yourdomain>" ed25519 sign never
gpg --export-secret-keys --armor <KEYID> > admin-private-key.asc
gpg --export --armor <KEYID> > admin-public-key.asc
```

Move the private key to the server over SFTP (SSH), or generate the key on the server since you're storing the private key on it anyway. Put the private key in the `secrets` directory of this project (as shown in the next step).

Import and trust the **public** key into the PGP software on every device you'll log in from, so decrypted challenges show a verified signature — it will work without that, but you have less security since you have no cryptographic proof the code you're decrypting actually came from the website you're using.

### 2. Directories and permissions

```bash
mkdir -p data secrets
sudo chown 1000:1000 data
mv admin-private-key.asc secrets/
sudo chown 1000:1000 secrets/admin-private-key.asc
chmod 600 secrets/admin-private-key.asc
```

The `chown`s are for the **container's** user (UID 1000, `node`), not yours — bind mounts match by raw numeric UID, and only the numbers cross the container boundary. `chmod 600` ensures only the owner of the file has permissions to read and write to it, and no one else has any access.

### 3. Configure

```bash
cp .env.example .env
```

| Variable | Meaning |
| --- | --- |
| `IDP_URL` | Public HTTPS URL of the IdP. Becomes the OIDC issuer; must match the Caddyfile site address exactly. |
| `KARAKEEP_URL` | Public HTTPS URL of the client app. Must equal Karakeep's `NEXTAUTH_URL` exactly (no trailing slash); the OAuth redirect URI is derived from it. |
| `KARAKEEP_CLIENT_SECRET` | Shared secret between IdP and client. Generate: `openssl rand -base64 32` |
| `ADMIN_PGP_PASSPHRASE` | Only if the admin key file is passphrase protected. |

The server refuses to start without the client secret — there is deliberately no default for security purposes.

You will need the client secret later on for the downstream application as well.

### 4. Reverse proxy

Add the IdP site block from the included `Caddyfile` and edit the hostname (the one value Caddy can't read from `.env`). The whole hostname is proxied — discovery, OIDC endpoints, login, and enrollment links all live under it — while the bare root path redirects human visitors to the application. The sample ships a strict CSP, possible because the pages load zero external resources.

The included `Caddyfile` template includes some secure HTTP headers that are worth adding, so check it out even if you know to configure Caddy already.

### 5. Build and run

```bash
docker compose up -d --build
```

Sanity check: `https://idp.[yourdomain.com]/.well-known/openid-configuration` returns JSON.

### 6. Create users and enroll keys

```bash
docker compose exec pgp-idp node pgp-oidc-idp.mjs add-user jamesbond james_bond@mi6.com
docker compose exec pgp-idp node pgp-oidc-idp.mjs enroll jamesbond
```

`enroll` prints a one-time link in the terminal that will expire if not used within 24 hours. The page allows you to register both a PGP public key (upload `.asc` or paste your public key) and a Nostr pubkey (paste an npub, or pull it from a NIP-07 extension in one click), or just one of the two.

If you wish to add a WebAuthn security key, this registration consumes the link by itself.

Use the email of your existing application account so account linking works (below).

### 7. Point Karakeep at it

In Karakeep's `.env` (then `docker compose up -d` to recreate — a plain restart won't reload env):

```bash
# Third party OIDC/OAuth configuration
OAUTH_WELLKNOWN_URL=https://idp.[yourdomain.com]/.well-known/openid-configuration
OAUTH_CLIENT_ID=karakeep
OAUTH_CLIENT_SECRET=<same value as KARAKEEP_CLIENT_SECRET>
OAUTH_PROVIDER_NAME=PGP
# Attach the OIDC identity to your existing Karakeep account by email
# at first login (instead of creating a duplicate):
OAUTH_ALLOW_DANGEROUS_EMAIL_ACCOUNT_LINKING=true
```

Test a full login with password auth still enabled as a safety net. Once it works:

```bash
DISABLE_PASSWORD_AUTH=true   # passwords gone entirely
OAUTH_AUTO_REDIRECT=true     # Karakeep bounces straight to the key prompt
```

If you want to create new accounts via this OAuth provider, ensure you set `DISABLE_SIGNUPS=false` otherwise they will not authenticate. You only need to do this until you login with those new accounts for the first time. After the initial login, you can change it back to `DISABLE_SIGNUPS=true` and for a self-hosted personal setup, we absolutely recommend that you do so.

The Karakeep mobile app can authenticate with an API key generated from your account settings in the Karakeep web UI, bypassing login entirely and ensuring this is fully compatible with use of the mobile app even if the login method you use is tricky on mobile.

Karakeep's container must be able to resolve and reach the IdP's public URL for the server-side token exchange; with public DNS and Caddy this just works.

**Any other OIDC client** configures the same way: discovery URL, client ID `karakeep` (or edit the `clients` array to add more), the shared secret, scopes `openid email profile`. The provider sends `sub`, `email`, `name`, and `preferred_username` in the ID token.

## CLI reference

All commands run as `docker compose exec pgp-idp node pgp-oidc-idp.mjs <command>`:

| Command | What it does |
| --- | --- |
| `add-user <username> <email>` | Create a user (no keys yet). |
| `enroll <username>` | Print a one-time key-enrollment link (24h validity, single use). Re-run any time to add or rotate keys — the stable `sub` means identity never changes. |
| `list-users` | Table of users showing which methods each has enrolled (PGP / Nostr / security key count / password set), plus current settings. |
| `delete-user <username>` | Remove a user and all their credentials. Live sessions die at next token use. Does **not** touch the matching account inside the client app. |
| `providers [enable\|disable <pgp\|nostr\|webauthn>]` | Choose which login methods are offered. All are enabled by default. Disabled providers vanish from the login and enrollment pages **and** are rejected server-side (the 403 is the control; the hidden button is cosmetics). Refuses to disable the last remaining provider. With no arguments, prints current state. Enrolled keys are kept when a provider is disabled and work again on re-enable. |
| `require-password on\|off` | Toggle the password second factor (see below). With no argument, prints current state. |
| `reset --yes` | Wipe the entire database — users, keys, passwords, sessions, cookie secrets, and the JWT signing key (all issued tokens become invalid). Recreated empty on next start. |

## Password second factor

`require-password on` turns every login into two factor authentication but in reverse: prove key possession first (any enabled method, exactly as before), then enter a password as the second factor. Off by default; turning it off restores key only login and keeps stored hashes.

Passwords are hashed with **Argon2id** (64 MiB memory, 3 iterations, 4 lanes; per-hash random salt embedded in the PHC string) — the raw password is never stored or logged. Any characters are allowed: passwords are treated as opaque strings, injection safety lives at the boundaries — JSON transport, parameterised SQL everywhere, immediate hashing, TLS. The only transformations are NFKC Unicode normalization (NIST SP 800-63B, so the same password typed through different keyboards compares equal) and an 8–256 character window.

The ordering is deliberate: passwords can never be probed anonymously, since an attacker must defeat a key before getting a single guess, and 3 wrong guesses burns the session — brute force costs a full key round-trip every three attempts.

If the password requirement is enabled after accounts exist, users without a password are prompted to create one at their next sign in, after key proof.

## Security model

**Protects against:** password reuse and credential stuffing (no passwords exist unless you add the second factor, and then they're factor two of two); theft of the server database (it contains public keys, Argon2id hashes, and hashed one-time codes); and phishing — natively for WebAuthn (browser enforced origin binding) and Nostr (browser asserted origin inside the signed event), and procedurally for PGP (the signed challenge names the site; verify the signature and read it).

**Mechanics:** PGP codes are 160-bit, hash-stored, constant-time compared, single-use, 5-minute TTL, 3 attempts. Nostr and WebAuthn challenges are single-use with the same TTL and method-tagged so challenge types are never interchangeable. Every interaction route is bound to the initiating browser via a per-interaction cookie, which also neutralises CSRF and cross-browser replay. Every authorisation attempt prompts for a key. WebAuthn signature counters detect cloned authenticators. Disabled providers are enforced server-side. Async errors return detail-free responses, never stack traces; failures are logged locally. Expired state is purged hourly.

**Does not protect against:** compromise of the server itself, which yields the JWT signing key and the admin PGP signing key (hence the dedicated throwaway admin key); a PGP user who ignores the warnings inside the decrypted challenge during a live relay attack; or loss of your own keys — there is **no recovery flow by design**. Keep offline key backups, keep more than one method enrolled, and keep one alternative auth path in the client app until you trust your setup.

**Known accepted limitations:** no rate limiting (I recommend [a Caddy rate limit plugin](https://github.com/mholt/caddy-ratelimit) or [fail2ban](https://github.com/fail2ban/fail2ban) or Cloudflare to implement it for the time being); username/pubkey existence is inferable by someone who has already started a login (cookie-gated, trivial when the user list is "you"); single static OIDC client list; CLI-only administration. This code has been repeatedly tested and reviewed and any potential vulns were patched, but **this software has not been independently audited** — treat it as a hobby project to learn about OIDC, fork it for your own use, and feel free to submit a PR if you spot anything I missed. But do NOT treat this like production ready infra. Seriously.

## Interoperability notes

Lessons encoded from wiring this to Karakeep's NextAuth, kept here for the next client you connect — in each case the IdP was spec compliant and the client supported a narrower subset:

- **ID token algorithm:** NextAuth verifies RS256 only and rejects EdDSA. The JWKS carries an RSA-4096 key and clients default to RS256. Tried using EdDSA but (at time of writing) Karakeep does not support it.
- **Token endpoint auth:** openid-client sends the secret via HTTP Basic (`client_secret_basic`); registering `client_secret_post` fails the exchange as `invalid_client`, surfaced only as a generic callback error. The secret in sent in the authorisation header.
- **Claims placement:** strict OIDC puts `email` in the userinfo response; NextAuth reads ID-token claims and errors without it. `conformIdTokenClaims: false` puts granted claims in both.
- **Debugging:** oidc-provider is silent about request-level failures unless you subscribe to its error events — this server does, so rejected exchanges appear in `docker compose logs` with an `[oidc:...]` prefix.

## Operations

- **Logs:** `docker compose logs -f pgp-idp`
- **Backup:** everything is `data/idp.sqlite` (WAL mode — snapshot with `sqlite3 data/idp.sqlite ".backup backup.sqlite"`).
- **Admin key rotation:** replace `secrets/admin-private-key.asc`, restart, re-import the new public key on client devices.
- **User key rotation:** issue a fresh `enroll` link; the stable `sub` means downstream identity is unaffected.
- **Lockout recovery:** you control the box — re-enable the client app's password auth via env var, or issue yourself a fresh enrollment link from the CLI.

## Donations

Feel free to zap a few sats if you think this is cool!

**Lightning:**

developer@cake.cash

**SegWit:**

bc1qu29u22swnv9elx879aztdntxzq6gyxvmvnyzmh

**Taproot:**

bc1pv68x4f6dfktsppwle2dcjyxmd6ademdtcc4mrw90aeyf6k2p28zstxnvxr

**Silent Payments:**

sp1qqv9ycl5aqd7qyc2jsupldvl8eadkvjpk0wx0v5l2uc63acfz7gtzqqmgvjwygj0n9wphuqw4c4ydygfkdd22mmsc5e8cw8gkktwgheddmqmjv6ay

## Roadmap

* Add rate limiting
* Add more unconventional and/or secure and privacy respecting methods of cryptographic authentication
* Add setting to use TOTP as the optional second factor instead of a password
* Being used as a sign in for some other experimental web app I make in the future

## Disclaimer of Warranty

This software is provided “as is”, without warranty of any kind, express or implied, including but not limited to warranties of merchantability, fitness for a particular purpose, and non-infringement.

This is an experimental hobby project and may contain bugs, security issues, incomplete features, or breaking changes. Use of this software is entirely at your own risk.

In no event shall the author be liable for any claim, damages, data loss, security incident, or other liability arising from the use of, inability to use, or reliance on this software.

This software and its creator are not affiliated with or endorsed by Karakeep. I'm simply an avid user and wanted to build something cool for it.
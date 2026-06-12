/**
 * pgp-oidc-idp.mjs  (v3)
 * ----------------------
 * OIDC identity provider with three key-based login methods — PGP,
 * Nostr (NIP-07), and WebAuthn passkeys — plus an optional password
 * second factor (CLI: require-password) and per-provider enable/disable
 * toggles (CLI: providers), where the
 * user's PRIVATE KEY NEVER TOUCHES THE BROWSER OR SERVER:
 *
 *   - PGP challenge-response: decrypt a one-time code in your own PGP
 *     software (Kleopatra/GnuPG) and paste it back.
 *   - Nostr (NIP-07): a browser extension (nos2x, Alby, ...) signs a
 *     server-issued challenge event; the server verifies the Schnorr
 *     signature against the enrolled pubkey.
 *
 * Identity model: `sub` is a stable random user_id (UUID), NOT a key
 * fingerprint — PGP keys and Nostr pubkeys are interchangeable
 * authenticators hanging off one account, so adding/rotating a method
 * never changes who you are to downstream apps.
 *
 * PGP login flow:
 *   1. Karakeep redirects to /auth -> oidc-provider -> /interaction/:uid
 *   2. User enters username; server returns an armored PGP message:
 *        - human-readable challenge text containing a one-time code
 *        - ENCRYPTED to the user's stored public key
 *        - SIGNED by the admin key (verify it in Kleopatra after importing
 *          the admin public key once)
 *   3. User copies the block into Kleopatra/GnuPG, decrypts it THERE,
 *      reads the code, pastes the code back into the page.
 *   4. Server hash-compares (single-use, 5 min expiry), finishes the
 *      OIDC interaction; Karakeep gets its auth code / ID token.
 *
 * Nostr login flow (NIP-07):
 *   1. Same interaction page; user clicks "Sign in with Nostr extension".
 *   2. Page asks the extension for the pubkey, fetches a random challenge
 *      for it, and asks the extension to sign a kind-22242 event carrying
 *      [challenge, origin, uid] tags.
 *   3. Server verifies: Schnorr signature, enrolled pubkey, challenge
 *      hash, origin == ISSUER, uid binding, freshness. Single-use.
 *   PGP and Nostr challenges are stored with a `method` column and each
 *   verify path filters on it, so a (non-secret) Nostr challenge can
 *   never be redeemed through the PGP code box.
 *
 * Key enrollment (registration is DISABLED — personal instance):
 *   - Admin CLI creates users and one-time enrollment links:
 *       node pgp-oidc-idp.mjs add-user james james@example.com
 *       node pgp-oidc-idp.mjs enroll james        # prints one-time URL
 *   - The /enroll/:token page lets that user upload an .asc/.gpg file or
 *     paste their armored PUBLIC key. Key policy below.
 *
 * Persistence: single SQLite file (idp.sqlite) holds users, enrollment
 * tokens, challenges, the JWT signing key, cookie secrets, and ALL
 * oidc-provider state (sessions, codes, grants) via a custom adapter.
 * Restarts no longer log anyone out or break issued tokens.
 *
 * Key policy ("future-proof but interoperable"):
 *   ACCEPT  v4 keys: Ed25519/Cv25519 (the modern GnuPG default)
 *   ACCEPT  v6 keys: RFC 9580 Ed25519/X25519 (OpenPGP.js v6 reads these)
 *   ACCEPT  RSA >= 3072 (grudgingly, for older hardware tokens)
 *   REJECT  DSA, ElGamal, RSA < 3072, expired or revoked keys,
 *           keys with no encryption-capable subkey
 *   NOTE: GnuPG/Kleopatra support for v6 keys is still settling
 *   (the RFC 9580 vs LibrePGP split), so v4 Curve25519 remains the
 *   recommendation shown on the enrollment page. Encryption uses
 *   OpenPGP.js v6 defaults, which interoperate with GnuPG 2.2+.
 *
 * Run:  node pgp-oidc-idp.mjs                 (server)
 * Deps: npm i oidc-provider openpgp better-sqlite3 express jose
 * Node: 18+ (ESM). Put it behind TLS; ISSUER must be https.
 */

import express from 'express';
import crypto from 'node:crypto';
import Database from 'better-sqlite3';
import * as openpgp from 'openpgp'; // v6
import { verifyEvent } from 'nostr-tools/pure';
import * as nip19 from 'nostr-tools/nip19';
import {
  generateRegistrationOptions, verifyRegistrationResponse,
  generateAuthenticationOptions, verifyAuthenticationResponse,
} from '@simplewebauthn/server';
import { generateKeyPair, exportJWK } from 'jose';
import Provider, { interactionPolicy } from 'oidc-provider';
import argon2 from 'argon2';

const ISSUER = process.env.ISSUER ?? 'https://idp.example.com';
const PORT = process.env.PORT ?? 3000;
const DB_PATH = process.env.DB_PATH ?? './idp.sqlite';
const CHALLENGE_TTL_MS = 5 * 60 * 1000;   // Kleopatra round-trip takes a moment
const PASSWORD_TTL_MS = 10 * 60 * 1000;   // entering a known password (manager unlock, typing)
const SET_PASSWORD_TTL_MS = 15 * 60 * 1000; // creating a password usually means a password-manager round trip
const ENROLL_TTL_MS = 24 * 60 * 60 * 1000;
// Where the "back to Karakeep" link on the error page points. Prefer the
// explicit env var; otherwise fall back to the origin of the redirect URI.
const KARAKEEP_URL = process.env.KARAKEEP_URL
  ?? (() => { try { return new URL(process.env.KARAKEEP_REDIRECT_URI).origin; } catch { return ISSUER; } })();

if (!process.env.KARAKEEP_CLIENT_SECRET)
  throw new Error('KARAKEEP_CLIENT_SECRET must be set (no insecure default).');

/* ================================================================== */
/* SQLite setup                                                        */
/* ================================================================== */

const db = new Database(DB_PATH);
db.pragma('journal_mode = WAL');
db.exec(`
  CREATE TABLE IF NOT EXISTS users (
    username     TEXT PRIMARY KEY,
    user_id      TEXT,             -- stable random id; this is the OIDC sub
    email        TEXT NOT NULL,
    fingerprint  TEXT,             -- NULL until a PGP key is enrolled
    public_key   TEXT,             -- armored PGP public key
    nostr_pubkey TEXT,             -- hex, NULL until a Nostr key is enrolled
    enrolled_at  INTEGER
  );
  CREATE TABLE IF NOT EXISTS enrollment_tokens (
    token      TEXT PRIMARY KEY,
    username   TEXT NOT NULL REFERENCES users(username),
    expires_at INTEGER NOT NULL,
    used       INTEGER DEFAULT 0
  );
  CREATE TABLE IF NOT EXISTS challenges (
    uid        TEXT PRIMARY KEY,  -- one live challenge per interaction
    username   TEXT NOT NULL,
    nonce_hash TEXT NOT NULL,
    expires_at INTEGER NOT NULL,
    attempts   INTEGER NOT NULL DEFAULT 0,
    method     TEXT NOT NULL DEFAULT 'pgp'   -- 'pgp' | 'nostr'
  );
  CREATE TABLE IF NOT EXISTS kv (                 -- jwks, cookie keys
    k TEXT PRIMARY KEY, v TEXT NOT NULL
  );
  CREATE TABLE IF NOT EXISTS webauthn_credentials (
    credential_id TEXT PRIMARY KEY,  -- base64url
    username      TEXT NOT NULL REFERENCES users(username),
    public_key    TEXT NOT NULL,     -- base64url COSE key
    counter       INTEGER NOT NULL DEFAULT 0,
    transports    TEXT,              -- JSON array
    created_at    INTEGER
  );
  CREATE TABLE IF NOT EXISTS oidc_payloads (      -- oidc-provider state
    id          TEXT NOT NULL,
    name        TEXT NOT NULL,    -- model name (Session, AccessToken, ...)
    payload     TEXT NOT NULL,
    grant_id    TEXT,
    user_code   TEXT,
    uid         TEXT,
    expires_at  INTEGER,
    consumed_at INTEGER,
    PRIMARY KEY (name, id)
  );
  CREATE INDEX IF NOT EXISTS idx_oidc_grant ON oidc_payloads(grant_id);
  CREATE INDEX IF NOT EXISTS idx_oidc_uid   ON oidc_payloads(uid);
`);

// Migration for databases created by earlier versions: ALTER TABLE ADD
// COLUMN fails harmlessly if the column already exists, then user_id is
// backfilled. NOTE FOR EXISTING DEPLOYMENTS: this changes the OIDC sub
// from PGP fingerprint to user_id, so downstream apps see a "new" user
// on next login — keep OAUTH_ALLOW_DANGEROUS_EMAIL_ACCOUNT_LINKING on in
// Karakeep so the matching email re-attaches the existing account.
const addColumn = (table, ddl) => { try { db.exec(`ALTER TABLE ${table} ADD COLUMN ${ddl}`); } catch { /* exists */ } };
addColumn('users', 'user_id TEXT');
addColumn('users', 'nostr_pubkey TEXT');
addColumn('users', 'password_hash TEXT');   // Argon2id PHC string; NULL until set
addColumn('challenges', "method TEXT NOT NULL DEFAULT 'pgp'");
for (const r of db.prepare('SELECT username FROM users WHERE user_id IS NULL').all()) {
  db.prepare('UPDATE users SET user_id = ? WHERE username = ?').run(crypto.randomUUID(), r.username);
}
// One-time cleanup: rows stored by earlier versions with NULL expires_at
// were effectively immortal (the purge job skips NULLs, the loader treats
// NULL as never-expiring). Give any such rows 24h to die.
db.prepare('UPDATE oidc_payloads SET expires_at = ? WHERE expires_at IS NULL')
  .run(Date.now() + 24 * 60 * 60 * 1000);
db.exec(`
  CREATE UNIQUE INDEX IF NOT EXISTS idx_users_user_id ON users(user_id);
  CREATE UNIQUE INDEX IF NOT EXISTS idx_users_nostr
    ON users(nostr_pubkey) WHERE nostr_pubkey IS NOT NULL;
`);

const kvGet = (k) => db.prepare('SELECT v FROM kv WHERE k = ?').get(k)?.v;
const kvSet = (k, v) =>
  db.prepare('INSERT INTO kv (k, v) VALUES (?, ?) ON CONFLICT(k) DO UPDATE SET v = excluded.v').run(k, v);
const sha256 = (s) => crypto.createHash('sha256').update(s).digest('hex');

// Which login providers are offered. All enabled by default; the admin can
// disable individual ones from the CLI (`providers disable <name>`). The
// list is enforced SERVER-SIDE on every challenge/verify/enroll route —
// hiding a button is presentation, the 403 is the actual control.
const ALL_METHODS = ['pgp', 'nostr', 'webauthn'];
function enabledMethods() {
  try {
    const v = JSON.parse(kvGet('enabled_methods') ?? 'null');
    const valid = Array.isArray(v) ? v.filter((m) => ALL_METHODS.includes(m)) : [];
    return valid.length ? valid : [...ALL_METHODS];
  } catch { return [...ALL_METHODS]; }
}
const methodEnabled = (m) => enabledMethods().includes(m);
const methodFlags = () => Object.fromEntries(ALL_METHODS.map((m) => [m, methodEnabled(m)]));

/* ================================================================== */
/* Persistent JWT signing key + cookie secrets                         */
/* ================================================================== */

async function loadOrCreateJwks() {
  const jwks = JSON.parse(kvGet('jwks') ?? '{"keys":[]}');

  // Karakeep's NextAuth hardcodes RS256 for ID token verification, so an
  // RSA key must exist. Runs as an in-place migration: an Ed25519-only
  // JWKS stored by earlier versions gets the RSA key appended (extra keys
  // in a JWKS are harmless, and removing the old one would break any
  // still-live sessions signed with it).
  if (!jwks.keys.some((k) => k.kty === 'RSA')) {
    const { privateKey } = await generateKeyPair('RS256', { modulusLength: 4096, extractable: true });
    const jwk = await exportJWK(privateKey);
    Object.assign(jwk, { alg: 'RS256', use: 'sig', kid: crypto.randomUUID() });
    jwks.keys.push(jwk);
    kvSet('jwks', JSON.stringify(jwks));
  }
  return jwks;
}

function loadOrCreateCookieKeys() {
  const stored = kvGet('cookie_keys');
  if (stored) return JSON.parse(stored);
  const keys = [crypto.randomBytes(32).toString('base64url')];
  kvSet('cookie_keys', JSON.stringify(keys));
  return keys;
}

/* ================================================================== */
/* oidc-provider SQLite adapter (sessions, codes, grants persist)      */
/* ================================================================== */

class SqliteAdapter {
  constructor(name) { this.name = name; }

  async upsert(id, payload, expiresIn) {
    db.prepare(`
      INSERT INTO oidc_payloads (id, name, payload, grant_id, user_code, uid, expires_at)
      VALUES (@id, @name, @payload, @grantId, @userCode, @uid, @expiresAt)
      ON CONFLICT(name, id) DO UPDATE SET
        payload = excluded.payload, grant_id = excluded.grant_id,
        user_code = excluded.user_code, uid = excluded.uid,
        expires_at = excluded.expires_at
    `).run({
      id, name: this.name, payload: JSON.stringify(payload),
      grantId: payload.grantId ?? null, userCode: payload.userCode ?? null,
      uid: payload.uid ?? null,
      // Never store a row without an expiry: a NULL expires_at reads as
      // "immortal" in #load, and an immortal Session row + a transient
      // cookie = silent re-login for as long as the browser stays open.
      // If oidc-provider ever omits expiresIn, cap at 24h instead.
      expiresAt: Date.now() + (expiresIn ? expiresIn * 1000 : 24 * 60 * 60 * 1000),
    });
  }

  async find(id) { return this.#load(db.prepare('SELECT * FROM oidc_payloads WHERE id = ? AND name = ?').get(id, this.name)); }
  async findByUid(uid) { return this.#load(db.prepare('SELECT * FROM oidc_payloads WHERE uid = ? AND name = ?').get(uid, this.name)); }
  async findByUserCode(c) { return this.#load(db.prepare('SELECT * FROM oidc_payloads WHERE user_code = ? AND name = ?').get(c, this.name)); }

  #load(row) {
    if (!row) return undefined;
    if (row.expires_at && row.expires_at < Date.now()) return undefined;
    const data = JSON.parse(row.payload);
    if (row.consumed_at) data.consumed = Math.floor(row.consumed_at / 1000);
    return data;
  }

  async consume(id) {
    db.prepare('UPDATE oidc_payloads SET consumed_at = ? WHERE id = ? AND name = ?')
      .run(Date.now(), id, this.name);
  }
  async destroy(id) {
    db.prepare('DELETE FROM oidc_payloads WHERE id = ? AND name = ?').run(id, this.name);
  }
  async revokeByGrantId(grantId) {
    db.prepare('DELETE FROM oidc_payloads WHERE grant_id = ?').run(grantId);
  }
}

/* ================================================================== */
/* Public key policy + validation                                      */
/* ================================================================== */

const CURVE_OK = new Set(['ed25519Legacy', 'curve25519Legacy', 'ed25519', 'x25519',
                          'curve25519', 'ed448', 'x448']); // names vary across opgp versions
const ALGO_REJECT = new Set(['dsa', 'elgamal']);

async function validateAndNormalizeKey(input) {
  // Accept armored text or raw binary (.gpg export)
  let key;
  try {
    key = await openpgp.readKey({ armoredKey: input.toString() });
  } catch {
    key = await openpgp.readKey({ binaryKey: input }); // throws -> caller handles
  }

  if (key.isPrivate()) throw new Error('That is a PRIVATE key. Only upload the public key.');

  if (await key.isRevoked()) throw new Error('Key is revoked.');
  const exp = await key.getExpirationTime();
  if (exp !== Infinity && exp !== null && exp < new Date())
    throw new Error('Key is expired.');

  // Must be able to encrypt to it (Cv25519/X25519 subkey on modern keys)
  await key.getEncryptionKey().catch(() => {
    throw new Error('Key has no encryption-capable subkey.');
  });

  // Algorithm policy across primary key + subkeys
  for (const k of [key, ...key.getSubkeys()]) {
    const { algorithm, bits, curve } = k.getAlgorithmInfo();
    const algo = String(algorithm).toLowerCase();
    if (ALGO_REJECT.has(algo)) throw new Error(`Rejected algorithm: ${algorithm}`);
    if (algo.startsWith('rsa') && (bits ?? 0) < 3072)
      throw new Error(`RSA keys must be >= 3072 bits (got ${bits}).`);
    if (curve && !CURVE_OK.has(String(curve)))
      throw new Error(`Unsupported curve: ${curve}. Use Curve25519/448.`);
  }

  return {
    fingerprint: key.getFingerprint().toUpperCase(),
    armored: key.armor(),
  };
}

/* ================================================================== */
/* Admin signing key (challenges are signed so Kleopatra shows a       */
/* verified signature; users import the admin PUBLIC key once)         */
/* ================================================================== */

import fs from 'node:fs';
const adminArmor = process.env.ADMIN_PGP_KEY
  ?? (process.env.ADMIN_PGP_KEY_FILE
        ? fs.readFileSync(process.env.ADMIN_PGP_KEY_FILE, 'utf8')
        : undefined);
if (!adminArmor) throw new Error('Set ADMIN_PGP_KEY or ADMIN_PGP_KEY_FILE');
let adminPrivateKey = await openpgp.readPrivateKey({ armoredKey: adminArmor });
if (process.env.ADMIN_PGP_PASSPHRASE) {
  adminPrivateKey = await openpgp.decryptKey({
    privateKey: adminPrivateKey,
    passphrase: process.env.ADMIN_PGP_PASSPHRASE,
  });
}

/* ================================================================== */
/* Challenge create / verify                                           */
/* ================================================================== */

async function createChallenge(uid, username) {
  const user = db.prepare('SELECT * FROM users WHERE username = ?').get(username);
  if (!user?.public_key) throw new Error('unknown user or no key enrolled');

  const code = crypto.randomBytes(20).toString('base64url'); // ~27 chars, easy to paste
  db.prepare(`
    INSERT INTO challenges (uid, username, nonce_hash, expires_at, attempts, method)
    VALUES (?, ?, ?, ?, 0, 'pgp')
    ON CONFLICT(uid) DO UPDATE SET
      username = excluded.username, nonce_hash = excluded.nonce_hash,
      expires_at = excluded.expires_at, attempts = 0, method = 'pgp'
  `).run(uid, username, sha256(code), Date.now() + CHALLENGE_TTL_MS);

  // Human-readable: the user reads this in Kleopatra, not a JSON parser.
  const text = [
    `PGP login challenge — ${ISSUER}`,
    ``,
    `User:    ${username}`,
    `Attempt: ${uid}`,
    `Issued:  ${new Date().toISOString()} (valid 5 minutes, single use)`,
    ``,
    `Enter this code ONLY at ${ISSUER}.`,
    `If any other website or person asked you for it, this is phishing — discard it.`,
    ``,
    `Code: ${code}`,
  ].join('\n');

  const userKey = await openpgp.readKey({ armoredKey: user.public_key });
  return openpgp.encrypt({
    message: await openpgp.createMessage({ text }),
    encryptionKeys: userKey,
    signingKeys: adminPrivateKey,
  });
}

function verifyChallenge(uid, submittedCode) {
  // method filter is load-bearing: Nostr challenges are NOT secrets (the
  // page sees them in plaintext), so they must never be redeemable here.
  const row = db.prepare("SELECT * FROM challenges WHERE uid = ? AND method = 'pgp'").get(uid);
  if (!row || Date.now() > row.expires_at) {
    db.prepare('DELETE FROM challenges WHERE uid = ?').run(uid);
    return null;
  }
  const a = Buffer.from(row.nonce_hash);
  const b = Buffer.from(sha256(submittedCode.trim()));
  const ok = a.length === b.length && crypto.timingSafeEqual(a, b);

  if (ok) {
    db.prepare('DELETE FROM challenges WHERE uid = ?').run(uid); // single-use
    return row.username;
  }
  // Mistyped paste shouldn't force a whole new Kleopatra round-trip:
  // allow 3 attempts. 3 guesses against a 160-bit code is still nothing.
  if (row.attempts + 1 >= 3) {
    db.prepare('DELETE FROM challenges WHERE uid = ?').run(uid);
  } else {
    db.prepare('UPDATE challenges SET attempts = attempts + 1 WHERE uid = ?').run(uid);
  }
  return null;
}

/* ================================================================== */
/* Nostr (NIP-07)                                                      */
/* ================================================================== */

function normalizeNostrPubkey(input) {
  const s = String(input ?? '').trim();
  if (/^[0-9a-f]{64}$/i.test(s)) return s.toLowerCase();
  if (s.toLowerCase().startsWith('npub1')) {
    const { type, data } = nip19.decode(s); // throws on bad checksum
    if (type !== 'npub') throw new Error('Not an npub.');
    return data;
  }
  throw new Error('Provide a 64-char hex pubkey or an npub1… string.');
}

function createNostrChallenge(uid, pubkeyHex) {
  const user = db.prepare('SELECT * FROM users WHERE nostr_pubkey = ?').get(pubkeyHex);
  if (!user) throw new Error('unknown pubkey');
  const challenge = crypto.randomBytes(32).toString('hex');
  db.prepare(`
    INSERT INTO challenges (uid, username, nonce_hash, expires_at, attempts, method)
    VALUES (?, ?, ?, ?, 0, 'nostr')
    ON CONFLICT(uid) DO UPDATE SET
      username = excluded.username, nonce_hash = excluded.nonce_hash,
      expires_at = excluded.expires_at, attempts = 0, method = 'nostr'
  `).run(uid, user.username, sha256(challenge), Date.now() + CHALLENGE_TTL_MS);
  return challenge;
}

// Verifies a signed kind-22242 auth event against the stored challenge.
// Returns the user row on success (consuming the challenge), null on any
// failure. The signature proves key possession; the tag checks bind the
// signature to THIS server, THIS login attempt, and the present moment.
function verifyNostrEvent(uid, ev) {
  const row = db.prepare("SELECT * FROM challenges WHERE uid = ? AND method = 'nostr'").get(uid);
  if (!row || Date.now() > row.expires_at) {
    db.prepare('DELETE FROM challenges WHERE uid = ?').run(uid);
    return null;
  }
  try {
    if (typeof ev !== 'object' || ev === null || ev.kind !== 22242) return null;
    const tag = (n) => ev.tags?.find((t) => Array.isArray(t) && t[0] === n)?.[1];
    if (sha256(String(tag('challenge') ?? '')) !== row.nonce_hash) return null;
    if (tag('origin') !== ISSUER) return null;             // not signed for another site
    if (tag('uid') !== uid) return null;                   // not from another login attempt
    if (Math.abs(Math.floor(Date.now() / 1000) - Number(ev.created_at)) > 600) return null;
    if (!verifyEvent(ev)) return null;                     // id hash + Schnorr signature
    const user = db.prepare('SELECT * FROM users WHERE username = ?').get(row.username);
    if (!user?.nostr_pubkey || ev.pubkey !== user.nostr_pubkey) return null;
    db.prepare('DELETE FROM challenges WHERE uid = ?').run(uid); // single-use
    return user;
  } catch {
    return null;
  }
}

/* ================================================================== */
/* WebAuthn (passkeys)                                                 */
/* ================================================================== */

const RP_ID = new URL(ISSUER).hostname;
const RP_NAME = RP_ID;

// WebAuthn challenges are stored in PLAINTEXT (in the nonce_hash column,
// despite its name): unlike the PGP code, a WebAuthn challenge is not a
// redeemable secret — it's only meaningful inside a clientDataJSON signed
// by the authenticator, and the verify functions need the original string
// to compare against. Keyed by interaction uid (login) or 'enroll:<token>'
// (registration), method-tagged like everything else.
function storeWebauthnChallenge(key, method, challenge) {
  db.prepare(`
    INSERT INTO challenges (uid, username, nonce_hash, expires_at, attempts, method)
    VALUES (?, '', ?, ?, 0, ?)
    ON CONFLICT(uid) DO UPDATE SET
      username = '', nonce_hash = excluded.nonce_hash,
      expires_at = excluded.expires_at, attempts = 0, method = excluded.method
  `).run(key, challenge, Date.now() + CHALLENGE_TTL_MS, method);
}

function takeWebauthnChallenge(key, method) {
  const row = db.prepare('SELECT * FROM challenges WHERE uid = ? AND method = ?').get(key, method);
  db.prepare('DELETE FROM challenges WHERE uid = ?').run(key); // single-use, success or not
  if (!row || Date.now() > row.expires_at) return null;
  return row.nonce_hash; // the plaintext challenge
}

/* ================================================================== */
/* CLI: add-user / enroll  (web registration is intentionally absent)  */
/* ================================================================== */

const [, , cmd, ...args] = process.argv;
if (cmd === 'add-user') {
  const [username, email] = args;
  db.prepare('INSERT INTO users (username, user_id, email) VALUES (?, ?, ?)')
    .run(username, crypto.randomUUID(), email);
  console.log(`User ${username} created. Now run: node pgp-oidc-idp.mjs enroll ${username}`);
  process.exit(0);
}
if (cmd === 'enroll') {
  const [username] = args;
  if (!db.prepare('SELECT 1 FROM users WHERE username = ?').get(username)) {
    console.error('No such user. add-user first.'); process.exit(1);
  }
  const token = crypto.randomBytes(32).toString('base64url');
  db.prepare('INSERT INTO enrollment_tokens (token, username, expires_at) VALUES (?, ?, ?)')
    .run(token, username, Date.now() + ENROLL_TTL_MS);
  console.log(`One-time key enrollment link (24h):\n${ISSUER}/enroll/${token}`);
  process.exit(0);
}
if (cmd === 'list-users') {
  const rows = db.prepare(`
    SELECT username, email, user_id,
      CASE WHEN public_key   IS NOT NULL THEN 'yes' ELSE '-' END AS pgp,
      CASE WHEN nostr_pubkey IS NOT NULL THEN 'yes' ELSE '-' END AS nostr,
      (SELECT COUNT(*) FROM webauthn_credentials w WHERE w.username = users.username) AS passkeys,
      CASE WHEN password_hash IS NOT NULL THEN 'set' ELSE '-' END AS password
    FROM users ORDER BY username
  `).all();
  if (!rows.length) console.log('No users.');
  else console.table(rows);
  console.log('Password second factor:', kvGet('require_password') === '1' ? 'ON' : 'OFF');
  process.exit(0);
}
if (cmd === 'delete-user') {
  const [username] = args;
  if (!username) { console.error('Usage: delete-user <username>'); process.exit(1); }
  db.prepare('DELETE FROM webauthn_credentials WHERE username = ?').run(username);
  db.prepare('DELETE FROM enrollment_tokens WHERE username = ?').run(username);
  db.prepare('DELETE FROM challenges WHERE username = ?').run(username);
  const info = db.prepare('DELETE FROM users WHERE username = ?').run(username);
  if (!info.changes) { console.error('No such user.'); process.exit(1); }
  console.log(`Deleted ${username} and their credentials. Any live OIDC sessions die at next
token use (the sub no longer resolves). NOTE: this does NOT touch the matching
account inside Karakeep — remove that from Karakeep's admin panel if needed.`);
  process.exit(0);
}
if (cmd === 'reset') {
  if (args[0] !== '--yes') {
    console.error(`This wipes EVERYTHING: users, enrolled keys, passwords, sessions, cookie
secrets, and the JWT signing key (all existing tokens become invalid). The
database is recreated empty on next start.
To confirm: node pgp-oidc-idp.mjs reset --yes`);
    process.exit(1);
  }
  db.close();
  for (const suffix of ['', '-wal', '-shm']) fs.rmSync(DB_PATH + suffix, { force: true });
  console.log('Database wiped. Start the server (or just restart the container) to recreate it.');
  process.exit(0);
}
if (cmd === 'require-password') {
  const [state] = args;
  if (state === 'on') {
    kvSet('require_password', '1');
    console.log(`Password second factor: ON.
Users sign in with their key as usual, then enter their password. Users with
no password yet will be asked to CREATE one at their next sign-in (after key
proof) — until they do, their key alone still signs them in, so log in
promptly after enabling this.`);
  } else if (state === 'off') {
    kvSet('require_password', '0');
    console.log('Password second factor: OFF. Key-only login restored. (Stored password hashes are kept.)');
  } else {
    console.log('Password second factor is currently:',
      kvGet('require_password') === '1' ? 'ON' : 'OFF');
    console.log('Usage: require-password on|off');
  }
  process.exit(0);
}
if (cmd === 'providers') {
  const [action, name] = args;
  const current = enabledMethods();
  if (action === 'enable' || action === 'disable') {
    if (!ALL_METHODS.includes(name)) {
      console.error(`Unknown provider '${name ?? ''}'. Valid: ${ALL_METHODS.join(', ')}`);
      process.exit(1);
    }
    let next;
    if (action === 'enable') {
      next = [...new Set([...current, name])];
    } else {
      next = current.filter((m) => m !== name);
      if (!next.length) {
        console.error('Refusing: that would disable the last remaining provider, locking everyone out.');
        process.exit(1);
      }
    }
    kvSet('enabled_methods', JSON.stringify(next));
    console.log(`Provider '${name}' ${action}d. Enrolled keys are kept either way;
disabled providers reject both sign-in and enrollment until re-enabled.`);
  } else if (action) {
    console.error('Usage: providers [enable|disable <pgp|nostr|webauthn>]');
    process.exit(1);
  }
  const final = enabledMethods();
  for (const m of ALL_METHODS) console.log(`${m.padEnd(8)} ${final.includes(m) ? 'enabled' : 'DISABLED'}`);
  process.exit(0);
}

/* ================================================================== */
/* OIDC provider                                                       */
/* ================================================================== */

const oidc = new Provider(ISSUER, {
  adapter: SqliteAdapter,
  jwks: await loadOrCreateJwks(),
  cookies: {
    keys: loadOrCreateCookieKeys(),
    // CRITICAL: 'short' is the maxAge of the transient cookies that carry a
    // browser through the auth handshake (_interaction, _state). These MUST
    // outlive the /auth -> interaction page -> redirect round trip. They are
    // unrelated to the SSO Session ttl below — keeping Session short stops
    // silent re-login, but if the handshake cookie is also short the flow
    // can't complete and oidc throws "interaction session not found".
    short: { maxAge: 60 * 60 * 1000 },        // 1h, matches Interaction ttl
    long: { maxAge: 14 * 24 * 60 * 60 * 1000 },
  },

  clients: [{
    client_id: 'karakeep',
    client_secret: process.env.KARAKEEP_CLIENT_SECRET, // presence enforced at startup
    redirect_uris: [process.env.KARAKEEP_REDIRECT_URI ?? 'https://karakeep.example.com/api/auth/callback/custom'],
    grant_types: ['authorization_code'],
    response_types: ['code'],
    // openid-client (NextAuth's OAuth library) sends the secret via HTTP
    // Basic auth by default; registering 'post' here makes oidc-provider
    // reject the token exchange with invalid_client.
    token_endpoint_auth_method: 'client_secret_basic',
    // No id_token_signed_response_alg override: the default is RS256,
    // which is the only alg Karakeep's NextAuth will verify (it rejects
    // EdDSA with "unexpected JWT alg received"). The JWKS contains an
    // RSA key specifically for this.
  }],

  async findAccount(_ctx, sub) {
    const user = db.prepare('SELECT * FROM users WHERE user_id = ?').get(sub);
    if (!user) return undefined;
    return {
      accountId: sub,
      async claims() {
        return { sub, email: user.email, name: user.username, preferred_username: user.username };
      },
    };
  },

  claims: { openid: ['sub'], email: ['email'], profile: ['name', 'preferred_username'] },
  // Lifetimes (seconds). Silent SSO is prevented by login.remember=false in
  // finishLogin (no persistent session cookie), NOT by a short Session ttl —
  // so Session only needs to outlive the slowest in-flight login. It MUST
  // exceed the longest password window (SET_PASSWORD_TTL_MS, 15 min) or the
  // session expires mid-flow and interactionResult fails. 20 min gives slack.
  // NOTE: never set Session to 0 — a falsy expiresIn would be miscaptured.
  ttl: {
    Session: 20 * 60,
    Interaction: 60 * 60,   // generous window for the Kleopatra round trip
    Grant: 60 * 60,
    AccessToken: 60 * 60,
    IdToken: 60 * 60,
  },
  // Per strict OIDC conformance, claims like email live in the userinfo
  // response, not the ID token — but Karakeep's NextAuth builds the user
  // profile from ID token claims and fails with "Provider didn't provide
  // an email" if it's not in there. This puts granted claims in both.
  conformIdTokenClaims: false,
  interactions: {
    // No silent SSO, done correctly this time. The earlier attempt failed
    // in both directions, and the difference is instructive:
    //   - An UNCONDITIONAL "request prompt" check is never satisfied — not
    //     even by the login just completed — so resumption dies with
    //     "interaction session not found".
    //   - NO check at all means an existing IdP session silently
    //     re-authenticates the next login (Karakeep's logout never calls
    //     our end-session endpoint, so that session lingers).
    // The correct middle: prompt UNLESS this very request carries a fresh
    // login result (ctx.oidc.result.login is populated during resumption
    // of the interaction we just finished). A pre-existing session never
    // satisfies it; the login you just performed always does.
    policy: (() => {
      const { Check } = interactionPolicy;
      const policy = interactionPolicy.base();
      policy.get('login').checks.add(new Check(
        'no_silent_sso',
        'every sign-in must prove key possession',
        (ctx) => (ctx.oidc.result?.login ? Check.NO_NEED_TO_PROMPT : Check.REQUEST_PROMPT),
      ));
      return policy;
    })(),
    url: (_ctx, i) => `/interaction/${i.uid}`,
  },
  features: { devInteractions: { enabled: false } },
  // Replace oidc-provider's default (ugly, detail-leaking) error page. Most
  // errors reaching here are transient — an expired or already-used sign-in
  // link — so the page explains that plainly and offers a way back to
  // Karakeep rather than echoing raw OIDC error codes at the user.
  async renderError(ctx, _out, _error) {
    ctx.type = 'html';
    ctx.body = pageShell('Sign-in problem', `
      <h1>Sign-in couldn't continue</h1>
      <p class="sub">This usually means the sign-in link expired or was
      already used. Start again from the app.</p>
      <div class="row"><a href="${escapeHtml(KARAKEEP_URL)}"><button>Back to Karakeep</button></a></div>`);
  },
});
oidc.proxy = true;

// oidc-provider is silent about request-level failures unless you listen
// for them — without this, a rejected token exchange logs nothing at all.
for (const ev of [
  'server_error', 'authorization.error', 'grant.error',
  'interaction.error', 'userinfo.error', 'end_session.error', 'jwks.error',
]) {
  oidc.on(ev, (ctx, err) => console.error(`[oidc:${ev}]`, err?.message, err?.error_description ?? ''));
}

/* ================================================================== */
/* HTTP routes                                                         */
/* ================================================================== */

const app = express();
app.use(express.json({ limit: '64kb' })); // armored keys fit comfortably

// CRITICAL: Express 4 does not catch async errors. interactionDetails()
// THROWS on an unknown/expired uid, and an unhandled rejection kills the
// Node process — i.e. `curl /interaction/garbage` would crash the IdP.
// Every async handler is wrapped, and a terminal error middleware turns
// failures into a detail-free 400.
const ah = (fn) => (req, res, next) => Promise.resolve(fn(req, res, next)).catch(next);

// Purge expired rows hourly so abandoned challenges, stale enrollment
// links, and dead oidc-provider state (anyone can create interactions by
// hitting /auth unauthenticated) don't grow the DB forever.
setInterval(() => {
  const now = Date.now();
  db.prepare('DELETE FROM challenges WHERE expires_at < ?').run(now);
  db.prepare('DELETE FROM enrollment_tokens WHERE expires_at < ? OR used = 1').run(now);
  db.prepare('DELETE FROM oidc_payloads WHERE expires_at IS NOT NULL AND expires_at < ?').run(now);
}, 60 * 60 * 1000).unref();

// Minimal HTML escaping for anything interpolated into pages.
const escapeHtml = (s) => String(s).replace(/[&<>"']/g, (c) =>
  ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));

/* ---- key enrollment (one-time token from the CLI) ---- */

function validEnrollToken(token) {
  const row = db.prepare('SELECT * FROM enrollment_tokens WHERE token = ?').get(token);
  if (!row || row.used || Date.now() > row.expires_at) return null;
  return row;
}

app.get('/enroll/:token', (req, res) => {
  const row = validEnrollToken(req.params.token);
  if (!row) return res.status(404).type('html').send('<p>Enrollment link is invalid or expired.</p>');
  res.type('html').send(enrollPage(row.username, methodFlags()));
});

app.post('/enroll/:token', ah(async (req, res) => {
  const row = validEnrollToken(req.params.token);
  if (!row) return res.status(404).json({ error: 'Invalid or expired link.' });
  const { publicKey, nostrPubkey } = req.body ?? {};
  if (publicKey && !methodEnabled('pgp'))
    return res.status(403).json({ error: 'PGP enrollment is disabled.' });
  if (nostrPubkey && !methodEnabled('nostr'))
    return res.status(403).json({ error: 'Nostr enrollment is disabled.' });
  if (!publicKey && !nostrPubkey)
    return res.status(400).json({ error: 'Provide a PGP public key, a Nostr pubkey, or both.' });
  try {
    const enrolled = {};
    // Validate EVERYTHING before writing ANYTHING, so a bad npub can't
    // leave a half-applied enrollment behind.
    const pgp = publicKey ? await validateAndNormalizeKey(publicKey) : null;
    const nostrHex = nostrPubkey ? normalizeNostrPubkey(nostrPubkey) : null;
    if (nostrHex) {
      const taken = db.prepare('SELECT 1 FROM users WHERE nostr_pubkey = ? AND username != ?')
        .get(nostrHex, row.username);
      if (taken) throw new Error('That Nostr key is already enrolled to another user.');
    }

    if (pgp) {
      db.prepare('UPDATE users SET fingerprint = ?, public_key = ?, enrolled_at = ? WHERE username = ?')
        .run(pgp.fingerprint, pgp.armored, Date.now(), row.username);
      enrolled.pgpFingerprint = pgp.fingerprint;
    }
    if (nostrHex) {
      db.prepare('UPDATE users SET nostr_pubkey = ? WHERE username = ?').run(nostrHex, row.username);
      enrolled.nostrPubkey = nostrHex;
    }
    db.prepare('UPDATE enrollment_tokens SET used = 1 WHERE token = ?').run(req.params.token);
    res.json({ ok: true, ...enrolled });
  } catch (e) {
    res.status(400).json({ error: e.message ?? 'Rejected.' });
  }
}));

/* ---- WebAuthn passkey registration (consumes the enrollment token) ---- */

app.post('/enroll/:token/webauthn/options', ah(async (req, res) => {
  if (!methodEnabled('webauthn')) return res.status(403).json({ error: 'Passkey enrollment is disabled.' });
  const row = validEnrollToken(req.params.token);
  if (!row) return res.status(404).json({ error: 'Invalid or expired link.' });
  const user = db.prepare('SELECT * FROM users WHERE username = ?').get(row.username);
  const existing = db.prepare(
    'SELECT credential_id, transports FROM webauthn_credentials WHERE username = ?').all(row.username);

  const options = await generateRegistrationOptions({
    rpName: RP_NAME,
    rpID: RP_ID,
    userID: new Uint8Array(Buffer.from(user.user_id)),
    userName: row.username,
    attestationType: 'none',
    // residentKey required => discoverable credential => usernameless login
    authenticatorSelection: { residentKey: 'required', userVerification: 'preferred' },
    excludeCredentials: existing.map((c) => ({
      id: c.credential_id, transports: JSON.parse(c.transports ?? '[]'),
    })),
  });
  storeWebauthnChallenge('enroll:' + req.params.token, 'webauthn-reg', options.challenge);
  res.json(options);
}));

app.post('/enroll/:token/webauthn/verify', ah(async (req, res) => {
  if (!methodEnabled('webauthn')) return res.status(403).json({ error: 'Passkey enrollment is disabled.' });
  const row = validEnrollToken(req.params.token);
  if (!row) return res.status(404).json({ error: 'Invalid or expired link.' });
  const expectedChallenge = takeWebauthnChallenge('enroll:' + req.params.token, 'webauthn-reg');
  if (!expectedChallenge) return res.status(400).json({ error: 'Challenge expired — try again.' });
  try {
    const { verified, registrationInfo } = await verifyRegistrationResponse({
      response: req.body,
      expectedChallenge,
      expectedOrigin: ISSUER,
      expectedRPID: RP_ID,
    });
    if (!verified) throw new Error('not verified');
    const cred = registrationInfo.credential;
    db.prepare(`
      INSERT INTO webauthn_credentials
        (credential_id, username, public_key, counter, transports, created_at)
      VALUES (?, ?, ?, ?, ?, ?)
    `).run(cred.id, row.username, Buffer.from(cred.publicKey).toString('base64url'),
           cred.counter, JSON.stringify(cred.transports ?? []), Date.now());
    db.prepare('UPDATE enrollment_tokens SET used = 1 WHERE token = ?').run(req.params.token);
    res.json({ ok: true });
  } catch {
    res.status(400).json({ error: 'Passkey registration failed.' });
  }
}));

/* ---- login interaction ---- */

app.get('/interaction/:uid', ah(async (req, res) => {
  await oidc.interactionDetails(req, res); // throws if unknown/expired
  res.type('html').send(loginPage(req.params.uid, methodFlags()));
}));

app.post('/interaction/:uid/challenge', ah(async (req, res) => {
  if (!methodEnabled('pgp')) return res.status(403).json({ error: 'PGP sign-in is disabled.' });
  try {
    await oidc.interactionDetails(req, res);
    const armored = await createChallenge(req.params.uid, String(req.body.username ?? ''));
    res.json({ challenge: armored });
  } catch {
    res.status(400).json({ error: 'Could not create a challenge.' }); // vague on purpose
  }
}));

app.post('/interaction/:uid/verify', ah(async (req, res) => {
  if (!methodEnabled('pgp')) return res.status(403).json({ error: 'PGP sign-in is disabled.' });
  const details = await oidc.interactionDetails(req, res);
  const username = verifyChallenge(req.params.uid, String(req.body.code ?? ''));
  if (!username) return res.status(401).json({ error: 'Code rejected (wrong, expired, or already used).' });
  const user = db.prepare('SELECT * FROM users WHERE username = ?').get(username);
  return completeKeyAuth(req, res, details, user);
}));

/* ---- Nostr (NIP-07) login ---- */

app.post('/interaction/:uid/nostr/challenge', ah(async (req, res) => {
  if (!methodEnabled('nostr')) return res.status(403).json({ error: 'Nostr sign-in is disabled.' });
  try {
    await oidc.interactionDetails(req, res);
    const pubkey = normalizeNostrPubkey(req.body.pubkey);
    const challenge = createNostrChallenge(req.params.uid, pubkey);
    // Deliberately NOT returning ISSUER/origin here: the client must sign
    // location.origin as seen by the browser, or the anti-phishing check
    // becomes circular.
    res.json({ challenge });
  } catch {
    res.status(400).json({ error: 'Could not create a challenge.' }); // vague on purpose
  }
}));

app.post('/interaction/:uid/nostr/verify', ah(async (req, res) => {
  if (!methodEnabled('nostr')) return res.status(403).json({ error: 'Nostr sign-in is disabled.' });
  const details = await oidc.interactionDetails(req, res);
  const user = verifyNostrEvent(req.params.uid, req.body.event);
  if (!user) return res.status(401).json({ error: 'Signature rejected (invalid, expired, or already used).' });
  return completeKeyAuth(req, res, details, user);
}));

/* ---- WebAuthn (passkey) login ---- */

app.post('/interaction/:uid/webauthn/options', ah(async (req, res) => {
  if (!methodEnabled('webauthn')) return res.status(403).json({ error: 'Passkey sign-in is disabled.' });
  try {
    await oidc.interactionDetails(req, res);
    // No allowCredentials: discoverable credentials mean the browser offers
    // whatever passkeys it holds for this RP — usernameless by design.
    const options = await generateAuthenticationOptions({ rpID: RP_ID, userVerification: 'preferred' });
    storeWebauthnChallenge(req.params.uid, 'webauthn', options.challenge);
    res.json(options);
  } catch {
    res.status(400).json({ error: 'Could not create a challenge.' });
  }
}));

app.post('/interaction/:uid/webauthn/verify', ah(async (req, res) => {
  if (!methodEnabled('webauthn')) return res.status(403).json({ error: 'Passkey sign-in is disabled.' });
  const details = await oidc.interactionDetails(req, res);
  const expectedChallenge = takeWebauthnChallenge(req.params.uid, 'webauthn');
  if (!expectedChallenge) return res.status(401).json({ error: 'Challenge expired — try again.' });

  const cred = db.prepare('SELECT * FROM webauthn_credentials WHERE credential_id = ?')
    .get(String(req.body?.id ?? ''));
  if (!cred) return res.status(401).json({ error: 'Unknown passkey.' });

  try {
    const { verified, authenticationInfo } = await verifyAuthenticationResponse({
      response: req.body,
      expectedChallenge,
      expectedOrigin: ISSUER,
      expectedRPID: RP_ID,
      credential: {
        id: cred.credential_id,
        publicKey: new Uint8Array(Buffer.from(cred.public_key, 'base64url')),
        counter: cred.counter,
        transports: JSON.parse(cred.transports ?? '[]'),
      },
    });
    if (!verified) throw new Error('not verified');
    // Signature counter: a cloned authenticator replaying an old counter
    // value fails verification above; persist the new one.
    db.prepare('UPDATE webauthn_credentials SET counter = ? WHERE credential_id = ?')
      .run(authenticationInfo.newCounter, cred.credential_id);

    const user = db.prepare('SELECT * FROM users WHERE username = ?').get(cred.username);
    return completeKeyAuth(req, res, details, user);
  } catch {
    return res.status(401).json({ error: 'Passkey rejected.' });
  }
}));

/* ---- password second factor (active only when require-password is on) ---- */

// Argon2id, explicit parameters (OWASP-recommended class): 64 MiB memory,
// 3 iterations, 4 lanes. The library generates a fresh random salt per
// hash and stores it inside the PHC-format string alongside the params.
const ARGON2_OPTS = { type: argon2.argon2id, memoryCost: 65536, timeCost: 3, parallelism: 4 };

// Passwords are treated as OPAQUE strings — no characters are stripped,
// escaped, or rewritten, because mutating a password weakens it. Safety
// against injection lives at the boundaries instead: JSON transport,
// parameterised SQL everywhere, immediate hashing (the raw password is
// never stored or logged), and textContent-only DOM writes client-side.
// The only transformations: NFKC Unicode normalization (NIST SP 800-63B —
// so the "same" password typed via different keyboards/IMEs compares
// equal) and a length window (>= 8 chars; <= 256 to bound Argon2 work).
function normalizePassword(input) {
  if (typeof input !== 'string') return null;
  const p = input.normalize('NFKC');
  if (p.length < 8 || p.length > 256) return null;
  return p;
}

// Key proof succeeded for this interaction. If the password factor is off,
// finish the login as before; if on, park the login (method-tagged row in
// the challenges table) and tell the page to ask for the password.
// Creating a NEW password gets a longer window than entering a known one —
// generating and saving a password in a manager takes real minutes.
async function completeKeyAuth(req, res, details, user) {
  if (kvGet('require_password') !== '1') return finishLogin(req, res, details, user.user_id);
  const ttl = user.password_hash ? PASSWORD_TTL_MS : SET_PASSWORD_TTL_MS;
  db.prepare(`
    INSERT INTO challenges (uid, username, nonce_hash, expires_at, attempts, method)
    VALUES (?, ?, '', ?, 0, 'password-pending')
    ON CONFLICT(uid) DO UPDATE SET
      username = excluded.username, nonce_hash = '',
      expires_at = excluded.expires_at, attempts = 0, method = 'password-pending'
  `).run(req.params.uid, user.username, Date.now() + ttl);
  res.json({ passwordRequired: true, setPassword: !user.password_hash });
}

app.post('/interaction/:uid/password', ah(async (req, res) => {
  const details = await oidc.interactionDetails(req, res);
  const pending = db.prepare(
    "SELECT * FROM challenges WHERE uid = ? AND method = 'password-pending'").get(req.params.uid);
  if (!pending || Date.now() > pending.expires_at) {
    db.prepare('DELETE FROM challenges WHERE uid = ?').run(req.params.uid);
    return res.status(401).json({ error: 'This step expired — start the sign-in again.' });
  }
  const user = db.prepare('SELECT * FROM users WHERE username = ?').get(pending.username);
  if (!user) return res.status(401).json({ error: 'This step expired — start the sign-in again.' });
  const password = normalizePassword(req.body?.password);
  if (!password) return res.status(400).json({ error: 'Password must be 8–256 characters.' });

  if (!user.password_hash) {
    // First sign-in since the factor was enabled: key proof for THIS
    // attempt already succeeded, so the keyholder sets their password now.
    const hash = await argon2.hash(password, ARGON2_OPTS);
    db.prepare('UPDATE users SET password_hash = ? WHERE username = ?').run(hash, user.username);
  } else {
    const ok = await argon2.verify(user.password_hash, password).catch(() => false);
    if (!ok) {
      // 3 attempts per key proof — exceeding that burns the pending login,
      // so password brute force costs a full key round-trip every 3 tries.
      if (pending.attempts + 1 >= 3) db.prepare('DELETE FROM challenges WHERE uid = ?').run(req.params.uid);
      else db.prepare('UPDATE challenges SET attempts = attempts + 1 WHERE uid = ?').run(req.params.uid);
      return res.status(401).json({ error: 'Wrong password.' });
    }
  }
  db.prepare('DELETE FROM challenges WHERE uid = ?').run(req.params.uid); // consume
  return finishLogin(req, res, details, user.user_id);
}));

// Shared completion for every method (and the password step): grant +
// interactionResult.
async function finishLogin(req, res, details, accountId) {
  const grant = new oidc.Grant({ accountId, clientId: details.params.client_id });
  grant.addOIDCScope('openid email profile');
  const grantId = await grant.save();

  // interactionResult (not interactionFinished): we return the redirect as
  // JSON so the fetch()-based page can navigate itself.
  // remember:false makes the session cookie transient (browser-session
  // scoped) — note this alone does NOT stop silent SSO within the same
  // browser session; the no_silent_sso policy check does that. This is
  // just defense in depth so no persistent cookie outlives the browser.
  const redirectTo = await oidc.interactionResult(
    req, res,
    { login: { accountId, remember: false }, consent: { grantId } },
    { mergeWithLastSubmission: false },
  );
  res.json({ redirectTo });
}

app.use(oidc.callback());

// Terminal error handler: logs locally, no stack traces or oidc-provider
// internals in the response. Status code is validated — some error types
// set .status instead of .statusCode, and a non-integer would make
// res.status() itself throw inside the error handler.
// eslint-disable-next-line no-unused-vars
app.use((err, req, res, next) => {
  console.error('[http]', req.method, req.path, err?.message ?? err);
  if (res.headersSent) return;
  const status = Number.isInteger(err?.statusCode) ? err.statusCode
               : Number.isInteger(err?.status) ? err.status
               : 400;
  res.status(status).json({ error: 'Request failed.' });
});

app.listen(PORT, () => console.log(`PGP OIDC IdP on :${PORT} (issuer ${ISSUER})`));

/* ================================================================== */
/* Pages — plain HTML, no crypto in the browser at all.                */
/* Dark theme matching Karakeep's shadcn/zinc aesthetic. Everything is */
/* inline (no external fonts/CSS/JS), so the strict CSP needs nothing. */
/* ================================================================== */

const pageShell = (title, body) => /* html */ `<!doctype html>
<html lang="en"><head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="color-scheme" content="dark">
<title>${title}</title>
<style>
  * { box-sizing: border-box; }
  body { margin: 0; min-height: 100vh; display: flex; align-items: center;
         justify-content: center; padding: 1.5rem; background: #09090b;
         color: #f4f4f5; font: 15px/1.6 system-ui, -apple-system, "Segoe UI", sans-serif; }
  .card { width: 100%; max-width: 30rem; background: #18181b;
          border: 1px solid #27272a; border-radius: 12px; padding: 2rem; }
  h1 { font-size: 1.25rem; font-weight: 600; margin: 0 0 .25rem; }
  .sub { color: #a1a1aa; font-size: .875rem; margin: 0 0 1.5rem; }
  label { display: block; font-size: .8125rem; color: #a1a1aa; margin-bottom: .375rem; }
  input, textarea { width: 100%; background: #09090b; color: #f4f4f5;
          border: 1px solid #27272a; border-radius: 8px; padding: .5rem .75rem; font: inherit; }
  textarea, .mono { font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace;
          font-size: .75rem; }
  input:focus, textarea:focus { outline: 2px solid #52525b; outline-offset: -1px;
          border-color: #52525b; }
  button { background: #fafafa; color: #18181b; border: 0; border-radius: 8px;
           font: inherit; font-weight: 500; padding: .5rem 1rem; cursor: pointer;
           white-space: nowrap; }
  button:hover { background: #e4e4e7; }
  button.ghost { background: transparent; color: #a1a1aa; border: 1px solid #27272a; }
  button.ghost:hover { color: #f4f4f5; border-color: #52525b; background: transparent; }
  .row { display: flex; gap: .5rem; margin-top: .25rem; }
  .row input { flex: 1; }
  .step { font-size: .8125rem; color: #a1a1aa; margin: 1.25rem 0 .5rem; }
  .step b { color: #f4f4f5; }
  #status { font-size: .8125rem; color: #a1a1aa; min-height: 1.25rem; margin: 1rem 0 0; }
  #status.err { color: #f87171; }
  hr { border: 0; border-top: 1px solid #27272a; margin: 1.5rem 0; }
  .methods { display: flex; gap: .5rem; }
  .methods button { flex: 1; background: transparent; color: #a1a1aa;
          border: 1px solid #27272a; padding: .625rem 1rem; }
  .methods button:hover { color: #f4f4f5; border-color: #52525b; background: transparent; }
  .methods button.active { background: #fafafa; color: #18181b; border-color: transparent; }
  .methods button.active:hover { background: #e4e4e7; }
</style></head><body><div class="card">${body}</div></body></html>`;

function loginPage(uid, m) {
  return pageShell('Sign in', /* html */ `
  <h1>Sign in</h1>
  <p class="sub">Choose how to prove it's you — every method uses a key only you hold.</p>

  <div class="methods">
    ${m.pgp ? '<button id="pickPgp">PGP</button>' : ''}
    ${m.nostr ? '<button id="pickNostr">Nostr</button>' : ''}
    ${m.webauthn ? '<button id="pickPasskey">Passkey</button>' : ''}
  </div>

  ${m.pgp ? /* html */ `
  <div id="pgpPanel" hidden>
    <hr>
    <label for="username">Username</label>
    <div class="row">
      <input id="username" autocomplete="username">
      <button id="getChallenge">Get challenge</button>
    </div>

    <div id="step2" hidden>
      <p class="step"><b>1.</b> Copy this encrypted challenge into your PGP software
      (Kleopatra: Notepad &rarr; paste &rarr; Decrypt/Verify). Confirm a
      <b>valid signature from the site admin's key</b> and that the message
      names this site.</p>
      <textarea id="challenge" rows="9" readonly></textarea>
      <div class="row"><button id="copy" class="ghost">Copy to clipboard</button></div>

      <p class="step"><b>2.</b> Enter the one-time code from the decrypted message:</p>
      <div class="row">
        <input id="code" class="mono" autocomplete="off" spellcheck="false">
        <button id="verify">Sign in</button>
      </div>
    </div>
  </div>` : ''}

  ${m.nostr ? /* html */ `
  <div id="nostrPanel" hidden>
    <hr>
    <p class="step">Your NIP-07 extension (nos2x, Alby, …) will ask you to
    reveal your public key, then to sign a one-time challenge. Nothing
    leaves the extension except the signed event.</p>
    <div class="row"><button id="nostrGo">Open extension and sign in</button></div>
  </div>` : ''}

  ${m.webauthn ? /* html */ `
  <div id="passkeyPanel" hidden>
    <hr>
    <p class="step">Your browser will prompt for a security key registered
    with this site — a YubiKey or other hardware key, or your device's
    built-in authenticator.</p>
    <div class="row"><button id="passkeyGo">Use security key</button></div>
  </div>` : ''}

  <div id="passwordPanel" hidden>
    <hr>
    <p class="step" id="pwPrompt"></p>
    <div class="row">
      <input id="password" type="password" autocomplete="current-password">
      <button id="pwGo">Continue</button>
    </div>
  </div>

  <p id="status"></p>

<script type="module">
  const uid = ${JSON.stringify(uid)};
  const M = ${JSON.stringify(m)};
  const $ = (id) => document.getElementById(id);
  const status = (m, err) => { const s = $('status'); s.textContent = m; s.className = err ? 'err' : ''; };
  const setHidden = (id, h) => { const e = $(id); if (e) e.hidden = h; };
  const setActive = (id, a) => { const e = $(id); if (e) e.classList.toggle('active', a); };

  const pick = (method) => {
    setActive('pickPgp', method === 'pgp');
    setActive('pickNostr', method === 'nostr');
    setActive('pickPasskey', method === 'passkey');
    setHidden('pgpPanel', method !== 'pgp');
    setHidden('nostrPanel', method !== 'nostr');
    setHidden('passkeyPanel', method !== 'passkey');
    setHidden('passwordPanel', true);
    $('password').value = '';
    status('');
  };
  if (M.pgp) $('pickPgp').onclick = () => pick('pgp');
  if (M.nostr) $('pickNostr').onclick = () => { pick('nostr'); nostrSignIn(); };
  if (M.webauthn) $('pickPasskey').onclick = () => { pick('passkey'); passkeySignIn(); };

  // Every verify endpoint either finishes the login ({redirectTo}) or, if
  // the password second factor is enabled, parks it ({passwordRequired})
  // until the password is provided (or first set).
  async function handleAuth(r) {
    if (!r.ok) return status((await r.json()).error ?? 'Sign-in failed.', true);
    const data = await r.json();
    if (data.passwordRequired) {
      ['pgpPanel', 'nostrPanel', 'passkeyPanel'].forEach((p) => setHidden(p, true));
      setHidden('passwordPanel', false);
      $('pwPrompt').textContent = data.setPassword
        ? 'Key verified. Create a password for this account (8-256 characters) - you will need it on every future sign-in:'
        : 'Key verified. Enter your password to finish signing in:';
      $('password').focus();
      return status('');
    }
    status('Verified. Redirecting…');
    window.location = data.redirectTo;
  }

  $('pwGo').onclick = async () => {
    const r = await fetch(\`/interaction/\${uid}/password\`, {
      method: 'POST', headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ password: $('password').value }),
    });
    handleAuth(r);
  };
  $('password').onkeydown = (e) => { if (e.key === 'Enter') $('pwGo').click(); };

  // base64url <-> ArrayBuffer, so the raw WebAuthn API needs no library.
  const b64u = (buf) => btoa(String.fromCharCode(...new Uint8Array(buf)))
    .replace(/\\+/g, '-').replace(/\\//g, '_').replace(/=+$/, '');
  const unb64u = (s) => Uint8Array.from(
    atob(String(s).replace(/-/g, '+').replace(/_/g, '/')), (c) => c.charCodeAt(0));

  /* ---- PGP flow ---- */

  if (M.pgp) {
    $('getChallenge').onclick = async () => {
      const r = await fetch(\`/interaction/\${uid}/challenge\`, {
        method: 'POST', headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ username: $('username').value.trim() }),
      });
      if (!r.ok) return status('Could not get a challenge.', true);
      $('challenge').value = (await r.json()).challenge;
      $('step2').hidden = false;
      status('Challenge issued. Decrypt it in your own PGP software.');
    };

    $('copy').onclick = () => navigator.clipboard.writeText($('challenge').value)
      .then(() => status('Copied.'));

    $('verify').onclick = async () => {
      const r = await fetch(\`/interaction/\${uid}/verify\`, {
        method: 'POST', headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ code: $('code').value }),
      });
      handleAuth(r);
    };
  }

  /* ---- Nostr flow ---- */

  if (M.nostr) $('nostrGo').onclick = () => nostrSignIn();

  async function nostrSignIn() {
    if (!window.nostr) return status('No NIP-07 extension (nos2x, Alby, …) detected.', true);
    try {
      status('Waiting for your extension…');
      const pubkey = await window.nostr.getPublicKey();
      let r = await fetch(\`/interaction/\${uid}/nostr/challenge\`, {
        method: 'POST', headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ pubkey }),
      });
      if (!r.ok) return status('Could not get a challenge for that key.', true);
      const { challenge } = await r.json();

      // SECURITY: the origin tag is location.origin — what this browser
      // actually sees — NOT a value echoed by the server. On a phishing
      // proxy this signs the attacker's hostname, and the IdP (which
      // compares against ISSUER) rejects it. Relay attacks die here.
      const signed = await window.nostr.signEvent({
        kind: 22242,
        created_at: Math.floor(Date.now() / 1000),
        tags: [['challenge', challenge], ['origin', location.origin], ['uid', uid]],
        content: 'Sign in to ' + location.origin,
      });

      r = await fetch(\`/interaction/\${uid}/nostr/verify\`, {
        method: 'POST', headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ event: signed }),
      });
      await handleAuth(r);
    } catch (e) {
      status(e?.message ?? 'Nostr signing was cancelled.', true);
    }
  }

  /* ---- Passkey flow ---- */

  if (M.webauthn) $('passkeyGo').onclick = () => passkeySignIn();

  async function passkeySignIn() {
    if (!window.PublicKeyCredential) return status('This browser does not support passkeys.', true);
    try {
      status('Waiting for your passkey…');
      let r = await fetch(\`/interaction/\${uid}/webauthn/options\`, {
        method: 'POST', headers: { 'Content-Type': 'application/json' }, body: '{}',
      });
      if (!r.ok) return status('Could not start passkey sign-in.', true);
      const opts = await r.json();
      opts.challenge = unb64u(opts.challenge);
      (opts.allowCredentials ?? []).forEach((c) => { c.id = unb64u(c.id); });

      const cred = await navigator.credentials.get({ publicKey: opts });
      const payload = {
        id: cred.id, rawId: b64u(cred.rawId), type: cred.type,
        clientExtensionResults: cred.getClientExtensionResults(),
        response: {
          clientDataJSON: b64u(cred.response.clientDataJSON),
          authenticatorData: b64u(cred.response.authenticatorData),
          signature: b64u(cred.response.signature),
          userHandle: cred.response.userHandle ? b64u(cred.response.userHandle) : undefined,
        },
      };

      r = await fetch(\`/interaction/\${uid}/webauthn/verify\`, {
        method: 'POST', headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(payload),
      });
      await handleAuth(r);
    } catch (e) {
      status(e?.message ?? 'Passkey sign-in was cancelled.', true);
    }
  }
</script>`);
}

function enrollPage(username, m) {
  const safeUsername = escapeHtml(username);
  return pageShell('Add your keys', /* html */ `
  <h1>Add your keys</h1>
  <p class="sub">Enrolling login keys for <b>${safeUsername}</b>. Any one of
  them signs you in.</p>

  ${m.pgp ? /* html */ `
  <p class="step"><b>PGP</b> &mdash; upload your exported <b>public</b> key
  (.asc / .gpg) or paste the armored block. Recommended: a v4 Ed25519/Cv25519
  key (GnuPG's modern default); v6 (RFC 9580) keys are accepted but GnuPG
  support is still maturing.</p>
  <p><input type="file" id="file" accept=".asc,.gpg,.pgp,.key,.txt"></p>
  <textarea id="key" rows="9"
    placeholder="-----BEGIN PGP PUBLIC KEY BLOCK-----"></textarea>` : ''}

  ${m.nostr ? /* html */ `
  <p class="step"><b>Nostr</b> &mdash; paste your public key (npub or hex), or
  pull it from a NIP-07 browser extension:</p>
  <div class="row">
    <input id="npub" class="mono" placeholder="npub1…" autocomplete="off" spellcheck="false">
    <button id="fromExt" class="ghost">Use extension</button>
  </div>` : ''}

  ${m.webauthn ? /* html */ `
  <p class="step"><b>Security key</b> &mdash; register a YubiKey or other
  hardware key, or this device's built-in authenticator. Note: registering
  one uses up this enrollment link on its own — submit any PGP/Nostr keys
  first, or ask the admin for separate links.</p>
  <div class="row"><button id="passkeyReg" class="ghost">Register a security key</button></div>` : ''}

  ${m.pgp || m.nostr ? /* html */ `
  <hr>
  <div class="row"><button id="submit">Submit keys</button></div>` : ''}
  <p id="status"></p>

<script type="module">
  const M = ${JSON.stringify(m)};
  const $ = (id) => document.getElementById(id);
  const status = (m, err) => { const s = $('status'); s.textContent = m; s.className = err ? 'err' : ''; };

  if (M.pgp) $('file').onchange = async () => {
    const f = $('file').files[0];
    if (f) $('key').value = await f.text(); // .asc is text; binary .gpg will fail readably
  };

  if (M.nostr) $('fromExt').onclick = async () => {
    if (!window.nostr) return status('No NIP-07 extension (nos2x, Alby, …) detected.', true);
    try { $('npub').value = await window.nostr.getPublicKey(); status('Public key read from extension.'); }
    catch { status('Extension request was cancelled.', true); }
  };

  const b64u = (buf) => btoa(String.fromCharCode(...new Uint8Array(buf)))
    .replace(/\\+/g, '-').replace(/\\//g, '_').replace(/=+$/, '');
  const unb64u = (s) => Uint8Array.from(
    atob(String(s).replace(/-/g, '+').replace(/_/g, '/')), (c) => c.charCodeAt(0));

  if (M.webauthn) $('passkeyReg').onclick = async () => {
    if (!window.PublicKeyCredential) return status('This browser does not support security keys.', true);
    try {
      status('Waiting for your authenticator…');
      let r = await fetch(location.pathname + '/webauthn/options', {
        method: 'POST', headers: { 'Content-Type': 'application/json' }, body: '{}',
      });
      if (!r.ok) return status('Could not start registration.', true);
      const opts = await r.json();
      opts.challenge = unb64u(opts.challenge);
      opts.user.id = unb64u(opts.user.id);
      (opts.excludeCredentials ?? []).forEach((c) => { c.id = unb64u(c.id); });

      const cred = await navigator.credentials.create({ publicKey: opts });
      const payload = {
        id: cred.id, rawId: b64u(cred.rawId), type: cred.type,
        clientExtensionResults: cred.getClientExtensionResults(),
        response: {
          clientDataJSON: b64u(cred.response.clientDataJSON),
          attestationObject: b64u(cred.response.attestationObject),
          transports: cred.response.getTransports ? cred.response.getTransports() : [],
        },
      };
      r = await fetch(location.pathname + '/webauthn/verify', {
        method: 'POST', headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(payload),
      });
      const data = await r.json();
      if (!r.ok) return status('Rejected: ' + data.error, true);
      status('Security key registered — you can sign in with it now. (This link is now used.)');
    } catch (e) {
      status(e?.message ?? 'Registration was cancelled.', true);
    }
  };

  if (M.pgp || M.nostr) $('submit').onclick = async () => {
    const publicKey = M.pgp ? $('key').value.trim() : '';
    const nostrPubkey = M.nostr ? $('npub').value.trim() : '';
    if (!publicKey && !nostrPubkey) return status('Add at least one key first.', true);

    const r = await fetch(location.pathname, {
      method: 'POST', headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        publicKey: publicKey || undefined,
        nostrPubkey: nostrPubkey || undefined,
      }),
    });
    const data = await r.json();
    if (!r.ok) return status('Rejected: ' + data.error, true);
    const parts = [];
    if (data.pgpFingerprint) parts.push('PGP fingerprint ' + data.pgpFingerprint);
    if (data.nostrPubkey) parts.push('Nostr pubkey ' + data.nostrPubkey.slice(0, 16) + '…');
    status('Enrolled: ' + parts.join(' and ') + ' — you can sign in now.');
  };
</script>`);
}

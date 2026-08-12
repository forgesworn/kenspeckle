// kenspeckle (`./invite` subpath) — join invite + single-attestation anti-sybil verify (spec §9).
//
// Two surfaces, one subpath:
//
//   (1) JoinInvite — the "come join this game" token that fixes the cold-start gap (§9.1). An inviter
//       signs a CANONICAL STRING over the (namespace, serverId, inviterPubkey, nonce, expiresAt) tuple
//       with @noble `schnorr` — a CUSTOM-PAYLOAD signature, NOT a Nostr event (an invite is not an
//       event; it's a structured token carried over QR/URL). An invitee parses the bytes, verifies the
//       Schnorr sig against the embedded `inviterPubkey`, and expiry-checks before opening a §5
//       handshake with the inviter.
//
//   (2) verifyBondAttestation — the single-attestation anti-sybil BRICK (§9.2). Verifies ONE real
//       `kindred-bond` attestation (the kind-31000 event K-4's `buildBondAttestation` builds + the
//       caller finalizes) and returns `{ ok, attesterPubHex, subjectPubHex }`. Collective/guild
//       sybil-resistance — counting a member's attestations into a set of DISTINCT verified humans —
//       lives in the CONSUMING APP. Kenspeckle provides the brick + per-attestation verification, but
//       NO graph traversal, NO counting (that would breach the §2 non-goals).
//
// This is a STANDALONE subpath entry (`import { ... } from 'kenspeckle/invite'`); it is deliberately NOT
// re-exported from the `.` barrel.
//
// --- Canonical invite signing form (DOCUMENT VERBATIM in PROTOCOL.md, K-8) ------------------------
//
//   digest = SHA-256( utf8( `kenspeckle-invite:v1:${namespace}:${serverId}:${inviterPubkey}:${nonce}:${expiresAt ?? ''}` ) )
//   sig    = bytesToHex( schnorr.sign( digest, hexToBytes(inviterPriv) ) )
//
// `serverId` is free-form and MAY contain colons. That is safe here — UNLIKE tessera-kit's capability
// token, whose canonical string was the SOLE wire carrier (so an embedded colon could shift field
// boundaries). Here the invite is parsed from a structured JSON OBJECT and the sig binds the exact
// field VALUES; the canonical string is only ever RECOMPUTED from the already-parsed fields, never
// re-split out of a flat string. So a colon in `serverId` cannot create field-boundary ambiguity.
// We still validate every field (defence in depth + untrusted-input guard).
//
// build → object, parse → bytes (the ASYMMETRY): `buildJoinInvite` returns a `JoinInvite` OBJECT (the
// caller embeds it in whatever transport they like). The transport carries the JSON; `parseJoinInvite`
// takes the decoded BYTES. So a round-trip is: build(object) → consumer serializes to bytes → parse.
// This mirrors the spec signature (build returns `JoinInvite`, parse takes `Uint8Array`) — build does
// NOT return bytes.
//
// `@noble/curves@2` `schnorr.getPublicKey`/`schnorr.sign`/`schnorr.verify` require `Uint8Array`, NOT
// hex (K-6 finding) — every key/sig/digest is `hexToBytes`-converted before the call. No console.

import { schnorr } from '@noble/curves/secp256k1.js'
import { sha256 } from '@noble/hashes/sha2.js'
import { utf8ToBytes, bytesToHex, hexToBytes } from '@noble/hashes/utils.js'
import { verifyEvent } from 'nostr-tools/pure'
import type { NostrEvent } from './types.js'

/** The signed "come join this game" token (spec §9.1). `sig` is a 64-byte (128-hex) Schnorr signature
 *  over the canonical string by the inviter's key. `expiresAt` is optional unix seconds. */
export interface JoinInvite {
  v: 1
  namespace: string
  serverId: string
  inviterPubkey: string
  nonce: string
  expiresAt?: number
  sig: string
}

/** Max accepted blob size, in bytes. Enforced BEFORE decode/parse (cheap DoS guard). Mirrors the
 *  8192-byte cap used across kenspeckle's other untrusted-input parsers (handshake) + signet-app. */
const MAX_BLOB_BYTES = 8192

/** Exactly 64 hex chars = 32 bytes (case-insensitive; lowercased on the way out). */
const HEX64 = /^[0-9a-f]{64}$/i
/** Exactly 128 hex chars = 64 bytes — a Schnorr signature (case-insensitive). */
const HEX128 = /^[0-9a-f]{128}$/i
/** Any non-empty run of hex (even length). The nonce is opaque entropy; we only require it be hex. */
const HEX_ANY = /^(?:[0-9a-f]{2})+$/i

/**
 * Build the canonical signing string for an invite, then SHA-256 it to the 32-byte digest the Schnorr
 * sig is computed over. Fields are used VERBATIM as the caller supplied (the caller has already
 * validated + lowercased the hex fields). `expiresAt` renders as its decimal string, or `''` when
 * absent — so an invite with no expiry and an invite with `expiresAt:0` produce DIFFERENT digests
 * (`...:nonce:` vs `...:nonce:0`), which is correct (they are different invites).
 */
function inviteDigest(p: {
  namespace: string
  serverId: string
  inviterPubkey: string
  nonce: string
  expiresAt?: number
}): Uint8Array {
  const canonical = `kenspeckle-invite:v1:${p.namespace}:${p.serverId}:${p.inviterPubkey}:${p.nonce}:${p.expiresAt ?? ''}`
  return sha256(utf8ToBytes(canonical))
}

function isRecord(v: unknown): v is Record<string, unknown> {
  return v !== null && typeof v === 'object' && !Array.isArray(v)
}

/**
 * Build a signed `JoinInvite` for a server the inviter is vouching entry into.
 *
 * Validates the inviter's private key (64-hex), the embedded `inviterPubkey` (64-hex), the `nonce`
 * (hex), and that `namespace`/`serverId` are non-empty strings. As an anti-forgery guard it also
 * asserts that `schnorr.getPublicKey(priv)` EQUALS `inviterPubkey` — so a caller cannot mint an invite
 * claiming an inviter key they don't actually control (the sig would verify against `inviterPubkey`,
 * so without this check a caller could put SOMEONE ELSE'S pubkey in the field and sign with their own
 * key, producing an invite that fails verification only at parse time; we fail fast at build instead).
 *
 * The private-key byte copy is zeroized in a `finally`. (JS `bigint` scalars inside `@noble` cannot be
 * wiped — same honest limitation documented for `deriveBondSecret`; we wipe the byte copy we hold.)
 *
 * @param p              The invite fields minus `v` and `sig` (those are computed here).
 * @param inviterPrivHex The inviter's persona private key, 64 hex chars (case-insensitive).
 * @returns A fully-populated `{ v:1, ...p, sig }` invite object (NOT bytes — the caller serializes).
 * @throws On any malformed field, or if `inviterPubkey` doesn't match the key derived from the priv.
 */
export function buildJoinInvite(p: Omit<JoinInvite, 'v' | 'sig'>, inviterPrivHex: string): JoinInvite {
  if (typeof inviterPrivHex !== 'string' || !HEX64.test(inviterPrivHex)) {
    throw new Error('invite: inviterPriv must be 64 hex chars')
  }
  if (typeof p.inviterPubkey !== 'string' || !HEX64.test(p.inviterPubkey)) {
    throw new Error('invite: inviterPubkey must be 64 hex chars')
  }
  if (typeof p.nonce !== 'string' || !HEX_ANY.test(p.nonce)) {
    throw new Error('invite: nonce must be a non-empty even-length hex string')
  }
  if (typeof p.namespace !== 'string' || p.namespace.length === 0) {
    throw new Error('invite: namespace must be a non-empty string')
  }
  if (typeof p.serverId !== 'string' || p.serverId.length === 0) {
    throw new Error('invite: serverId must be a non-empty string')
  }
  if (p.expiresAt !== undefined && (typeof p.expiresAt !== 'number' || !Number.isFinite(p.expiresAt))) {
    throw new Error('invite: expiresAt must be a finite number when present')
  }

  const namespace = p.namespace
  const serverId = p.serverId
  const inviterPubkey = p.inviterPubkey.toLowerCase()
  const nonce = p.nonce.toLowerCase()

  const privBytes = hexToBytes(inviterPrivHex.toLowerCase())
  try {
    // Anti-forgery: the priv MUST control the claimed inviterPubkey, else the sig wouldn't verify at
    // parse time anyway — fail fast here so a mismatch is a build-time error, not a silent dud invite.
    const derivedPub = bytesToHex(schnorr.getPublicKey(privBytes))
    if (derivedPub !== inviterPubkey) {
      throw new Error('invite: inviterPubkey does not match the key derived from inviterPriv')
    }

    const digest = inviteDigest({ namespace, serverId, inviterPubkey, nonce, expiresAt: p.expiresAt })
    const sig = bytesToHex(schnorr.sign(digest, privBytes))

    const invite: JoinInvite = { v: 1, namespace, serverId, inviterPubkey, nonce, sig }
    if (p.expiresAt !== undefined) invite.expiresAt = p.expiresAt
    return invite
  } finally {
    privBytes.fill(0) // best-effort zeroize; see the zeroization contract in PROTOCOL.md / bond.ts
  }
}

/**
 * Serialize a `JoinInvite` object to its canonical wire bytes — the symmetry counterpart to
 * `parseJoinInvite` (which takes bytes). `buildJoinInvite` returns the OBJECT and `parseJoinInvite`
 * consumes BYTES (the build→object / parse→bytes asymmetry documented above), so a consumer needs an
 * object→bytes step between them. This is exactly `new TextEncoder().encode(JSON.stringify(invite))`;
 * exposing it as a named helper means callers (and tests) no longer hand-roll the encode, and the wire
 * encoding has ONE definition. The transport (QR / URL) carries these bytes; the round-trip is
 * `build → serialize → parse`.
 *
 * @param invite A fully-populated `JoinInvite` (typically straight from `buildJoinInvite`).
 * @returns UTF-8 JSON bytes ready for the transport.
 */
export function serializeJoinInvite(invite: JoinInvite): Uint8Array {
  return new TextEncoder().encode(JSON.stringify(invite))
}

/**
 * Parse + harden an untrusted invite blob into a typed `JoinInvite`, verifying the inviter's signature
 * and (if present) expiry.
 *
 * Order matters: the 8192-byte size cap is checked BEFORE any UTF-8 decode or JSON parse (cheap DoS
 * guard). A non-JSON blob surfaces a clear `Error` (never a raw `SyntaxError` leak). Every field is
 * validated, hex is lowercase-normalized, then the canonical digest is RECOMPUTED from the parsed
 * fields and the Schnorr sig verified against the embedded `inviterPubkey`. Finally, if `expiresAt` is
 * present and `now` is strictly past it, the invite is rejected as expired.
 *
 * @param blob The decoded invite bytes (UTF-8 JSON).
 * @param now  Optional injected clock (unix seconds) for deterministic expiry tests. Defaults to the
 *             wall clock. Expiry is EXCLUSIVE: `now === expiresAt` is still valid (not yet past).
 * @returns The typed, hex-normalized `JoinInvite`.
 * @throws  On oversize, malformed JSON, any bad field, a bad signature, or an expired invite.
 */
export function parseJoinInvite(blob: Uint8Array, now?: number): JoinInvite {
  // (1) Size cap FIRST — before decode/parse.
  if (blob.length > MAX_BLOB_BYTES) {
    throw new Error('invite: payload too large')
  }

  // (2) Decode + parse, rethrowing a clear Error for non-JSON (no raw SyntaxError surface).
  let raw: unknown
  try {
    raw = JSON.parse(new TextDecoder().decode(blob))
  } catch {
    throw new Error('invite: malformed JSON')
  }

  // (3) Structural + field guards.
  if (!isRecord(raw)) throw new Error('invite: payload must be a JSON object')
  if (raw.v !== 1) throw new Error('invite: unsupported version (v must be 1)')

  if (typeof raw.namespace !== 'string' || raw.namespace.length === 0) {
    throw new Error('invite: namespace must be a non-empty string')
  }
  if (typeof raw.serverId !== 'string' || raw.serverId.length === 0) {
    throw new Error('invite: serverId must be a non-empty string')
  }
  if (typeof raw.inviterPubkey !== 'string' || !HEX64.test(raw.inviterPubkey)) {
    throw new Error('invite: inviterPubkey must be 64 hex chars')
  }
  if (typeof raw.nonce !== 'string' || !HEX_ANY.test(raw.nonce)) {
    throw new Error('invite: nonce must be a non-empty even-length hex string')
  }
  if (typeof raw.sig !== 'string' || !HEX128.test(raw.sig)) {
    throw new Error('invite: sig must be 128 hex chars (64-byte Schnorr signature)')
  }
  let expiresAt: number | undefined
  if (raw.expiresAt !== undefined) {
    if (typeof raw.expiresAt !== 'number' || !Number.isFinite(raw.expiresAt)) {
      throw new Error('invite: expiresAt must be a finite number when present')
    }
    expiresAt = raw.expiresAt
  }

  const namespace = raw.namespace
  const serverId = raw.serverId
  const inviterPubkey = raw.inviterPubkey.toLowerCase()
  const nonce = raw.nonce.toLowerCase()
  const sig = raw.sig.toLowerCase()

  // (4) Recompute the canonical digest from the PARSED fields and verify the Schnorr sig.
  const digest = inviteDigest({ namespace, serverId, inviterPubkey, nonce, expiresAt })
  if (!schnorr.verify(hexToBytes(sig), digest, hexToBytes(inviterPubkey))) {
    throw new Error('invite: bad signature')
  }

  // (5) Expiry (EXCLUSIVE): reject only when the clock is strictly past `expiresAt`.
  const clock = now ?? Math.floor(Date.now() / 1000)
  if (expiresAt !== undefined && clock > expiresAt) {
    throw new Error('invite: expired')
  }

  const invite: JoinInvite = { v: 1, namespace, serverId, inviterPubkey, nonce, sig }
  if (expiresAt !== undefined) invite.expiresAt = expiresAt
  return invite
}

/**
 * Verify a SINGLE `kindred-bond` attestation (spec §9.2) — the anti-sybil brick.
 *
 * Checks (in order, fail-fast): (a) the Nostr event signature + id via `verifyEvent`; (b) the kind is
 * 31000 (the kindred-bond addressable attestation kind); (c) a `["type","kindred-bond"]` tag is
 * present (the discriminator nostr-attestations `createAttestation({type:'kindred-bond'})` renders —
 * confirmed by running K-4's `buildBondAttestation`, which emits tags `["d",...]`, `["type",
 * "kindred-bond"]`, `["p",<subject>]`, optional `["summary",...]`, `["L","nip-va"]`, `["l",
 * "kindred-bond","nip-va"]`); (d) a subject `["p",<64-hex>]` tag is present. On success it returns the
 * attester (`event.pubkey` — the signer) and the subject (the `p`-tag value).
 *
 * This is per-attestation verification ONLY. Counting a member's attestations into a set of DISTINCT
 * verified humans (the collective/guild sybil-resistance of §9.2) is the CONSUMING APP's job — kenspeckle
 * does NO graph traversal and NO counting here (that would breach the §2 non-goals).
 *
 * @param event An (untrusted) Nostr event, ideally wire-shaped (a fresh JSON object). Note nostr-tools
 *   caches `verifyEvent` in an enumerable `verifiedSymbol` on `finalizeEvent` output; a caller that
 *   passes such an object directly would have `verifyEvent` short-circuit on the stale cache. Pass a
 *   wire-clone (`JSON.parse(JSON.stringify(ev))`) if the event might carry that symbol.
 * @returns `{ ok:true, attesterPubHex, subjectPubHex }` on success; `{ ok:false }` otherwise.
 */
export function verifyBondAttestation(event: NostrEvent): {
  ok: boolean
  attesterPubHex?: string
  subjectPubHex?: string
} {
  // (a) Real signature + event-id check. (For finalizeEvent output, the caller should wire-clone to
  //     drop the verifiedSymbol cache; otherwise verifyEvent may short-circuit on a stale `true`.)
  if (!verifyEvent(event)) return { ok: false }

  // (b) Must be the kindred-bond addressable attestation kind.
  if (event.kind !== 31000) return { ok: false }

  // (c) The kindred-bond discriminator tag (the EXACT shape nostr-attestations emits — verified
  //     against the real buildBondAttestation output, not guessed).
  const typeTag = event.tags.find((t) => t[0] === 'type' && t[1] === 'kindred-bond')
  if (!typeTag) return { ok: false }

  // (d) The subject p-tag (the pubkey the attester is asserting a bond with). Must be 64-hex.
  const pTag = event.tags.find((t) => t[0] === 'p' && typeof t[1] === 'string' && HEX64.test(t[1]))
  if (!pTag || typeof pTag[1] !== 'string') return { ok: false }

  return { ok: true, attesterPubHex: event.pubkey, subjectPubHex: pTag[1] }
}

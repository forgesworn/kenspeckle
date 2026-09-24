// kenspeckle (`./invite` subpath) — join invite + single-attestation anti-sybil verify (spec §9).
//
// Two surfaces, one subpath:
//
//   (1) JoinInvite — the "come join this game" token that fixes the cold-start gap (§9.1). An inviter
//       signs a CANONICAL ENCODING of the (namespace, serverId, inviterPubkey, nonce, expiresAt) tuple
//       with @noble `schnorr` — a CUSTOM-PAYLOAD signature, NOT a Nostr event (an invite is not an
//       event; it's a structured token carried over QR/URL). An invitee parses the bytes, verifies the
//       Schnorr sig against the embedded `inviterPubkey`, and expiry-checks before opening a §5
//       handshake with the inviter.
//
//   (2) verifyBondAttestation — the single-attestation anti-sybil BRICK (§9.2). Verifies ONE real
//       `kindred-bond` attestation (the kind-31000 event K-4's `buildBondAttestation` builds + the
//       caller finalizes) and returns `{ ok, attesterPubHex, subjectPubHex }`. Revoked, expired and
//       self-attestations are rejected with a distinct `reason`. Collective/guild sybil-resistance —
//       counting a member's attestations into a set of DISTINCT verified humans — lives in the
//       CONSUMING APP. Kenspeckle provides the brick + per-attestation verification, but NO graph
//       traversal, NO counting (that would breach the §2 non-goals).
//
// This is a STANDALONE subpath entry (`import { ... } from 'kenspeckle/invite'`); it is deliberately NOT
// re-exported from the `.` barrel.
//
// --- Canonical invite signing form, v2 (DOCUMENT VERBATIM in PROTOCOL.md §6) -----------------------
//
//   digest = SHA-256( utf8( JSON.stringify(
//              ["kenspeckle-invite", 2, namespace, serverId, inviterPubkey, nonce, expiresAt ?? null] ) ) )
//   sig    = bytesToHex( schnorr.sign( digest, hexToBytes(inviterPriv) ) )
//
// WHY A JSON ARRAY, NOT A COLON-JOINED STRING: v1 signed `kenspeckle-invite:v1:${ns}:${serverId}:…`.
// `namespace` and `serverId` are free text that may contain `:`, so that string was NOT injective: an
// invite signed for `{namespace:"game", serverId:"eu:prod"}` verified as `{namespace:"game:eu",
// serverId:"prod"}` — recomputing from parsed fields does not help when two different field tuples
// flatten to the same bytes. A JSON array quotes and escapes every string, so distinct tuples always
// encode to distinct bytes. Every string must also be well-formed UTF-16: `utf8()` maps a lone
// surrogate to U+FFFD, which would make `"\uD800"` and `"\uFFFD"` collide; such strings are rejected
// at build AND parse. v1 invites are NOT accepted (no fallback — nothing consumed them before v2).
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
import { utf8ToBytes, bytesToHex, hexToBytes, randomBytes } from '@noble/hashes/utils.js'
import { isValid } from 'nostr-attestations'
import { verifyEvent } from 'nostr-tools/pure'
import type { NostrEvent } from './types.js'

/** The signed "come join this game" token (spec §9.1). `sig` is a 64-byte (128-hex) Schnorr signature
 *  over the v2 canonical encoding by the inviter's key. `expiresAt` is optional unix seconds. */
export interface JoinInvite {
  v: 2
  namespace: string
  serverId: string
  inviterPubkey: string
  nonce: string
  expiresAt?: number
  sig: string
}

/** Current (and only accepted) invite wire version. */
export const INVITE_VERSION = 2

/** Domain tag at index 0 of the canonical array. */
export const INVITE_DOMAIN = 'kenspeckle-invite'

/** Minimum nonce entropy, in bytes. A short nonce makes (inviter, nonce) collide across invites, which
 *  defeats the dedupe-by-(inviter, nonce) replay guidance in PROTOCOL.md §6.3. */
export const INVITE_NONCE_MIN_BYTES = 16

/** Max accepted blob size, in bytes. Enforced BEFORE decode/parse (cheap DoS guard). Mirrors the
 *  8192-byte cap used across kenspeckle's other untrusted-input parsers (handshake) + signet-app. */
const MAX_BLOB_BYTES = 8192

/** Exactly 64 hex chars = 32 bytes (case-insensitive; the builder lowercases on the way out). */
const HEX64 = /^[0-9a-f]{64}$/i
/** Exactly 64 LOWERCASE hex chars. The parser accepts only the canonical spelling. */
const HEX64_LOWER = /^[0-9a-f]{64}$/
/** Exactly 128 LOWERCASE hex chars = 64 bytes — a Schnorr signature. */
const HEX128_LOWER = /^[0-9a-f]{128}$/
/** At least 16 bytes of even-length hex (case-insensitive; the builder lowercases). */
const NONCE_HEX = /^(?:[0-9a-f]{2}){16,}$/i
/** The same, lowercase only (parse side: one wire spelling per invite). */
const NONCE_HEX_LOWER = /^(?:[0-9a-f]{2}){16,}$/

/** A lone (unpaired) UTF-16 surrogate. Hand-rolled rather than `String.prototype.isWellFormed` so the
 *  check does not depend on the ES2024 lib / runtime. */
const LONE_SURROGATE = /[\uD800-\uDBFF](?![\uDC00-\uDFFF])|(?<![\uD800-\uDBFF])[\uDC00-\uDFFF]/

/** A non-empty string with no lone surrogates. */
function isWellFormedText(value: unknown): value is string {
  return typeof value === 'string' && value.length > 0 && !LONE_SURROGATE.test(value)
}

/** A non-negative safe integer (unix seconds). Rules out floats, `1e21` (which stringifies as
 *  `"1e+21"`), negatives, NaN and Infinity. */
function isUnixSeconds(value: unknown): value is number {
  return typeof value === 'number' && Number.isSafeInteger(value) && value >= 0
}

/**
 * The v2 canonical encoding, SHA-256'd to the 32-byte digest the Schnorr sig is computed over:
 * `sha256(utf8(JSON.stringify(["kenspeckle-invite", 2, namespace, serverId, inviterPubkey, nonce,
 * expiresAt ?? null])))`. Callers pass already-validated, lowercased fields. An invite with no expiry
 * encodes `null`, one with `expiresAt: 0` encodes `0` — different digests, which is correct.
 */
function inviteDigest(p: {
  namespace: string
  serverId: string
  inviterPubkey: string
  nonce: string
  expiresAt?: number
}): Uint8Array {
  const canonical = JSON.stringify([
    INVITE_DOMAIN,
    INVITE_VERSION,
    p.namespace,
    p.serverId,
    p.inviterPubkey,
    p.nonce,
    p.expiresAt ?? null,
  ])
  return sha256(utf8ToBytes(canonical))
}

function isRecord(v: unknown): v is Record<string, unknown> {
  return v !== null && typeof v === 'object' && !Array.isArray(v)
}

/** A fresh 16-byte (32-hex) invite nonce from the platform CSPRNG. */
export function generateInviteNonce(): string {
  return bytesToHex(randomBytes(INVITE_NONCE_MIN_BYTES))
}

/**
 * Build a signed v2 `JoinInvite` for a server the inviter is vouching entry into.
 *
 * Validates the inviter's private key (64-hex), the embedded `inviterPubkey` (64-hex), the `nonce`
 * (≥16 bytes of hex — use `generateInviteNonce`), that `namespace`/`serverId` are non-empty,
 * well-formed (no lone surrogates) strings, and that `expiresAt`, when present, is a non-negative safe
 * integer. If `now` is supplied, an `expiresAt` already strictly in the past is rejected (the same
 * exclusive rule `parseJoinInvite` applies). As an anti-forgery guard it also asserts that
 * `schnorr.getPublicKey(priv)` EQUALS `inviterPubkey` — so a caller cannot mint an invite claiming an
 * inviter key they don't control (it would only fail at parse time; we fail fast at build instead).
 *
 * The private-key byte copy handed to `@noble` is zeroized in a `finally`. (JS `bigint` scalars inside
 * `@noble` cannot be wiped — see PROTOCOL.md §1.6; we wipe the byte copy we hold.)
 *
 * @param p              The invite fields minus `v` and `sig` (those are computed here).
 * @param inviterPrivHex The inviter's persona private key, 64 hex chars (case-insensitive).
 * @param now            Optional clock (unix seconds) for the already-expired check. Omitted → no check.
 * @returns A fully-populated `{ v:2, ...p, sig }` invite object (NOT bytes — the caller serializes).
 * @throws On any malformed field, or if `inviterPubkey` doesn't match the key derived from the priv.
 */
export function buildJoinInvite(p: Omit<JoinInvite, 'v' | 'sig'>, inviterPrivHex: string, now?: number): JoinInvite {
  if (typeof inviterPrivHex !== 'string' || !HEX64.test(inviterPrivHex)) {
    throw new Error('invite: inviterPriv must be 64 hex chars')
  }
  if (typeof p.inviterPubkey !== 'string' || !HEX64.test(p.inviterPubkey)) {
    throw new Error('invite: inviterPubkey must be 64 hex chars')
  }
  if (typeof p.nonce !== 'string' || !NONCE_HEX.test(p.nonce)) {
    throw new Error(`invite: nonce must be at least ${INVITE_NONCE_MIN_BYTES} bytes of even-length hex`)
  }
  if (!isWellFormedText(p.namespace)) {
    throw new Error('invite: namespace must be a non-empty well-formed string')
  }
  if (!isWellFormedText(p.serverId)) {
    throw new Error('invite: serverId must be a non-empty well-formed string')
  }
  if (p.expiresAt !== undefined && !isUnixSeconds(p.expiresAt)) {
    throw new Error('invite: expiresAt must be a non-negative safe integer when present')
  }
  if (now !== undefined && p.expiresAt !== undefined && now > p.expiresAt) {
    throw new Error('invite: expiresAt is already in the past')
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

    const invite: JoinInvite = { v: INVITE_VERSION, namespace, serverId, inviterPubkey, nonce, sig }
    if (p.expiresAt !== undefined) invite.expiresAt = p.expiresAt
    return invite
  } finally {
    privBytes.fill(0) // best-effort zeroize; see the zeroization contract in PROTOCOL.md §1.6
  }
}

/**
 * Serialize a `JoinInvite` object to its canonical wire bytes — the symmetry counterpart to
 * `parseJoinInvite` (which takes bytes). `buildJoinInvite` returns the OBJECT and `parseJoinInvite`
 * consumes BYTES (the build→object / parse→bytes asymmetry documented above), so a consumer needs an
 * object→bytes step between them. Only the declared fields are emitted (an explicit projection, never
 * the caller's object); the transport (QR / URL) carries these bytes and the round-trip is
 * `build → serialize → parse`.
 *
 * @param invite A fully-populated `JoinInvite` (typically straight from `buildJoinInvite`).
 * @returns UTF-8 JSON bytes ready for the transport.
 */
export function serializeJoinInvite(invite: JoinInvite): Uint8Array {
  const wire: JoinInvite = {
    v: invite.v,
    namespace: invite.namespace,
    serverId: invite.serverId,
    inviterPubkey: invite.inviterPubkey,
    nonce: invite.nonce,
    sig: invite.sig,
  }
  if (invite.expiresAt !== undefined) wire.expiresAt = invite.expiresAt
  return new TextEncoder().encode(JSON.stringify(wire))
}

/**
 * Parse + harden an untrusted invite blob into a typed `JoinInvite`, verifying the inviter's signature
 * and (if present) expiry.
 *
 * Order matters: the 8192-byte size cap is checked BEFORE any UTF-8 decode or JSON parse (cheap DoS
 * guard). A non-JSON blob surfaces a clear `Error` (never a raw `SyntaxError` leak). Only `v === 2` is
 * accepted. Every field is validated — hex fields must already be lowercase (one wire spelling per
 * invite), the nonce is ≥16 bytes, strings must be well-formed, `expiresAt` a non-negative safe integer
 * — then the v2 canonical digest is RECOMPUTED from the parsed fields and the Schnorr sig verified
 * against the embedded `inviterPubkey`. Finally, if `expiresAt` is present and `now` is strictly past
 * it, the invite is rejected as expired.
 *
 * A valid signature does not make an invite single-use: dedupe on `(inviterPubkey, nonce)` if an
 * invite must be redeemable once (PROTOCOL.md §6.3).
 *
 * @param blob The decoded invite bytes (UTF-8 JSON).
 * @param now  Optional injected clock (unix seconds) for deterministic expiry tests. Defaults to the
 *             wall clock. Expiry is EXCLUSIVE: `now === expiresAt` is still valid (not yet past).
 * @returns The typed `JoinInvite`.
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
  if (raw.v !== INVITE_VERSION) throw new Error(`invite: unsupported version (v must be ${INVITE_VERSION})`)

  if (!isWellFormedText(raw.namespace)) {
    throw new Error('invite: namespace must be a non-empty well-formed string')
  }
  if (!isWellFormedText(raw.serverId)) {
    throw new Error('invite: serverId must be a non-empty well-formed string')
  }
  if (typeof raw.inviterPubkey !== 'string' || !HEX64_LOWER.test(raw.inviterPubkey)) {
    throw new Error('invite: inviterPubkey must be 64 lowercase hex chars')
  }
  if (typeof raw.nonce !== 'string' || !NONCE_HEX_LOWER.test(raw.nonce)) {
    throw new Error(`invite: nonce must be at least ${INVITE_NONCE_MIN_BYTES} bytes of lowercase hex`)
  }
  if (typeof raw.sig !== 'string' || !HEX128_LOWER.test(raw.sig)) {
    throw new Error('invite: sig must be 128 lowercase hex chars (64-byte Schnorr signature)')
  }
  let expiresAt: number | undefined
  if (raw.expiresAt !== undefined) {
    if (!isUnixSeconds(raw.expiresAt)) {
      throw new Error('invite: expiresAt must be a non-negative safe integer when present')
    }
    expiresAt = raw.expiresAt
  }

  const namespace = raw.namespace
  const serverId = raw.serverId
  const inviterPubkey = raw.inviterPubkey
  const nonce = raw.nonce
  const sig = raw.sig

  // (4) Recompute the canonical digest from the PARSED fields and verify the Schnorr sig.
  const digest = inviteDigest({ namespace, serverId, inviterPubkey, nonce, expiresAt })
  let sigOk = false
  try {
    sigOk = schnorr.verify(hexToBytes(sig), digest, hexToBytes(inviterPubkey))
  } catch {
    sigOk = false // an off-curve x can throw inside @noble — surface it as a bad signature
  }
  if (!sigOk) throw new Error('invite: bad signature')

  // (5) Expiry (EXCLUSIVE): reject only when the clock is strictly past `expiresAt`.
  const clock = now ?? Math.floor(Date.now() / 1000)
  if (expiresAt !== undefined && clock > expiresAt) {
    throw new Error('invite: expired')
  }

  const invite: JoinInvite = { v: INVITE_VERSION, namespace, serverId, inviterPubkey, nonce, sig }
  if (expiresAt !== undefined) invite.expiresAt = expiresAt
  return invite
}

/** Why `verifyBondAttestation` rejected an event. `revoked` / `expired` / `not-yet-active` /
 *  `claim-expired` come from the attestation's own lifecycle tags (nostr-attestations `isValid`). */
export type BondAttestationRejection =
  | 'bad-signature'
  | 'wrong-kind'
  | 'not-kindred-bond'
  | 'bad-subject'
  | 'd-tag-mismatch'
  | 'self-attestation'
  | 'revoked'
  | 'expired'
  | 'not-yet-active'
  | 'claim-expired'

/** Result of `verifyBondAttestation`. On success both pubkeys are lowercase 64-hex. */
export interface BondAttestationResult {
  ok: boolean
  attesterPubHex?: string
  subjectPubHex?: string
  reason?: BondAttestationRejection
}

/**
 * Verify a SINGLE `kindred-bond` attestation (spec §9.2) — the anti-sybil brick.
 *
 * Checks (in order, fail-fast): (a) the Nostr event signature + id via `verifyEvent`; (b) the kind is
 * 31000; (c) a `["type","kindred-bond"]` tag is present (the discriminator nostr-attestations
 * `createAttestation({type:'kindred-bond'})` renders); (d) EXACTLY ONE `["p",<64-hex>]` subject tag;
 * (e) exactly one `d` tag, equal to `kindred-bond:<subject>` (lowercase) — so the event sits at the
 * address a `buildBondRevocation` overwrites and cannot dodge revocation under a different `d`;
 * (f) the subject is not the attester (a self-attestation proves nothing); (g) the lifecycle via
 * nostr-attestations `isValid(event, now)`: a `["status","revoked"]` event, a passed NIP-40
 * `expiration`, a future `valid_from` or a passed `valid_to` are all rejected.
 *
 * (g) only sees the event it is given. A revocation REPLACES the attestation at its address (kind 31000
 * is addressable), so a consumer must fetch the LATEST event for `(attester, 31000, d)` — an older
 * non-revoked copy still passes here.
 *
 * This is per-attestation verification ONLY. Counting a member's attestations into a set of DISTINCT
 * verified humans (the collective/guild sybil-resistance of §9.2) is the CONSUMING APP's job — kenspeckle
 * does NO graph traversal and NO counting here (that would breach the §2 non-goals). Both returned
 * pubkeys are lowercased so a distinct-count over them is not fooled by case.
 *
 * @param event An (untrusted) Nostr event, ideally wire-shaped (a fresh JSON object). Note nostr-tools
 *   caches `verifyEvent` in an enumerable `verifiedSymbol` on `finalizeEvent` output; a caller that
 *   passes such an object directly would have `verifyEvent` short-circuit on the stale cache. Pass a
 *   wire-clone (`JSON.parse(JSON.stringify(ev))`) if the event might carry that symbol.
 * @param now   Optional injected clock (unix seconds) for the lifecycle check. Defaults to the wall clock.
 * @returns `{ ok:true, attesterPubHex, subjectPubHex }` on success; `{ ok:false, reason }` otherwise.
 */
export function verifyBondAttestation(event: NostrEvent, now?: number): BondAttestationResult {
  // (a) Real signature + event-id check. (For finalizeEvent output, the caller should wire-clone to
  //     drop the verifiedSymbol cache; otherwise verifyEvent may short-circuit on a stale `true`.)
  if (!verifyEvent(event)) return { ok: false, reason: 'bad-signature' }

  // (b) Must be the kindred-bond addressable attestation kind.
  if (event.kind !== 31000) return { ok: false, reason: 'wrong-kind' }

  // (c) The kindred-bond discriminator tag (the EXACT shape nostr-attestations emits).
  const typeTag = event.tags.find((t) => t[0] === 'type' && t[1] === 'kindred-bond')
  if (!typeTag) return { ok: false, reason: 'not-kindred-bond' }

  // (d) Exactly one subject p-tag, 64-hex. Lowercased so the caller's distinct-count is case-proof.
  const pTags = event.tags.filter((t) => t[0] === 'p')
  const subjectRaw = pTags.length === 1 ? pTags[0]?.[1] : undefined
  if (typeof subjectRaw !== 'string' || !HEX64.test(subjectRaw)) return { ok: false, reason: 'bad-subject' }
  const subject = subjectRaw.toLowerCase()

  // (e) The addressable slot must be the one a revocation for this subject targets.
  const dTags = event.tags.filter((t) => t[0] === 'd')
  if (dTags.length !== 1 || dTags[0]?.[1] !== `kindred-bond:${subject}`) {
    return { ok: false, reason: 'd-tag-mismatch' }
  }

  // (f) verifyEvent has already required a 64-hex pubkey; lowercase for the same case-proofing.
  const attester = event.pubkey.toLowerCase()
  if (attester === subject) return { ok: false, reason: 'self-attestation' }

  // (g) Lifecycle: revoked / expired / not yet active / claim window passed.
  const validity = isValid(event, now)
  if (!validity.valid) {
    return { ok: false, reason: (validity.reason ?? 'revoked') as BondAttestationRejection }
  }

  return { ok: true, attesterPubHex: attester, subjectPubHex: subject }
}

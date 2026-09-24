// kenspeckle (`./bond` subpath) — the migration-critical bond ceremony (spec §5.2, §5.4, §5.5, §5.6).
//
// A "bond" is a kith relationship: two personas mutually verify each other out-of-band by speaking
// short, time-rotating words derived from a shared ECDH secret (spoken-token). This file is the
// MIGRATION-CRITICAL surface: `deriveBondSecret` MUST reproduce signet-protocol's ECDH construction
// byte-for-byte, or every contact migrated from signet-app gets a different secret → different words
// → broken verification for both parties. The frozen vector in bond.test.ts is the regression gate.
//
// This is a STANDALONE subpath entry (`import { ... } from 'kenspeckle/bond'`); it is deliberately NOT
// re-exported from the `.` barrel. It works entirely with hex strings + @noble + spoken-token +
// nostr-attestations — no TextEncoder/fetch, no model dependency, no console output anywhere.

import { secp256k1 } from '@noble/curves/secp256k1.js'
import { sha256 } from '@noble/hashes/sha2.js'
import { bytesToHex, hexToBytes } from '@noble/hashes/utils.js'
import { deriveDirectionalPair } from 'spoken-token'
import { timingSafeStringEqual } from 'spoken-token/crypto'
import { ATTESTATION_KIND, createAttestation, createRevocation } from 'nostr-attestations'
import type { EventTemplate, BondAssertion } from './types.js'

// `secp256k1.Point` is the v2 Weierstrass point class. `Point.Fn` is the scalar field; `.ORDER` is
// the curve order N (confirmed the right v2 accessor against the sibling repo `range-proof`, which
// does `export const N = secp256k1.Point.Fn.ORDER`).
const Point = secp256k1.Point

/** Domain-separation namespace for the spoken-token directional pair. Distinct from any other
 *  spoken-token use so a bond word can never collide with (or be replayed as) another ceremony. */
export const KINDRED_BOND_NAMESPACE = 'kindred:bond'

/** The addressable kind nostr-attestations publishes bond attestations (and their revocations) under. */
const BOND_ATTESTATION_KIND: number = ATTESTATION_KIND

/** Exactly 64 lowercase hex chars (32 bytes). Inputs are lowercased before this test runs. */
const HEX64_LOWER = /^[0-9a-f]{64}$/

/**
 * Derive the kith shared secret via ECDH — **byte-for-byte identical to signet-protocol**.
 *
 * Construction (the migration-critical part):
 *   secret = SHA-256( x-coordinate-bytes-of( theirPubPoint × myScalar ) )
 *
 * where `theirPubPoint` is the even-y lift of the counterparty's x-only (BIP-340) pubkey and the
 * x-coordinate is serialised as 32 big-endian bytes (left-zero-padded). Returns 64-char lc hex.
 *
 * **Why the agreement holds (and why it is NOT because "02 even-y is correct"):** x-only pubkeys
 * drop the y parity, so lifting with the `02` (even-y) prefix may pick the OPPOSITE point (−P) from
 * the one the counterparty actually holds. ECDH with −P yields −(shared point), but −Q and Q share
 * the SAME x-coordinate (negation flips only y). Because this construction hashes ONLY the
 * x-coordinate, both seats land on the identical secret regardless of which y-parity each side lifted.
 * This is exactly why signet-protocol is safe to migrate from byte-for-byte: the shared x is the
 * invariant, not the chosen sign.
 *
 * **Zeroization contract (see PROTOCOL.md §1.6): none.** The key arrives as an immutable hex string
 * and the ECDH runs on a `bigint` scalar and point limbs, none of which can be wiped from JS, and no
 * byte copy of the key is made. This function makes NO zeroization claim. A future Rust/WASM port
 * MUST take the key as bytes and zeroize the scalar and the point.
 *
 * @param myPrivHex   - My persona private key, 64 hex chars (case-insensitive).
 * @param theirPubHex - The counterparty's x-only (BIP-340) pubkey, 64 hex chars (case-insensitive).
 * @returns 64-char lowercase hex: SHA-256 of the shared x-coordinate.
 * @throws If priv/pub are not 64 hex, the pubkey is not on the curve, or the scalar is non-canonical.
 */
export function deriveBondSecret(myPrivHex: string, theirPubHex: string): string {
  const priv = myPrivHex.toLowerCase(),
    pub = theirPubHex.toLowerCase()
  if (!HEX64_LOWER.test(priv)) throw new Error('deriveBondSecret: priv must be 64 hex')
  if (!HEX64_LOWER.test(pub)) throw new Error('deriveBondSecret: pubkey must be 64 hex (x-only)')

  let theirPoint
  try {
    // Lift the x-only pubkey to a full point using the even-y (02) prefix. Throws if x is not a
    // valid curve x-coordinate. (Sign choice is irrelevant — see the x-only note above.)
    theirPoint = Point.fromHex('02' + pub)
  } catch {
    throw new Error('deriveBondSecret: invalid curve point')
  }

  const scalar = BigInt('0x' + priv)
  // Canonical scalar range is [1, N-1]. 0 is the identity; >= N is reduced-equivalent and rejected.
  if (scalar <= 0n || scalar >= Point.Fn.ORDER) {
    throw new Error('deriveBondSecret: non-canonical scalar')
  }

  const xHex = theirPoint.multiply(scalar).toAffine().x.toString(16).padStart(64, '0')
  return bytesToHex(sha256(hexToBytes(xHex)))
}

/** Options for `bondWords` — additive + backward-compatible (default reproduces the existing behaviour).
 *
 *  `namespace` exists for ONE reason: signet-me compatibility during the signet-app migration rollout
 *  (see PROTOCOL.md §2.1). signet-app's `signet-me` derives words with namespace `'signet:me'`. A
 *  migrated contact whose peer has NOT yet migrated must be able to reproduce signet-me's exact words to
 *  cross-verify, so `bondWords` can be steered to that namespace.
 *
 *  WHY THERE IS NO role-order knob: `deriveDirectionalPair` keys each word on `namespace + '\0' + role`
 *  — i.e. on the role STRING, independent of its POSITION in the tuple. So `namespace` is the only knob
 *  that changes the words; tuple order does not (sorted vs caller-order give the same `mine`/`theirs`,
 *  because `mine = pair[aPubHex]` regardless of order). signet-me compat is reproduced by `namespace`
 *  alone. Each seat still passes its OWN pubkey as `aPubHex`, so it picks its own role's word.
 *
 *  With DEFAULT opts the words DIFFER from signet-me (kenspeckle uses `'kindred:bond'`), so a naive
 *  migration changes the words — both peers must upgrade together OR pass the signet-me `namespace`. */
export interface BondWordsOpts {
  /** Domain-separation namespace fed to `deriveDirectionalPair`. Default `KINDRED_BOND_NAMESPACE`
   *  (`'kindred:bond'`). Pass `'signet:me'` to reproduce signet-app's `signet-me` words. This is the
   *  knob that actually changes the derived words. */
  namespace?: string
}

/** Compute the canonical `[lo, hi]` = `sort([a,b])` role-token tuple for a (a,b) pubkey pair, so both
 *  seats feed `deriveDirectionalPair` the identical roles regardless of which pubkey they passed first;
 *  the caller's own pubkey then selects which role token is "mine." (Because `deriveDirectionalPair`
 *  keys each word on the role STRING, not its tuple index, the sort affects only the tuple shape — not
 *  `bondWords`'s output — so no role-order knob is needed.) Built as an explicit 2-tuple (not
 *  array-destructured) so the `[string, string]` shape survives `noUncheckedIndexedAccess`. */
function bondRoles(a: string, b: string): [string, string] {
  return a < b ? [a, b] : [b, a]
}

/** Validate + normalise the non-secret `bondWords` inputs, throwing a kenspeckle-shaped error rather
 *  than letting spoken-token throw its own (`Roles must be distinct`, empty namespace) from inside.
 *  Both pubkeys must be 64-hex and DIFFERENT (a self-bond has no counterparty word), and the
 *  namespace a non-empty string. */
function bondWordsInputs(
  aPubHex: string,
  bPubHex: string,
  opts: BondWordsOpts | undefined,
): { a: string; b: string; namespace: string } {
  if (typeof aPubHex !== 'string' || !HEX64_LOWER.test(aPubHex.toLowerCase())) {
    throw new Error('bondWords: own pubkey must be 64 hex chars')
  }
  if (typeof bPubHex !== 'string' || !HEX64_LOWER.test(bPubHex.toLowerCase())) {
    throw new Error('bondWords: counterparty pubkey must be 64 hex chars')
  }
  const a = aPubHex.toLowerCase(),
    b = bPubHex.toLowerCase()
  if (a === b) throw new Error('bondWords: own and counterparty pubkeys must differ')
  const namespace = opts?.namespace ?? KINDRED_BOND_NAMESPACE
  if (typeof namespace !== 'string' || namespace.length === 0) {
    throw new Error('bondWords: namespace must be a non-empty string')
  }
  return { a, b, namespace }
}

/**
 * Derive this seat's directional spoken-token word pair for a given rotation counter.
 *
 * `aPubHex` is the CALLER'S OWN persona pubkey; `bPubHex` is the counterparty's. By default the two
 * pubkeys are sorted to canonical `[lo, hi]` role tokens so both seats feed `deriveDirectionalPair` the
 * identical `(secret, namespace, roles, counter)` and therefore agree on the pair. The caller's own
 * pubkey then selects which role's token is "mine" (the word I speak) vs "theirs" (the word I expect).
 *
 * The directional construction means `mine !== theirs`: the listener cannot parrot the speaker's word
 * back (spoken-token's "echo problem" defence) — each direction is an independent HMAC output.
 *
 * **signet-me compatibility (`opts`).** Pass `{ namespace: 'signet:me' }` to reproduce signet-app's
 * `signet-me` words byte-for-byte (so a migrated contact can cross-verify with a peer who has NOT yet
 * migrated); each seat passes its OWN pubkey as `aPubHex`. With DEFAULT opts the words differ from
 * signet-me — see `BondWordsOpts`.
 *
 * @param secretHex - The bond secret (hex; interpreted as bytes, ≥16 — our 32-byte secret is fine).
 * @param aPubHex   - Caller's own persona pubkey (64 hex; case-insensitive); selects which role's token
 *                    is "mine."
 * @param bPubHex   - Counterparty pubkey (64 hex; case-insensitive).
 * @param counter   - Rotation counter (uint32) — words change as it advances.
 * @param opts      - Optional `{ namespace? }` — additive, default reproduces the existing behaviour
 *                    (`'kindred:bond'`).
 * @returns `{ mine, theirs }` — the word I speak and the word I expect from the counterparty.
 * @throws If the secret or either pubkey is not 64-hex, the two pubkeys are equal, or the namespace is
 *         empty.
 */
export function bondWords(
  secretHex: string,
  aPubHex: string,
  bPubHex: string,
  counter: number,
  opts?: BondWordsOpts,
): { mine: string; theirs: string } {
  // Guard the secret shape at the kenspeckle boundary: `secretHex` must be the 64-hex value
  // `deriveBondSecret` emits. Without this, an odd-length / non-hex secret reaches
  // `deriveDirectionalPair` and leaks a raw `hexToBytes: odd-length hex string` (spoken-token/@noble)
  // — an opaque error with no kenspeckle context. Match `deriveBondSecret`'s own error surface. This also
  // covers `verifyBondWord` (it derives via `bondWords`); a malformed secret is a programmer error,
  // distinct from the fail-soft tolerance/counter clamps which never throw on a VALID-shaped call.
  if (typeof secretHex !== 'string' || !/^[0-9a-f]{64}$/i.test(secretHex)) {
    throw new Error('bondWords: secret must be 64 hex chars')
  }
  const { a, b, namespace } = bondWordsInputs(aPubHex, bPubHex, opts)
  const roles = bondRoles(a, b)
  const pair = deriveDirectionalPair(secretHex, namespace, roles, counter)
  // a and b are each exactly one of the two role tokens, so these lookups always resolve.
  return { mine: pair[a]!, theirs: pair[b]! }
}

/** Max clock-skew window kenspeckle will honour, mirroring spoken-token's own `MAX_TOLERANCE = 10`. A
 *  larger `tolerance` is clamped to this (it is a dev arg, not attacker input — fail-soft, do not throw)
 *  so a bogus value can never spin an unbounded re-derivation loop. */
export const MAX_BOND_TOLERANCE = 10

/** Coerce a caller-supplied `tolerance` to a safe window size: integer, in `[0, MAX_BOND_TOLERANCE]`.
 *  A negative / NaN / non-finite / fractional value becomes `0` (exact-counter match); anything above the
 *  cap is clamped down. Pure + total — never throws (the `verifyBondWord` `{ok}` contract forbids it). */
function clampTolerance(tolerance: number | undefined): number {
  if (tolerance === undefined) return 0
  // `Math.trunc(NaN) === NaN`, and `NaN < 0` is false, so guard NaN/Infinity explicitly first.
  if (!Number.isFinite(tolerance)) return 0
  const t = Math.trunc(tolerance)
  if (t <= 0) return 0
  return t > MAX_BOND_TOLERANCE ? MAX_BOND_TOLERANCE : t
}

/** Options for `verifyBondWord` — a superset of `BondWordsOpts` adding a clock-skew `tolerance` window.
 *  `namespace` carries the same signet-me-compat meaning as on `bondWords`. */
export interface VerifyBondWordOpts extends BondWordsOpts {
  /** Clock-skew window (in counter steps), like signet-me's `SIGNET_ME_TOLERANCE`. Default `0` (exact
   *  match only). Tolerance `t` accepts `spoken` if it equals the counterparty's word at ANY counter in
   *  `[counter - t, counter + t]`, the window CLAMPED to the valid uint32 counter range `[0, 0xFFFFFFFF]`
   *  (so a boundary `counter` never feeds spoken-token an out-of-range counter). `t` is itself coerced to
   *  an integer in `[0, MAX_BOND_TOLERANCE]` (= 10): negative/NaN → `0`, larger → `10`. Each candidate is
   *  constant-time-compared; the boolean is the OR of those compares, so timing does not leak WHICH
   *  counter matched beyond the verdict itself. */
  tolerance?: number
}

/**
 * Verify the counterparty's spoken word for a given counter, in (best-effort) constant time.
 *
 * Re-derives the EXPECTED counterparty word via `bondWords` (which uses `deriveDirectionalPair`,
 * deterministically — NOT a tolerance-window `verifyToken`) and constant-time-compares it to what was
 * `spoken`. A constant-time compare avoids leaking, via early-exit timing, how many leading characters
 * of a guessed word were correct.
 *
 * **Tolerance window (`opts.tolerance`).** Like signet-me's ±tolerance clock-skew window: with `t > 0`,
 * `spoken` is accepted if it matches the counterparty's word at ANY counter in `[counter-t, counter+t]`.
 * Every candidate counter is checked with a constant-time compare and the results OR-accumulated WITHOUT
 * early-return, so the timing does not leak which counter matched beyond the final boolean.
 *
 * **Fail-soft window clamping (the `{ok}` contract — this function MUST NOT throw on a valid-shaped
 * call).** Two clamps keep it total: (1) `tolerance` is coerced to an integer in `[0, MAX_BOND_TOLERANCE]`
 * (negative/NaN → `0`, larger → `10`), so a bogus dev arg can't drive an unbounded loop; (2) the candidate
 * counter range is clamped to the valid uint32 span `[0, 0xFFFFFFFF]`. Without (2) a boundary `counter`
 * (e.g. `counter = 0, tolerance = 1` → `-1`, or `counter = 0xFFFFFFFF, tolerance = 1` → `0x100000000`)
 * would feed spoken-token's `counterBe32` an out-of-range value and throw a `RangeError` — breaking the
 * `{ok}` contract. The clamp simply skips the out-of-range counters; the in-range ones are still checked.
 *
 * **signet-me compatibility.** Pass `{ namespace: 'signet:me', tolerance: N }` to verify against the
 * words signet-app's `signet-me` would produce (for an un-migrated peer).
 *
 * @param secretHex - The bond secret (hex).
 * @param aPubHex   - Caller's own persona pubkey (64 hex); selects which role's token is "mine."
 * @param bPubHex   - Counterparty pubkey (64 hex).
 * @param counter   - The rotation counter both seats agreed on for this exchange (the window centre).
 * @param spoken    - The word the counterparty actually said.
 * @param opts      - Optional `{ namespace?, tolerance? }` — additive, defaults reproduce the existing
 *                    behaviour (`'kindred:bond'`, exact-counter `tolerance: 0`).
 * **Pubkey / namespace problems are a verdict, not a throw.** A self-bond (`aPubHex === bPubHex`, e.g.
 * a handshake that echoed my own pubkey back), a malformed pubkey or an empty namespace returns
 * `{ ok: false }`: no spoken word can verify such a bond. A malformed SECRET still throws — it is a
 * programmer error (the value `deriveBondSecret` returns is always well-formed).
 *
 * **Guessing odds (see SECURITY.md).** A word is one of 2048 (11 bits). Tolerance `t` accepts `2t+1`
 * candidate words, so a blind guess succeeds with probability about `(2t+1)/2048`: ≈0.05% at `t=0`,
 * ≈0.15% at `t=1`, ≈1% at `t=10`. There is no rate limit here; the protection is the human in the loop.
 *
 * @returns `{ ok: true }` iff `spoken` equals the expected counterparty word (within tolerance), else
 *          `{ ok: false }`. Never throws on a well-formed secret.
 */
export function verifyBondWord(
  secretHex: string,
  aPubHex: string,
  bPubHex: string,
  counter: number,
  spoken: string,
  opts?: VerifyBondWordOpts,
): { ok: boolean } {
  if (typeof secretHex !== 'string' || !/^[0-9a-f]{64}$/i.test(secretHex)) {
    throw new Error('bondWords: secret must be 64 hex chars')
  }
  // Fail-soft on the non-secret inputs: a self-bond / bad pubkey / empty namespace is `{ ok: false }`.
  try {
    bondWordsInputs(aPubHex, bPubHex, opts)
  } catch {
    return { ok: false }
  }
  const tolerance = clampTolerance(opts?.tolerance)
  const wordOpts: BondWordsOpts = { namespace: opts?.namespace }
  // Clamp the candidate counter window to the valid uint32 range so a boundary `counter` never feeds
  // spoken-token's `counterBe32` an out-of-range value (which would throw, breaking the {ok} contract).
  // `counter` may itself be fractional/out-of-range (dev arg); `Math.trunc` + the clamp keep `lo`/`hi`
  // as integers in [0, 0xFFFFFFFF]. If `counter` is wholly outside the range, `lo > hi` and the loop is a
  // no-op → `{ ok: false }` (no spoken word can match a counter that doesn't exist) — still fail-soft.
  const centre = Number.isFinite(counter) ? Math.trunc(counter) : 0
  const lo = Math.max(0, centre - tolerance)
  const hi = Math.min(0xffffffff, centre + tolerance)
  // Accumulate an OR of constant-time compares across the clamped window WITHOUT early-return, so timing
  // can't leak which counter (if any) matched beyond the final boolean. The window is small (a clock-skew
  // window, ≤ 2·MAX_BOND_TOLERANCE+1 candidates), so the loop is bounded regardless of caller input.
  let matched = false
  for (let c = lo; c <= hi; c++) {
    const theirs = bondWords(secretHex, aPubHex, bPubHex, c, wordOpts).theirs
    matched = timingSafeStringEqual(theirs, spoken) || matched
  }
  return { ok: matched }
}

/**
 * Build the unsigned kind-31000 attestation EventTemplate for a (consensual, co-signed) bond record.
 *
 * Uses `type: 'kindred-bond'` — the literal `'assertion'` is RESERVED by nostr-attestations and would
 * throw. `subject` is the counterparty's pubkey, which nostr-attestations renders as the `p` tag (and
 * folds into the addressable `d` tag). The caller signs the returned template (adds pubkey/id/sig/
 * created_at) before publishing, then records the resulting event id as the `BondAssertion.mineId`.
 *
 * `createAttestation` returns nostr-attestations' own template shape (`created_at?` optional); we
 * stamp `created_at` here so the result satisfies kenspeckle's canonical `EventTemplate` (re-exported
 * from nostr-tools, where `created_at` is REQUIRED — the "ONE event type" invariant from K-1). The
 * stamped value is a normal nostr build-time timestamp; a caller may still override it before signing
 * (`finalizeEvent` sets its own if needed).
 *
 * @param p.subjectPubHex - Counterparty pubkey (must be 64-char lowercase hex; nostr-attestations
 *                          rejects otherwise). The "who I am bonding with" subject of the attestation.
 * @param p.summary       - Optional human-readable fallback (rendered as a `summary` tag).
 * @returns An unsigned kind-31000 `EventTemplate` with a build-time `created_at`.
 */
export function buildBondAttestation(p: { subjectPubHex: string; summary?: string }): EventTemplate {
  const template = createAttestation({
    type: 'kindred-bond',
    subject: p.subjectPubHex,
    summary: p.summary,
  })
  return { ...template, created_at: template.created_at ?? Math.floor(Date.now() / 1000) }
}

/**
 * Build the unsigned kind-31000 REVOCATION of a bond attestation — the PRIMARY way to retract one.
 *
 * Uses nostr-attestations' own `createRevocation({ type:'kindred-bond', identifier: subject, subject })`,
 * which republishes the SAME addressable slot (`d = kindred-bond:<subject>`) with `["status","revoked"]`.
 * Because kind 31000 is addressable, the revocation REPLACES the attestation on every relay that
 * honours replaceable semantics, and `verifyBondAttestation` rejects it with `reason: 'revoked'`. Unlike
 * a NIP-09 deletion this is a positive, signed statement a verifier can see, not a request to forget.
 * The caller signs it with the SAME key that signed the attestation.
 *
 * @param p.subjectPubHex - The counterparty pubkey the attestation was about (64-hex; lowercased here).
 * @param p.reason        - Optional human-readable reason (rendered as a `reason` tag).
 * @returns An unsigned kind-31000 `EventTemplate` with a build-time `created_at`.
 * @throws If `subjectPubHex` is not 64-hex.
 */
export function buildBondRevocation(p: { subjectPubHex: string; reason?: string }): EventTemplate {
  if (typeof p.subjectPubHex !== 'string' || !HEX64_LOWER.test(p.subjectPubHex.toLowerCase())) {
    throw new Error('buildBondRevocation: subjectPubHex must be 64 hex chars')
  }
  const subject = p.subjectPubHex.toLowerCase()
  const template = createRevocation({ type: 'kindred-bond', identifier: subject, subject, reason: p.reason })
  return { ...template, created_at: template.created_at ?? Math.floor(Date.now() / 1000) }
}

/**
 * Build the unsigned NIP-09 (kind-5) deletion request that SUPPLEMENTS `buildBondRevocation`.
 *
 * Publish the revocation first; this asks relays to also drop the old attestation. It references it
 * three ways, as NIP-09 asks for an addressable event: `["e", mineId]` (the specific version),
 * `["a", "31000:<attester>:kindred-bond:<subject>"]` (every version at that address up to this
 * request's `created_at`) and `["k", "31000"]`. An `e` tag alone deletes one version and leaves a
 * republished one standing. NIP-09 is a request — a retraction can never be cryptographically
 * guaranteed network-wide, which is why the revocation is the primary mechanism. The caller signs this
 * with the SAME key that signed the original (only the author may delete their event).
 *
 * @param assertion - The local bond record; `assertion.mineId` (64-hex event id) is the version to drop.
 * @param address   - `attesterPubHex` (the signer of the attestation) and `subjectPubHex`, both 64-hex.
 * @returns An unsigned kind-5 `EventTemplate` with `e`, `a` and `k` tags.
 * @throws If `mineId` or either pubkey is not 64-hex.
 */
export function retractBondAssertion(
  assertion: BondAssertion,
  address: { attesterPubHex: string; subjectPubHex: string },
): EventTemplate {
  const mineId = typeof assertion?.mineId === 'string' ? assertion.mineId.toLowerCase() : ''
  if (!HEX64_LOWER.test(mineId)) throw new Error('retractBondAssertion: mineId must be a 64-hex event id')
  const attester = typeof address?.attesterPubHex === 'string' ? address.attesterPubHex.toLowerCase() : ''
  const subject = typeof address?.subjectPubHex === 'string' ? address.subjectPubHex.toLowerCase() : ''
  if (!HEX64_LOWER.test(attester)) throw new Error('retractBondAssertion: attesterPubHex must be 64 hex chars')
  if (!HEX64_LOWER.test(subject)) throw new Error('retractBondAssertion: subjectPubHex must be 64 hex chars')
  return {
    kind: 5,
    tags: [
      ['e', mineId],
      ['a', `${BOND_ATTESTATION_KIND}:${attester}:kindred-bond:${subject}`],
      ['k', String(BOND_ATTESTATION_KIND)],
    ],
    content: '',
    created_at: Math.floor(Date.now() / 1000),
  }
}

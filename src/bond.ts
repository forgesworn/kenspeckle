// kindred (`./bond` subpath) — the migration-critical bond ceremony (spec §5.2, §5.4, §5.5, §5.6).
//
// A "bond" is a kith relationship: two personas mutually verify each other out-of-band by speaking
// short, time-rotating words derived from a shared ECDH secret (spoken-token). This file is the
// MIGRATION-CRITICAL surface: `deriveBondSecret` MUST reproduce signet-protocol's ECDH construction
// byte-for-byte, or every contact migrated from signet-app gets a different secret → different words
// → broken verification for both parties. The frozen vector in bond.test.ts is the regression gate.
//
// This is a STANDALONE subpath entry (`import { ... } from 'kindred/bond'`); it is deliberately NOT
// re-exported from the `.` barrel. It works entirely with hex strings + @noble + spoken-token +
// nostr-attestations — no TextEncoder/fetch, no model dependency, no console output anywhere.

import { secp256k1 } from '@noble/curves/secp256k1.js'
import { sha256 } from '@noble/hashes/sha2.js'
import { bytesToHex, hexToBytes } from '@noble/hashes/utils.js'
import { deriveDirectionalPair } from 'spoken-token'
import { timingSafeStringEqual } from 'spoken-token/crypto'
import { createAttestation } from 'nostr-attestations'
import type { EventTemplate, BondAssertion } from './types.js'

// `secp256k1.Point` is the v2 Weierstrass point class. `Point.Fn` is the scalar field; `.ORDER` is
// the curve order N (confirmed the right v2 accessor against the sibling repo `range-proof`, which
// does `export const N = secp256k1.Point.Fn.ORDER`).
const Point = secp256k1.Point

/** Domain-separation namespace for the spoken-token directional pair. Distinct from any other
 *  spoken-token use so a bond word can never collide with (or be replayed as) another ceremony. */
export const KINDRED_BOND_NAMESPACE = 'kindred:bond'

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
 * **Zeroization contract (see PROTOCOL.md):** we zeroize the `privBytes` copy in a `finally`. We do
 * NOT — and CANNOT — wipe the `scalar` (`bigint`s are immutable in JS; there is no in-place clear)
 * nor the intermediate ECDH point's internal limbs. State this honestly: a future Rust/WASM port
 * MUST zeroize the scalar and the point. This JS implementation is best-effort on the byte copy only.
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

  // Best-effort zeroization target (the only material we CAN wipe — the bigint scalar can't be).
  const privBytes = hexToBytes(priv)
  try {
    const xHex = theirPoint.multiply(scalar).toAffine().x.toString(16).padStart(64, '0')
    return bytesToHex(sha256(hexToBytes(xHex)))
  } finally {
    privBytes.fill(0) // best-effort; see zeroization contract above + PROTOCOL.md
  }
}

/** Options for `bondWords` — additive + backward-compatible (all default to the existing behaviour).
 *
 *  These exist for ONE reason: signet-me compatibility during the signet-app migration rollout (see
 *  PROTOCOL.md §2.1). signet-app's `signet-me` derives words with namespace `'signet:me'` and
 *  caller-order roles `[myPub, theirPub]`. A migrated contact whose peer has NOT yet migrated must be
 *  able to reproduce signet-me's exact words to cross-verify, so `bondWords` can be steered to match it.
 *
 *  EMPIRICAL NOTE (verified against the installed `spoken-token`): `deriveDirectionalPair` keys each
 *  word on `namespace + '\0' + role` — i.e. on the role STRING, independent of its POSITION in the
 *  tuple. So **`namespace` is the load-bearing knob** (it changes the words); **`roleOrder` does NOT
 *  change `bondWords`'s output** for a fixed arg order (sorted vs caller give the same `mine`/`theirs`,
 *  because `mine = pair[aPubHex]` regardless of tuple order). `roleOrder` is retained as an explicit,
 *  additive INTENT knob — and a guard, should a future role-derivation ever become position-sensitive.
 *  For this spoken-token, signet-me compat is reproduced by `{ namespace: 'signet:me' }` alone.
 *
 *  With DEFAULT opts the words DIFFER from signet-me (kindred uses `'kindred:bond'`), so a naive
 *  migration changes the words — both peers must upgrade together OR pass the signet-me `namespace`. */
export interface BondWordsOpts {
  /** Domain-separation namespace fed to `deriveDirectionalPair`. Default `KINDRED_BOND_NAMESPACE`
   *  (`'kindred:bond'`). Pass `'signet:me'` to reproduce signet-app's `signet-me` words. This is the
   *  knob that actually changes the derived words. */
  namespace?: string
  /** How the two role tokens are ordered in the tuple passed to `deriveDirectionalPair`. `'sorted'`
   *  (default) uses `[lo, hi]` = `sort([a,b])`; `'caller'` uses `[aPubHex, bPubHex]` VERBATIM (so
   *  `aPubHex` is the FIRST role), matching `signet-me`'s `[myPubkey, theirPubkey]` assignment. Because
   *  spoken-token keys words per-role-string (not per-index), this choice does NOT change the output
   *  words for the installed spoken-token — it is an explicit intent/forward-compat knob (see above). */
  roleOrder?: 'sorted' | 'caller'
}

/** Compute the directional role-token tuple for a (a,b) pubkey pair under the given ordering. With
 *  `'sorted'`, both seats derive the same `[lo, hi]` regardless of which pubkey they passed first (the
 *  default kindred behaviour). With `'caller'`, the caller's args are used VERBATIM — so `a` is always
 *  the FIRST role (matching signet-me's `[myPubkey, theirPubkey]`). NOTE: because `deriveDirectionalPair`
 *  keys each word on the role STRING (not its tuple index), the two orderings yield the SAME per-pubkey
 *  word — the order affects only the tuple shape, not `bondWords`'s output (see `BondWordsOpts`). Built
 *  as an explicit 2-tuple (not array-destructured) so the `[string, string]` shape survives
 *  `noUncheckedIndexedAccess`. */
function bondRoles(a: string, b: string, roleOrder: 'sorted' | 'caller'): [string, string] {
  if (roleOrder === 'caller') return [a, b]
  return a < b ? [a, b] : [b, a]
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
 * **signet-me compatibility (`opts`).** Pass `{ namespace: 'signet:me', roleOrder: 'caller' }` to
 * reproduce signet-app's `signet-me` words byte-for-byte (so a migrated contact can cross-verify with a
 * peer who has NOT yet migrated). With DEFAULT opts the words differ from signet-me — see `BondWordsOpts`.
 *
 * @param secretHex - The bond secret (hex; interpreted as bytes, ≥16 — our 32-byte secret is fine).
 * @param aPubHex   - Caller's own persona pubkey (64 hex; case-insensitive). With `roleOrder:'caller'`
 *                    this is the "my" role (signet-me's `myPubkey`).
 * @param bPubHex   - Counterparty pubkey (64 hex; case-insensitive).
 * @param counter   - Rotation counter (uint32) — words change as it advances.
 * @param opts      - Optional `{ namespace?, roleOrder? }` — additive, defaults reproduce the existing
 *                    behaviour (`'kindred:bond'` + `'sorted'`).
 * @returns `{ mine, theirs }` — the word I speak and the word I expect from the counterparty.
 */
export function bondWords(
  secretHex: string,
  aPubHex: string,
  bPubHex: string,
  counter: number,
  opts?: BondWordsOpts,
): { mine: string; theirs: string } {
  const a = aPubHex.toLowerCase(),
    b = bPubHex.toLowerCase()
  const namespace = opts?.namespace ?? KINDRED_BOND_NAMESPACE
  const roles = bondRoles(a, b, opts?.roleOrder ?? 'sorted')
  const pair = deriveDirectionalPair(secretHex, namespace, roles, counter)
  // a and b are each exactly one of the two role tokens, so these lookups always resolve.
  return { mine: pair[a]!, theirs: pair[b]! }
}

/** Options for `verifyBondWord` — a superset of `BondWordsOpts` adding a clock-skew `tolerance` window.
 *  `namespace`/`roleOrder` carry the same signet-me-compat meaning as on `bondWords`. */
export interface VerifyBondWordOpts extends BondWordsOpts {
  /** Clock-skew window (in counter steps), like signet-me's `SIGNET_ME_TOLERANCE`. Default `0` (exact
   *  match only). Tolerance `t` accepts `spoken` if it equals the counterparty's word at ANY counter in
   *  `[counter - t, counter + t]`. Each candidate is constant-time-compared; the boolean is the OR of
   *  those compares, so timing does not leak WHICH counter matched beyond the verdict itself. */
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
 * **signet-me compatibility.** Pass `{ namespace: 'signet:me', roleOrder: 'caller', tolerance: N }` to
 * verify against the words signet-app's `signet-me` would produce (for an un-migrated peer).
 *
 * @param secretHex - The bond secret (hex).
 * @param aPubHex   - Caller's own persona pubkey (64 hex). With `roleOrder:'caller'`, the "my" role.
 * @param bPubHex   - Counterparty pubkey (64 hex).
 * @param counter   - The rotation counter both seats agreed on for this exchange (the window centre).
 * @param spoken    - The word the counterparty actually said.
 * @param opts      - Optional `{ namespace?, roleOrder?, tolerance? }` — additive, defaults reproduce the
 *                    existing behaviour (`'kindred:bond'`, `'sorted'`, exact-counter `tolerance: 0`).
 * @returns `{ ok: true }` iff `spoken` equals the expected counterparty word (within tolerance), else
 *          `{ ok: false }`.
 */
export function verifyBondWord(
  secretHex: string,
  aPubHex: string,
  bPubHex: string,
  counter: number,
  spoken: string,
  opts?: VerifyBondWordOpts,
): { ok: boolean } {
  const tolerance = opts?.tolerance ?? 0
  const wordOpts: BondWordsOpts = { namespace: opts?.namespace, roleOrder: opts?.roleOrder }
  // Accumulate an OR of constant-time compares across the full [counter-t, counter+t] window WITHOUT
  // early-return, so timing can't leak which counter (if any) matched beyond the final boolean. `t` is
  // small (a clock-skew window); the loop always runs the same number of compares for a given tolerance.
  let matched = false
  for (let offset = -tolerance; offset <= tolerance; offset++) {
    const theirs = bondWords(secretHex, aPubHex, bPubHex, counter + offset, wordOpts).theirs
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
 * stamp `created_at` here so the result satisfies kindred's canonical `EventTemplate` (re-exported
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
 * Build the unsigned NIP-09 (kind-5) deletion request that retracts a previously-published bond
 * attestation, referencing the original by its event id.
 *
 * Per NIP-09 the deletion is a request — relays and clients SHOULD drop the referenced event, but a
 * retraction can never be cryptographically guaranteed network-wide. The caller signs this template
 * with the SAME key that signed the original attestation (only the author may delete their event).
 *
 * @param assertion - The local bond record; `assertion.mineId` is the id of the event to retract.
 * @returns An unsigned kind-5 `EventTemplate` with an `e` tag referencing `assertion.mineId`.
 */
export function retractBondAssertion(assertion: BondAssertion): EventTemplate {
  return {
    kind: 5,
    tags: [['e', assertion.mineId]],
    content: '',
    created_at: Math.floor(Date.now() / 1000),
  }
}

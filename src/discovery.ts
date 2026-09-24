// kenspeckle ./discovery — local presence intersection over a sibling `tessera-kit` membership filter,
// plus signed Nostr filter publications (kind 30444) and the opt-out request (kind 30445).
//
// Spec: signet-plans/docs/plans/2026-06-02-kenspeckle-primitive-spec.md §8 (discovery) + §11 (opt-out).
// Publication shape matches tessera-kit PROTOCOL.md §6 byte-for-byte (kind 30444, d-tag
// `kindred:members:<namespace>:<serverId>`, indexable `['n', namespace]` tag, base64-of-KFLT-blob
// content). The `namespace` is reverse-DNS-style and MUST be colon-free (the d-tag splits on the
// first colon after the prefix to recover `<namespace>` vs `<serverId>`); `serverId` MAY contain
// colons (it is the remainder). The Nostr event signature (NIP-01) and the in-blob Schnorr provenance
// signature (§4) are DISTINCT; `parseFilterPublication` verifies BOTH before returning anything
// trustable. The base64 publication mechanics are delegated to tessera-kit's generic `./nostr`
// builder/decoder so the wire-format lives in ONE place (kenspeckle supplies only its kind + tags).
//
// This layer holds no state, opens no sockets, and never enumerates a server's membership — it only
// tests the consumer's OWN contacts against a published filter (presence, not a member list).
//
// tessera-kit 0.2.0: every filter-blob signature is now bound to a caller-supplied `context` string
// (PROTOCOL.md §4.1/§4.3/§6). For the kindred convention, `context` IS the d-tag value
// (`kindred:members:<namespace>:<serverId>`) — see `filterSignatureContext`. The verifier MUST build
// `context` from the `(namespace, serverId)` it CHOSE to fetch, NEVER from the received event's own
// `d`-tag — `parseFilterPublicationResult`/`parseFilterPublication` now take `opts.namespace` /
// `opts.serverId` (REQUIRED) for exactly this reason, and separately check the event's own d-tag
// matches (`'address-mismatch'`) rather than trusting it as the context source. Every tessera-kit
// throw is now a `TesseraError` with a stable `code` (never matched on `.message` here).

import {
  parseFilter,
  testMembership,
  memberKey,
  verifyFilterBlob,
  TesseraError,
  type MembershipFilter,
} from '@forgesworn/tessera-kit'
// Publication MECHANICS (base64 assembly + length-capped decode) are delegated to tessera-kit's
// relationship-agnostic `./nostr` core, so the wire-format lives in ONE place. kenspeckle still owns the
// kind + d/n/epoch/keyed tags and passes them in. Aliased to avoid clashing with kenspeckle's own
// `buildFilterPublication` (the kenspeckle-specific wrapper exported from this module).
import { buildFilterPublication as buildPublicationTemplate, decodeFilterPublicationContent } from '@forgesworn/tessera-kit/nostr'
import { verifyEvent } from 'nostr-tools/pure'
import { schnorr } from '@noble/curves/secp256k1.js'
import { bytesToHex, hexToBytes } from '@noble/hashes/utils.js'
import type { KindredEntry, EventTemplate, NostrEvent, NostrFilter } from './types.js'

// `parseFilter` is re-exported only so callers can `import { parseFilter } from 'kenspeckle/discovery'`
// without reaching past kenspeckle into tessera-kit; kenspeckle's own functions take a parsed filter.
export { parseFilter }

/** Addressable Nostr kind for a published membership filter (provisional; not NIP-registered).
 *  MUST equal tessera-kit PROTOCOL.md §6's `30444` — the publication shape is shared. */
export const KINDRED_FILTER_KIND = 30444
/** Addressable Nostr kind for a member's opt-out request (provisional; not NIP-registered). */
export const KINDRED_OPTOUT_KIND = 30445

/** d-tag prefix for the addressable filter publication / opt-out (`<prefix><namespace>:<serverId>`). */
const D_TAG_PREFIX = 'kindred:members:'

const HEX64 = /^[0-9a-f]{64}$/

/** tessera-kit's hostile-input blob cap (KFLT_MAX_BLOB_BYTES = 64 MiB). Mirrored here so a hostile
 *  publication can be rejected BEFORE base64-decoding an oversized payload into memory. */
const MAX_BLOB_BYTES = 64 * 1024 * 1024

/** Current unix time in whole seconds (the kenspeckle event `created_at` convention). */
function nowSec(): number {
  return Math.floor(Date.now() / 1000)
}

/** The shared `<prefix><namespace>:<serverId>` construction — the ONE place the d-tag value / filter
 *  signature context is built, so `buildFilterPublication`'s d-tag, `buildOptOutRequest`'s d-tag, and
 *  `filterSignatureContext`'s context string can never drift apart from one another. */
function dTagValue(namespace: string, serverId: string): string {
  return `${D_TAG_PREFIX}${namespace}:${serverId}`
}

/**
 * The kindred convention's filter-signature CONTEXT string (tessera-kit PROTOCOL.md §4.1/§4.3/§6,
 * CHANGELOG [0.2.0]) — identical to the d-tag value, `kindred:members:<namespace>:<serverId>`.
 * tessera-kit 0.2.0 binds every filter-blob signature (`signFilterBlob`/`verifyFilterBlob`/
 * `verifyAndParseFilter`) to a caller-supplied `context`; for the kindred convention that context IS
 * the d-tag value, built here from the SAME `dTagValue` construction `buildFilterPublication` uses
 * for the actual d-tag, so the two can never disagree.
 *
 * ⚠️ **SECURITY — build `context` from the `(namespace, serverId)` you CHOSE to fetch, NEVER from a
 * received event's own `d`-tag.** A relay or MITM controls every tag on the event it serves; trusting
 * the tag would let it relabel a substituted blob and have the context check pass trivially (see
 * tessera-kit PROTOCOL.md §4.3's ⚠️ warning). `parseFilterPublicationResult`/`parseFilterPublication`
 * do this correctly: they build `context` from `opts.namespace`/`opts.serverId` (the caller's own
 * prior knowledge of what it asked for) and separately check the event's OWN d-tag matches it
 * (`FilterPublicationRejection`'s `'address-mismatch'`), rather than trusting the tag as the context
 * source.
 */
export function filterSignatureContext(namespace: string, serverId: string): string {
  return dTagValue(namespace, serverId)
}

/**
 * Local presence intersection (spec §4 persona-scoping + §8.1).
 *
 * Returns the subset of `entries` whose `pubkey` tests present in the server filter `f`. For a keyed
 * pool, pass the out-of-band `saltHex` the pool was built with (the salt is never in the blob — see
 * tessera-kit PROTOCOL.md §1); omit it for an open pool.
 *
 * PERSONA SCOPING (anti-correlation): every entry MUST share the same `ownerPubkey` as the declared
 * `ownerPubkey` (case-insensitive). Mixing entries scoped to different personas into one discovery
 * call would let a server correlate two of the caller's personas via a single presence query, so a
 * mixed-persona input is a bug and is REJECTED (throws) rather than silently filtered.
 *
 * KEYED-WITHOUT-SALT GUARD: a keyed filter tests `sha256(salt||pubkey)`, so calling it with no salt
 * would test the OPEN-form `memberKey` and silently return `[]` ("nobody you know is here"). The
 * filter KNOWS it is keyed (`f.keyed`), so that wrong-but-quiet answer is a doxxing-adjacent footgun
 * (the caller may act on a false "no friends present"). It THROWS instead, demanding the salt.
 *
 * OPEN-WITH-SALT GUARD (M3 audit finding): the mirror-image footgun. An OPEN filter tests the raw
 * pubkey (`memberKey` with no salt); passing a salt anyway hashes every candidate as if the pool
 * were keyed, so NOTHING matches and this silently returns `[]` — the same false "no friends here"
 * as the keyed-without-salt case, e.g. when a salt left over from a different (keyed) pool in app
 * state gets reused here. It THROWS instead of guessing which the caller meant.
 *
 * NO local truncation: every matching entry is returned (`KindredEntry[]` per spec §8.1). The
 * `{truncated}` flag the spec mentions elsewhere is an aggregator concern (deferred §8.4), not this
 * local layer's.
 */
export function discoverPresent(
  f: MembershipFilter,
  entries: KindredEntry[],
  ownerPubkey: string,
  saltHex?: string,
): KindredEntry[] {
  const owner = ownerPubkey.toLowerCase()
  for (const e of entries) {
    if (e.ownerPubkey.toLowerCase() !== owner) {
      throw new Error('discoverPresent: mixed-persona input — all entries must share ownerPubkey')
    }
  }
  // Fail loud, not silent: a keyed filter without its salt can only produce a misleading empty result.
  if (f.keyed && saltHex === undefined) {
    throw new Error('discoverPresent: filter is keyed but no salt was provided — pass the keyed-pool salt')
  }
  // EMPTY-SALT GUARD (tessera-kit 0.2.0): `memberKey`/`buildMembershipFilter` now reject an
  // empty-string salt outright (an empty salt gives away nothing an open pool wouldn't — see
  // tessera-kit CHANGELOG [0.2.0]). Catch it here, before tessera-kit is ever called, in the same
  // fail-loud style as the keyed-without-salt / open-with-salt guards around it, rather than letting
  // a raw tessera-kit `TesseraError` (`INPUT_SALT_INVALID`) surface from `memberKey` below.
  if (f.keyed && saltHex === '') {
    throw new Error('discoverPresent: filter is keyed but an empty-string salt was provided — pass the keyed-pool salt')
  }
  // Mirror-image guard (M3): an open filter given a salt anyway would hash every candidate and
  // silently match nothing — equally misleading as the keyed-without-salt case above.
  if (!f.keyed && saltHex !== undefined) {
    throw new Error('discoverPresent: filter is open (unkeyed) but a salt was provided — omit the salt')
  }
  return entries.filter((e) => testMembership(f, memberKey(e.pubkey, saltHex)))
}

/** Honest disclosure of what discovery participation actually exposes (spec §8 + §10). */
export interface DiscoveryDisclosure {
  /** Pool values were salted (the salt is shared out-of-band; not in the blob). */
  keyed: boolean
  /** Whether an INCLUDED member is locatable across many servers from the published filter alone.
   *  An OPEN pool tests the raw pubkey, so anyone holding a candidate pubkey can locate that member
   *  in any open pool that contains them (cross-server). A KEYED pool tests `sha256(salt||pubkey)`,
   *  so without the salt the same member is NOT cross-server locatable. */
  crossServerDiscoverable: boolean
  /** Discovery is always opt-in (a server only lists members who consented to be tested). */
  optIn: true
  /** A member can always REQUEST removal (`buildOptOutRequest`); honoured on the next rebuild. This
   *  is unconditionally `true` — see `buildOptOutRequest`'s doc comment for the honest limitation
   *  (requestable, never cryptographically confirmable). Typed as the literal `true`, not `boolean`
   *  (L6 audit finding): nothing in this module can ever compute `false` here, so the wider type
   *  only invited a caller to imagine a case that doesn't exist. */
  canExit: true
}

/**
 * Compute the disclosure surface for a pool FROM THE PARSED FILTER — not from a bare `{salt}`
 * (L6 audit finding). The previous signature took `{ salt?: string }` and derived `keyed` from
 * salt PRESENCE; that is a second, independent source of truth for the same fact `f.keyed` already
 * carries (authoritatively, from the signed blob header), and the two can disagree — e.g. a caller
 * that has the pool's salt on hand for an unrelated reason but is describing an OPEN filter would
 * get `keyed:true` back, mis-describing the actual pool. Deriving `keyed` from `f.keyed` directly
 * makes disagreement structurally impossible.
 */
export function disclosureFor(f: MembershipFilter): DiscoveryDisclosure {
  return {
    keyed: f.keyed,
    // Open (unsalted) pools test the raw pubkey, so an included member is locatable across every
    // open pool that holds them. Keyed pools hide that without the out-of-band salt.
    crossServerDiscoverable: !f.keyed,
    optIn: true,
    canExit: true,
  }
}

/**
 * Build the addressable Nostr publication (kind 30444) carrying a server's KFLT filter blob. Returns
 * an UNSIGNED `EventTemplate` — the publisher's Nostr key signs it (separate from the in-blob Schnorr
 * provenance key). Shape matches tessera-kit PROTOCOL.md §6 exactly so a tessera-kit-only server can
 * emit an identical event.
 *
 * - d-tag `kindred:members:<namespace>:<serverId>` is the addressable identity (one filter per
 *   `(namespace, serverId)`; a newer epoch replaces the older addressable event). `namespace` is
 *   reverse-DNS-style and MUST be **colon-free** — a colon would shift the `<namespace>:<serverId>`
 *   boundary `parseFilterPublication` splits on (the first colon after the prefix), mis-parsing the
 *   two fields. (serverId MAY contain colons — it is the unambiguous remainder, e.g. a
 *   `wss://host:port/path` URL.) tessera-kit's capability already guards its own serverId this way;
 *   this mirrors it for kenspeckle's namespace.
 * - `['n', namespace]` is the single-letter relay-indexable tag the aggregator queries (`#n`).
 *
 * The base64-of-blob CONTENT and `EventTemplate` assembly are delegated to tessera-kit's generic
 * `./nostr` publisher (`buildPublicationTemplate`) so the wire mechanics live in ONE place; kenspeckle
 * supplies only its kind + tags. Output is byte-identical to the previous hand-rolled form.
 *
 * `p.blob` MUST already be a SIGNED KFLT blob (`signFilterBlob`), signed with `context =
 * filterSignatureContext(p.namespace, p.serverId)` (tessera-kit 0.2.0). This function verifies that
 * itself — `verifyFilterBlob(p.blob, filterSignatureContext(p.namespace, p.serverId))` — and THROWS a
 * clear kenspeckle error if it doesn't verify, so a blob signed for the wrong context (a different
 * server/namespace, or an unsigned blob) is caught here, before ever publishing it, rather than
 * silently shipping an event no consumer's `parseFilterPublicationResult` will ever accept.
 */
export function buildFilterPublication(p: {
  namespace: string
  serverId: string
  blob: Uint8Array
  keyed: boolean
  epoch: number
}): EventTemplate {
  // d-tag misparse guard: a colon in the namespace would corrupt the addressable identity boundary.
  if (p.namespace.includes(':')) {
    throw new Error('buildFilterPublication: namespace must not contain a colon')
  }
  const context = filterSignatureContext(p.namespace, p.serverId)
  const { ok } = verifyFilterBlob(p.blob, context)
  if (!ok) {
    throw new Error(
      `buildFilterPublication: blob does not verify for context "${context}" — it must be signed ` +
        '(signFilterBlob) for THIS namespace/serverId; a blob signed for a different deployment, or ' +
        'an unsigned/tampered blob, will not verify here',
    )
  }
  return buildPublicationTemplate({
    kind: KINDRED_FILTER_KIND,
    tags: [
      ['d', dTagValue(p.namespace, p.serverId)],
      ['n', p.namespace],
      ['epoch', String(p.epoch)],
      ['keyed', p.keyed ? '1' : '0'],
    ],
    blob: p.blob,
    createdAt: nowSec(),
  })
}

/** Parsed, trust-checked filter publication. `signerPubkeyHex` is the IN-BLOB Schnorr signer (the
 *  server's provenance key) — NOT the Nostr event author. The consumer MUST compare it against a
 *  pinned / out-of-band-known server key before trusting any membership result (§10 invariant 5);
 *  `parseFilterPublication` only proves the signature is internally consistent. */
export interface FilterPublication {
  namespace: string
  serverId: string
  blob: Uint8Array
  keyed: boolean
  epoch: number
  signerPubkeyHex: string
}

/** `namespace`/`serverId` the caller asked for, plus the optional freshness/trust-model knobs.
 *  REQUIRED as of tessera-kit 0.2.0 (a BREAKING change — see CHANGELOG): `context` for the in-blob
 *  signature check (tessera-kit PROTOCOL.md §4.1/§4.3) MUST be built from the `(namespace, serverId)`
 *  the verifier itself chose to fetch, NEVER from the received event's own `d`-tag — see
 *  `filterSignatureContext`'s doc comment for why. Passing `opts` used to be optional (both fields
 *  defaulted to being read off the event); it no longer is. */
export interface ParseFilterPublicationOpts {
  namespace: string
  serverId: string
  minEpoch?: number
  requireAuthorIsSigner?: boolean
}

/** Why `parseFilterPublicationResult` rejected an event — one code per internal `return { ok: false }`
 *  path, in the SAME order `parseFilterPublication`'s doc comment numbers its checks:
 *   1. `invalid-opts`              — `opts.namespace`/`opts.serverId` is missing, not a non-empty
 *                                    string, or (rare) produces a `context` tessera-kit itself rejects
 *                                    as malformed (not well-formed UTF-16, or over 1024 UTF-8 bytes).
 *                                    A caller-configuration problem, but this function never throws.
 *   2. `bad-signature`             — the Nostr event signature is invalid (`verifyEvent`).
 *   3. `wrong-kind`                — `event.kind !== KINDRED_FILTER_KIND`.
 *   4. `bad-content`               — `event.content` is not a string.
 *   5. `bad-blob`                  — the base64 content is undecodable, or the blob exceeds
 *                                    tessera-kit's 64 MiB cap.
 *   6. `address-mismatch`          — the event's `d`-tag does not EXACTLY equal
 *                                    `filterSignatureContext(opts.namespace, opts.serverId)` — the
 *                                    address the caller asked for. Checked BEFORE the blob signature
 *                                    (tessera-kit 0.2.0; see the module note): `context` for that
 *                                    signature check is built ONLY from `opts`, never from this tag,
 *                                    so this is a separate, kenspeckle-owned consistency check, not
 *                                    the source of the context binding itself.
 *   7. `n-tag-mismatch`            — the indexable `n` tag is absent or disagrees with
 *                                    `opts.namespace`.
 *   8. `bad-blob-signature`        — the IN-BLOB Schnorr provenance signature is invalid for
 *                                    `context = filterSignatureContext(opts.namespace, opts.serverId)`
 *                                    (`verifyFilterBlob`) — the §10 invariant, extended in 0.2.0 with
 *                                    context binding (closes cross-server/namespace substitution).
 *   9. `unparseable-blob`          — the blob does not re-parse as a `MembershipFilter`
 *                                    (`parseFilter` throws → tampered header).
 *   10. `non-finite-epoch`         — the blob's signed epoch is not a finite number (defensive; a
 *                                    genuinely-signed blob never produces this).
 *   11. `author-not-signer`        — `opts.requireAuthorIsSigner` (default `true`) and
 *                                    `event.pubkey !== signerPubkeyHex`.
 *   12. `epoch-tag-mismatch`       — the event's (unsigned) `epoch` tag is present and disagrees with
 *                                    the blob's SIGNED epoch (defense-in-depth tampering signal).
 *   13. `keyed-tag-mismatch`       — the event's (unsigned) `keyed` tag is present and disagrees with
 *                                    the blob's SIGNED `keyed` flag.
 *   14. `stale-epoch`              — `opts.minEpoch` is set and the blob's SIGNED epoch `<= minEpoch`
 *                                    (monotonicity — rollback defense).
 *
 *  REMOVED as of 0.2.0 (BREAKING — see CHANGELOG): `bad-d-tag`, `d-tag-no-colon`, and
 *  `empty-namespace-or-serverid`. Those existed to PARSE `namespace`/`serverId` OUT of the d-tag,
 *  which was the only source of truth for them pre-0.2.0. `opts.namespace`/`opts.serverId` are now
 *  that source of truth, so any d-tag that doesn't exactly reproduce
 *  `filterSignatureContext(opts.namespace, opts.serverId)` — malformed, wrong prefix, no colon
 *  boundary, empty segment, or simply a different (but well-formed) address — now falls, more
 *  simply and more strictly, into the single `address-mismatch` code. */
export type FilterPublicationRejection =
  | 'invalid-opts'
  | 'bad-signature'
  | 'wrong-kind'
  | 'bad-content'
  | 'bad-blob'
  | 'address-mismatch'
  | 'n-tag-mismatch'
  | 'bad-blob-signature'
  | 'unparseable-blob'
  | 'non-finite-epoch'
  | 'author-not-signer'
  | 'epoch-tag-mismatch'
  | 'keyed-tag-mismatch'
  | 'stale-epoch'

/** Result of `parseFilterPublicationResult`: the parsed `FilterPublication` on success, or the
 *  specific `FilterPublicationRejection` code on failure — additive alongside `parseFilterPublication`
 *  (which collapses this to `null` on any failure, unchanged behaviour). */
export type FilterPublicationResult =
  | { ok: true; value: FilterPublication }
  | { ok: false; reason: FilterPublicationRejection }

/** tessera-kit `TesseraErrorCode`s that mean "the `context` string itself was malformed" (empty, a
 *  lone UTF-16 surrogate, or over the 1024 UTF-8 byte cap) — as opposed to "the context was
 *  well-formed but didn't verify," which is folded into `VERIFY_SIGNATURE_OR_SIGNER_MISMATCH` and
 *  mapped to `'bad-blob-signature'` below. Since `context` here is BUILT from
 *  `opts.namespace`/`opts.serverId`, a malformed context can only mean a malformed
 *  namespace/serverId — hence mapped to `'invalid-opts'`, not `'bad-blob-signature'`. */
const CONTEXT_ERROR_CODES = new Set(['VERIFY_CONTEXT_EMPTY', 'VERIFY_CONTEXT_NOT_WELL_FORMED', 'VERIFY_CONTEXT_TOO_LONG'])

/**
 * Parse + verify a filter publication, returning WHY it was rejected instead of a bare `null`.
 * Never throws. See `FilterPublicationRejection` for the full list of reason codes and what each
 * one means; the checks run in that same order (fail-fast on the first that fails).
 *
 * `parseFilterPublication` is a thin wrapper over this function (`ok ? value : null`) kept for
 * backward compatibility — this is the additive surface for a caller that wants to distinguish
 * failure modes (e.g. to log a tampering signal differently from an ordinary decode failure).
 *
 * See `parseFilterPublication`'s doc comment for the full rationale behind each check (rollback
 * hardening, context binding, minEpoch strictness, etc.) — it is not repeated here.
 */
export function parseFilterPublicationResult(
  event: NostrEvent,
  opts: ParseFilterPublicationOpts,
): FilterPublicationResult {
  // 1. `opts.namespace`/`opts.serverId` are the caller-chosen address (§4.3's "the address the
  //    verifier CHOSE to request") that `context` gets built from below — never throw on a
  //    caller-configuration mistake, report it as a rejection instead.
  if (
    opts === null ||
    typeof opts !== 'object' ||
    typeof opts.namespace !== 'string' ||
    opts.namespace.length === 0 ||
    typeof opts.serverId !== 'string' ||
    opts.serverId.length === 0
  ) {
    return { ok: false, reason: 'invalid-opts' }
  }

  // 2. Nostr event signature (transport integrity).
  if (!verifyEvent(event)) return { ok: false, reason: 'bad-signature' }
  // 3. Correct kind.
  if (event.kind !== KINDRED_FILTER_KIND) return { ok: false, reason: 'wrong-kind' }

  // 4. Decode the blob from base64 content, delegated to tessera-kit's `./nostr` helper. It caps the
  //    ENCODED length BEFORE decoding (so an oversized payload can't be expanded into memory),
  //    decodes, and re-asserts the decoded length — throwing on a non-string, an over-length, or
  //    malformed base64. We catch → a reason to keep this function's never-throws contract. Identical
  //    over-length-before-allocation behaviour to the previous hand-rolled cap.
  if (typeof event.content !== 'string') return { ok: false, reason: 'bad-content' }
  let blob: Uint8Array
  try {
    blob = decodeFilterPublicationContent(event.content, MAX_BLOB_BYTES)
  } catch {
    return { ok: false, reason: 'bad-blob' }
  }

  // 5. THE CONTEXT (tessera-kit 0.2.0, PROTOCOL.md §4.3/§6). Built ONLY from `opts` — the
  //    (namespace, serverId) the CALLER asked for — NEVER from the event's own `d`-tag (see
  //    `filterSignatureContext`'s doc comment for the substitution attack this closes).
  const context = filterSignatureContext(opts.namespace, opts.serverId)

  // 6. ADDRESS BINDING — kenspeckle's own check, separate from and prior to the blob signature: the
  //    event's `d`-tag must EXACTLY equal the address we asked for. This does not itself provide the
  //    cross-server-substitution defense (that's `context`, above, which the attacker cannot forge
  //    without the private key); it is a belt-and-suspenders structural check that fails fast, with a
  //    specific reason, on an event served under the wrong addressable identity — including the case
  //    a relay rewrites the `d`-tag on a blob signed for a DIFFERENT context, which proves the
  //    signature check that follows is bound to `opts`, not to whatever this tag claims.
  const dTag = event.tags.find((t) => t[0] === 'd')?.[1]
  if (dTag !== context) return { ok: false, reason: 'address-mismatch' }

  // 7. The indexable 'n' tag MUST equal `opts.namespace` (M2 audit finding, updated for 0.2.0: was
  //    checked against the namespace RECOVERED FROM the d-tag; `opts.namespace` is now the
  //    authoritative source). Every publication this module builds (`buildFilterPublication`) always
  //    sets both from the same `namespace`, so this costs a genuine publication nothing.
  const nTag = event.tags.find((t) => t[0] === 'n')?.[1]
  if (nTag !== opts.namespace) return { ok: false, reason: 'n-tag-mismatch' }

  // 8. In-blob Schnorr provenance signature, bound to `context` (§10 invariant, extended in 0.2.0
  //    with the mandatory context binding — closes cross-server/namespace filter substitution
  //    cryptographically). `verifyFilterBlob` throws a `TesseraError` only if `context` ITSELF is
  //    malformed (empty / not well-formed UTF-16 / over 1024 UTF-8 bytes) — unreachable in practice
  //    here since `opts.namespace`/`opts.serverId` were already checked non-empty strings in step 1,
  //    but mapped defensively to `'invalid-opts'` (never on `.message` — see `CONTEXT_ERROR_CODES`)
  //    rather than allowed to escape this never-throws function. Any other unexpected throw is
  //    mapped to `'bad-blob-signature'`, the closest existing code.
  let sigCheck: { signerPubkeyHex: string; ok: boolean }
  try {
    sigCheck = verifyFilterBlob(blob, context)
  } catch (err) {
    if (err instanceof TesseraError && CONTEXT_ERROR_CODES.has(err.code)) {
      return { ok: false, reason: 'invalid-opts' }
    }
    return { ok: false, reason: 'bad-blob-signature' }
  }
  if (!sigCheck.ok) return { ok: false, reason: 'bad-blob-signature' }

  // 9. Parse the blob with tessera-kit's hardened parser to recover the SIGNED epoch + keyed flag from
  //    the KFLT header (covered by the in-blob Schnorr sig verified in step 8). These — NOT the event
  //    tags — are authoritative for the rollback check and the returned value (see the doc note above).
  //    `parseFilter` validates the header and throws on a malformed/over-cap blob; catch → a reason to
  //    keep the never-throws contract. (verifyFilterBlob already passed, so a throw here is
  //    unexpected, but we stay defensive.)
  let signedEpoch: number
  let signedKeyed: boolean
  try {
    const f = parseFilter(blob)
    signedEpoch = f.epoch
    signedKeyed = f.keyed
  } catch {
    return { ok: false, reason: 'unparseable-blob' }
  }
  if (!Number.isFinite(signedEpoch)) return { ok: false, reason: 'non-finite-epoch' }

  // 10. Author/signer binding: require the OUTER event's signer to be the SAME key as the in-blob
  //     provenance signer (M2 audit finding). NIP-01's event signature covers every tag (via the
  //     event id), so this transitively ties the server's signed identity to the d-tag/n-tag it
  //     published under — defense-in-depth alongside (not instead of) the `context` binding above.
  //     Opt out via `opts.requireAuthorIsSigner: false` for a different trust model.
  if (opts.requireAuthorIsSigner !== false && event.pubkey !== sigCheck.signerPubkeyHex) {
    return { ok: false, reason: 'author-not-signer' }
  }

  // 11. Defense-in-depth: if the (UNSIGNED) event tags are PRESENT and DISAGREE with the blob's
  //     SIGNED values, treat it as a tampering signal and reject. (A publisher MAY omit the tags
  //     entirely — the blob is the source of truth — but if they assert them, they must match what
  //     the server signed.) The epoch tag is compared numerically so '0007' vs 7 is not a false
  //     mismatch.
  const epochTag = event.tags.find((t) => t[0] === 'epoch')?.[1]
  if (epochTag !== undefined) {
    const taggedEpoch = Number(epochTag)
    if (!Number.isFinite(taggedEpoch) || taggedEpoch !== signedEpoch) {
      return { ok: false, reason: 'epoch-tag-mismatch' }
    }
  }
  const keyedTag = event.tags.find((t) => t[0] === 'keyed')?.[1]
  if (keyedTag !== undefined && (keyedTag === '1') !== signedKeyed) {
    return { ok: false, reason: 'keyed-tag-mismatch' }
  }

  // 12. Epoch monotonicity (replay/rollback defense) — against the blob's SIGNED epoch, never the tag.
  if (opts.minEpoch !== undefined && signedEpoch <= opts.minEpoch) {
    return { ok: false, reason: 'stale-epoch' }
  }

  return {
    ok: true,
    value: {
      namespace: opts.namespace,
      serverId: opts.serverId,
      blob,
      keyed: signedKeyed,
      epoch: signedEpoch,
      signerPubkeyHex: sigCheck.signerPubkeyHex,
    },
  }
}

/**
 * Parse + verify a filter publication. Returns `null` (never throws) on ANY failure, in order:
 *   1. `opts.namespace`/`opts.serverId` is missing or not a non-empty string;
 *   2. the Nostr event signature is invalid (`verifyEvent`);
 *   3. the kind is not `KINDRED_FILTER_KIND`;
 *   4. the base64 content is missing/undecodable, or the blob exceeds tessera-kit's 64 MiB cap;
 *   5. the event's `d`-tag does not exactly equal `filterSignatureContext(opts.namespace,
 *      opts.serverId)`, OR the `n` tag does not equal `opts.namespace`;
 *   6. the IN-BLOB Schnorr provenance signature is invalid for that same `context`
 *      (`verifyFilterBlob`) — the §10 invariant, extended in 0.2.0 with context binding;
 *   7. the blob does not re-parse as a MembershipFilter (`parseFilter` throws → tampered header);
 *   8. `opts.requireAuthorIsSigner` (default `true`) and `event.pubkey !== signerPubkeyHex`;
 *   9. the event's `epoch`/`keyed` TAGS are present and DISAGREE with the blob's SIGNED values
 *      (defense-in-depth tampering signal);
 *   10. `opts.minEpoch` is set and the blob's SIGNED epoch `<= minEpoch` (monotonicity — rollback
 *      defense).
 *
 * `opts.namespace`/`opts.serverId` are now REQUIRED (tessera-kit 0.2.0 — BREAKING, see CHANGELOG):
 * every filter-blob signature is bound to a `context` string (tessera-kit PROTOCOL.md §4.1/§4.3),
 * and for the kindred convention `context = filterSignatureContext(namespace, serverId)`. **This
 * `context` MUST be built from the `(namespace, serverId)` the verifier itself chose to fetch —
 * NEVER from the event's own `d`-tag.** A relay or MITM controls every tag on the event it serves;
 * trusting the tag would let it relabel a substituted blob (signed for a DIFFERENT deployment under
 * the SAME signing key) and have the context check trivially "match" itself. Passing `opts` used to
 * be optional; it no longer is, and this is the load-bearing reason why.
 *
 * `minEpoch` IS STRICT (`<=`, not `<`) — RE-READING THE SAME CURRENT PUBLICATION RETURNS `null` (L7
 * audit finding). If a consumer tracks `minEpoch` as "the last epoch I successfully accepted" and
 * later re-fetches that SAME (unchanged) publication — a normal poll, not an attack — this function
 * returns `null` for it, indistinguishable from a genuine forgery/rollback attempt (this function
 * has no reason codes to tell the two apart — seeing one is not, on its own, evidence of anything).
 * This is deliberate: monotonicity must be strict for the rollback defense to mean anything (`<`
 * would accept a byte-for-byte replay of the current epoch as if it were new). If a consumer wants
 * to distinguish "no change" from "rejected", track the LAST epoch it observed (not "accepted") and
 * pass `lastObservedEpoch - 1` as `minEpoch`, or compare `epoch` against its own cached value BEFORE
 * calling this function and skip the call entirely when nothing changed.
 *
 * AUTHOR/SIGNER BINDING (M2 audit finding). The in-blob Schnorr signature covers epoch/keyed/type/
 * fingerprint (and, as of 0.2.0, `context`) but NOT the event's `pubkey` field itself. Without step
 * 8, an attacker holding any genuinely server-signed blob (for the RIGHT context) could still wrap
 * it in an event they sign with their OWN Nostr key, and `parseFilterPublication` would return
 * `signerPubkeyHex` = the real server's key — a valid-looking publication the real server never
 * actually published (as opposed to a WRONG-context substitution, which `context` binding alone
 * already defeats). NIP-01's event signature covers every tag via the event id, so requiring
 * `event.pubkey === signerPubkeyHex` ties the outer transport identity to the in-blob provenance
 * identity too. `opts.requireAuthorIsSigner: false` opts back out for a caller with a different
 * trust model (e.g. an aggregator that intentionally republishes under its own key).
 *
 * EPOCH/KEYED ARE READ FROM THE SIGNED BLOB, NOT THE EVENT TAGS (rollback hardening). The KFLT blob
 * header carries the epoch + keyed flag COVERED BY THE IN-BLOB SCHNORR SIGNATURE; the event tags are
 * UNSIGNED-by-the-server (the republisher controls them). A malicious republisher can wrap the
 * server's OLD signed blob (in-blob epoch=5) in a NEW event they sign, with an `epoch` tag forged to
 * 9999 — `verifyEvent` passes (their key), the in-blob sig is still the real server's — so trusting
 * the tag for the `minEpoch` check would let a STALE blob roll back the consumer. We therefore use the
 * blob's `f.epoch`/`f.keyed` (authoritative) for BOTH the returned `FilterPublication` and the
 * rollback check, and reject outright if the (optional) tags disagree with the signed values.
 *
 * Returns the namespace/serverId (echoing `opts` — guaranteed, by the address-binding check above, to
 * equal what the event's own d-tag carries), the SIGNED epoch + keyed (from the blob), the decoded
 * blob, and the in-blob `signerPubkeyHex` for the consumer's pin check.
 */
export function parseFilterPublication(
  event: NostrEvent,
  opts: ParseFilterPublicationOpts,
): FilterPublication | null {
  const r = parseFilterPublicationResult(event, opts)
  return r.ok ? r.value : null
}

/** Relay filter an aggregator uses to collect every server's publication for one namespace, across
 *  all `serverId`s, via the indexable `#n` tag. */
export function aggregatorQuery(namespace: string): NostrFilter {
  return { kinds: [KINDRED_FILTER_KIND], '#n': [namespace] }
}

/**
 * Build a member's opt-out request (spec §11). Returns an UNSIGNED `EventTemplate` (kind 30445); the
 * consumer finalizes/signs it with the SAME member key. The server honours it on its next filter
 * rebuild (it cannot retroactively remove a member from an already-published immutable blob).
 *
 * The `['p', <memberPubkey>]` tag self-identifies the opter (x-only pubkey derived from
 * `memberPrivHex`), so the server can match the request to a member without trusting the d-tag alone.
 *
 * HONEST LIMITATION: a member CANNOT cryptographically verify their removal from a KEYED pool they
 * have left — they can only assert the request and trust the next rebuild. This is surfaced via
 * `DiscoveryDisclosure.canExit` (exit is always requestable, never cryptographically confirmable).
 *
 * PRIVACY (L5 audit finding): a published, signed kind-30445 carrying `['p', memberPubkey]` plus the
 * server's d-tag PERMANENTLY proves — to anyone who ever sees the relay event — that this member was
 * in that specific pool, which links a persona to a server exactly as visibly as an OPEN pool would
 * (the entire point of a KEYED pool is to hide that link). Consider sending this request encrypted
 * or directly to the server (e.g. a gift-wrapped DM) rather than to public relays, especially for a
 * keyed pool. There is also no expiry/`created_at` freshness semantics here: an old opt-out is
 * replayable by anyone who captured it (re-published after the member re-joins would incorrectly
 * exit them again) — a server SHOULD treat a fresh in-band exit request from the member as the more
 * authoritative signal where the two conflict.
 */
export function buildOptOutRequest(
  p: { namespace: string; serverId: string },
  memberPrivHex: string,
): EventTemplate {
  // d-tag misparse guard (L5, mirrors `buildFilterPublication`): a colon in the namespace would
  // corrupt the addressable identity boundary the same way it would for a filter publication.
  if (p.namespace.includes(':')) {
    throw new Error('buildOptOutRequest: namespace must not contain a colon')
  }
  const priv = memberPrivHex.toLowerCase()
  if (!HEX64.test(priv)) {
    throw new Error('buildOptOutRequest: memberPrivHex must be 64 hex chars')
  }
  // Derive the member's x-only pubkey to self-identify the request. Under @noble/curves@2
  // `schnorr.getPublicKey` takes a Uint8Array (not a hex string) and returns a 32-byte x-only key.
  // Zeroize both the private-key byte copy and the derived pubkey byte copy afterwards (best-effort;
  // the immutable bigint scalar inside noble can't be wiped from here — same caveat as ./bond).
  const privBytes = hexToBytes(priv)
  let memberPubkeyHex: string
  try {
    const pubBytes = schnorr.getPublicKey(privBytes)
    memberPubkeyHex = bytesToHex(pubBytes)
    pubBytes.fill(0)
  } finally {
    privBytes.fill(0)
  }
  return {
    kind: KINDRED_OPTOUT_KIND,
    tags: [
      ['d', dTagValue(p.namespace, p.serverId)],
      ['p', memberPubkeyHex],
    ],
    content: 'opt-out',
    created_at: Math.floor(Date.now() / 1000),
  }
}

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

import { parseFilter, testMembership, memberKey, verifyFilterBlob, type MembershipFilter } from '@forgesworn/tessera-kit'
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
  return buildPublicationTemplate({
    kind: KINDRED_FILTER_KIND,
    tags: [
      ['d', `${D_TAG_PREFIX}${p.namespace}:${p.serverId}`],
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

/** Why `parseFilterPublicationResult` rejected an event — one code per internal `return { ok: false }`
 *  path, in the SAME order `parseFilterPublication`'s doc comment numbers its checks:
 *   1. `bad-signature`             — the Nostr event signature is invalid (`verifyEvent`).
 *   2. `wrong-kind`                — `event.kind !== KINDRED_FILTER_KIND`.
 *   3. `bad-content`               — `event.content` is not a string.
 *   4. `bad-blob`                  — the base64 content is undecodable, or the blob exceeds
 *                                    tessera-kit's 64 MiB cap.
 *   5. `bad-blob-signature`        — the IN-BLOB Schnorr provenance signature is invalid
 *                                    (`verifyFilterBlob`) — the §10 invariant.
 *   6. `unparseable-blob`          — the blob does not re-parse as a `MembershipFilter`
 *                                    (`parseFilter` throws → tampered header).
 *   7. `non-finite-epoch`          — the blob's signed epoch is not a finite number (defensive; a
 *                                    genuinely-signed blob never produces this).
 *   8. `bad-d-tag`                 — the d-tag is missing, or does not start with `D_TAG_PREFIX`.
 *   9. `d-tag-no-colon`            — the d-tag has the right prefix but no `<namespace>:<serverId>`
 *                                    colon boundary after it.
 *   10. `empty-namespace-or-serverid` — the recovered namespace or serverId is the empty string.
 *   11. `n-tag-mismatch`           — the indexable `n` tag is absent or disagrees with the namespace
 *                                    recovered from the d-tag.
 *   12. `author-not-signer`        — `opts.requireAuthorIsSigner` (default `true`) and
 *                                    `event.pubkey !== signerPubkeyHex` (namespace/serverId binding).
 *   13. `epoch-tag-mismatch`       — the event's (unsigned) `epoch` tag is present and disagrees with
 *                                    the blob's SIGNED epoch (defense-in-depth tampering signal).
 *   14. `keyed-tag-mismatch`       — the event's (unsigned) `keyed` tag is present and disagrees with
 *                                    the blob's SIGNED `keyed` flag.
 *   15. `stale-epoch`              — `opts.minEpoch` is set and the blob's SIGNED epoch `<= minEpoch`
 *                                    (monotonicity — rollback defense). */
export type FilterPublicationRejection =
  | 'bad-signature'
  | 'wrong-kind'
  | 'bad-content'
  | 'bad-blob'
  | 'bad-blob-signature'
  | 'unparseable-blob'
  | 'non-finite-epoch'
  | 'bad-d-tag'
  | 'd-tag-no-colon'
  | 'empty-namespace-or-serverid'
  | 'n-tag-mismatch'
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
 * hardening, namespace/serverId binding, minEpoch strictness, etc.) — it is not repeated here.
 */
export function parseFilterPublicationResult(
  event: NostrEvent,
  opts?: { minEpoch?: number; requireAuthorIsSigner?: boolean },
): FilterPublicationResult {
  // 1. Nostr event signature (transport integrity).
  if (!verifyEvent(event)) return { ok: false, reason: 'bad-signature' }
  // 2. Correct kind.
  if (event.kind !== KINDRED_FILTER_KIND) return { ok: false, reason: 'wrong-kind' }

  // 3. Decode the blob from base64 content, delegated to tessera-kit's `./nostr` helper. It caps the
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

  // 4. In-blob Schnorr provenance signature (§10 invariant: consumers verify the in-blob sig).
  const sigCheck = verifyFilterBlob(blob)
  if (!sigCheck.ok) return { ok: false, reason: 'bad-blob-signature' }

  // 5. Parse the blob with tessera-kit's hardened parser to recover the SIGNED epoch + keyed flag from
  //    the KFLT header (covered by the in-blob Schnorr sig verified in step 4). These — NOT the event
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

  // 6. Parse the d-tag → namespace / serverId. Prefix is `kindred:members:`; the namespace is the
  //    segment up to the NEXT colon, and the serverId is the rest (so a serverId may itself contain
  //    colons, e.g. a `wss://host:port/path` URL). namespace/serverId are NOT in the blob, so the
  //    d-tag is authoritative for them — that's correct and unchanged.
  const dTag = event.tags.find((t) => t[0] === 'd')?.[1]
  if (typeof dTag !== 'string' || !dTag.startsWith(D_TAG_PREFIX)) return { ok: false, reason: 'bad-d-tag' }
  const rest = dTag.slice(D_TAG_PREFIX.length)
  const firstColon = rest.indexOf(':')
  if (firstColon < 0) return { ok: false, reason: 'd-tag-no-colon' }
  const namespace = rest.slice(0, firstColon)
  const serverId = rest.slice(firstColon + 1)
  if (namespace.length === 0 || serverId.length === 0) {
    return { ok: false, reason: 'empty-namespace-or-serverid' }
  }

  // 6b. The indexable 'n' tag MUST equal the namespace recovered from the d-tag (M2 audit finding).
  //     Every publication this module builds (`buildFilterPublication`) always sets both from the
  //     same `namespace`, so this costs a genuine publication nothing; it closes a mismatch/tampering
  //     path where an aggregator's `#n` index and the addressable d-tag identity disagree.
  const nTag = event.tags.find((t) => t[0] === 'n')?.[1]
  if (nTag !== namespace) return { ok: false, reason: 'n-tag-mismatch' }

  // 7. Namespace/serverId binding (M2 audit finding — see the doc note above): the in-blob signature
  //    covers neither namespace nor serverId, so require the OUTER event's signer to be the SAME key
  //    as the in-blob provenance signer. NIP-01's event signature covers every tag (via the event
  //    id), so this transitively ties the server's signed identity to the d-tag/n-tag it published
  //    under. Opt out via `opts.requireAuthorIsSigner: false` for a different trust model.
  if (opts?.requireAuthorIsSigner !== false && event.pubkey !== sigCheck.signerPubkeyHex) {
    return { ok: false, reason: 'author-not-signer' }
  }

  // 8. Defense-in-depth: if the (UNSIGNED) event tags are PRESENT and DISAGREE with the blob's SIGNED
  //    values, treat it as a tampering signal and reject. (A publisher MAY omit the tags entirely —
  //    the blob is the source of truth — but if they assert them, they must match what the server
  //    signed.) The epoch tag is compared numerically so '0007' vs 7 is not a false mismatch.
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

  // 9. Epoch monotonicity (replay/rollback defense) — against the blob's SIGNED epoch, never the tag.
  if (opts?.minEpoch !== undefined && signedEpoch <= opts.minEpoch) {
    return { ok: false, reason: 'stale-epoch' }
  }

  return {
    ok: true,
    value: {
      namespace,
      serverId,
      blob,
      keyed: signedKeyed,
      epoch: signedEpoch,
      signerPubkeyHex: sigCheck.signerPubkeyHex,
    },
  }
}

/**
 * Parse + verify a filter publication. Returns `null` (never throws) on ANY failure, in order:
 *   1. the Nostr event signature is invalid (`verifyEvent`);
 *   2. the kind is not `KINDRED_FILTER_KIND`;
 *   3. the base64 content is missing/undecodable, or the blob exceeds tessera-kit's 64 MiB cap;
 *   4. the IN-BLOB Schnorr provenance signature is invalid (`verifyFilterBlob`) — the §10 invariant;
 *   5. the blob does not re-parse as a MembershipFilter (`parseFilter` throws → tampered header);
 *   6. the d-tag does not carry the `kindred:members:<ns>:<server>` shape, OR the `n` tag is absent
 *      or does not equal the namespace recovered from the d-tag;
 *   7. `opts.requireAuthorIsSigner` (default `true`) and `event.pubkey !== signerPubkeyHex`
 *      (namespace/serverId binding — see below);
 *   8. the event's `epoch`/`keyed` TAGS are present and DISAGREE with the blob's SIGNED values
 *      (defense-in-depth tampering signal);
 *   9. `opts.minEpoch` is set and the blob's SIGNED epoch `<= minEpoch` (monotonicity — rollback
 *      defense).
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
 * NAMESPACE/SERVERID BINDING (M2 audit finding). The KFLT blob's in-blob Schnorr signature (§10
 * invariant, step 4) covers epoch/keyed/type/fingerprint — NOT namespace or serverId (those live
 * only in the d-tag, outside the blob). Without step 7, an attacker holding any genuinely
 * server-signed blob could re-wrap it under a DIFFERENT d-tag (e.g. a different `serverId`), sign
 * the OUTER event with their OWN key, and `parseFilterPublication` would still return
 * `signerPubkeyHex` = the real server's key — falsely showing that server's presence at a pool it
 * never published to. NIP-01's event signature DOES cover every tag (d, n, epoch, keyed) via the
 * event id, so requiring `event.pubkey === signerPubkeyHex` transitively binds the SIGNED blob's
 * provenance identity to the namespace/serverId the event asserts — the outer signature now
 * "covers" them by being from the same key. `opts.requireAuthorIsSigner: false` opts back out for a
 * caller with a different trust model (e.g. an aggregator that intentionally republishes under its
 * own key); this is a BREAKING default-behaviour change from the pre-M2 shape (a cross-serverId
 * republish that used to parse now returns `null` unless the caller opts out) — see CHANGELOG.
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
 * Returns the namespace/serverId (from the d-tag — NOT in the blob, so the tag is authoritative
 * there), the SIGNED epoch + keyed (from the blob), the decoded blob, and the in-blob
 * `signerPubkeyHex` for the consumer's pin check.
 */
export function parseFilterPublication(
  event: NostrEvent,
  opts?: { minEpoch?: number; requireAuthorIsSigner?: boolean },
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
      ['d', `${D_TAG_PREFIX}${p.namespace}:${p.serverId}`],
      ['p', memberPubkeyHex],
    ],
    content: 'opt-out',
    created_at: Math.floor(Date.now() / 1000),
  }
}

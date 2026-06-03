// kindred ./discovery — local presence intersection over a sibling `tessera-kit` membership filter,
// plus signed Nostr filter publications (kind 30444) and the opt-out request (kind 30445).
//
// Spec: signet-plans/docs/plans/2026-06-02-kindred-primitive-spec.md §8 (discovery) + §11 (opt-out).
// Publication shape matches tessera-kit PROTOCOL.md §6 byte-for-byte (kind 30444, d-tag
// `kindred:members:<namespace>:<serverId>`, indexable `['n', namespace]` tag, base64-of-KFLT-blob
// content). The `namespace` is reverse-DNS-style and MUST be colon-free (the d-tag splits on the
// first colon after the prefix to recover `<namespace>` vs `<serverId>`); `serverId` MAY contain
// colons (it is the remainder). The Nostr event signature (NIP-01) and the in-blob Schnorr provenance
// signature (§4) are DISTINCT; `parseFilterPublication` verifies BOTH before returning anything
// trustable. The base64 publication mechanics are delegated to tessera-kit's generic `./nostr`
// builder/decoder so the wire-format lives in ONE place (kindred supplies only its kind + tags).
//
// This layer holds no state, opens no sockets, and never enumerates a server's membership — it only
// tests the consumer's OWN contacts against a published filter (presence, not a member list).

import { parseFilter, testMembership, memberKey, verifyFilterBlob, type MembershipFilter } from '@forgesworn/tessera-kit'
// Publication MECHANICS (base64 assembly + length-capped decode) are delegated to tessera-kit's
// relationship-agnostic `./nostr` core, so the wire-format lives in ONE place. kindred still owns the
// kind + d/n/epoch/keyed tags and passes them in. Aliased to avoid clashing with kindred's own
// `buildFilterPublication` (the kindred-specific wrapper exported from this module).
import { buildFilterPublication as buildPublicationTemplate, decodeFilterPublicationContent } from '@forgesworn/tessera-kit/nostr'
import { verifyEvent } from 'nostr-tools/pure'
import { schnorr } from '@noble/curves/secp256k1.js'
import { bytesToHex, hexToBytes } from '@noble/hashes/utils.js'
import type { KindredEntry, EventTemplate, NostrEvent, NostrFilter } from './types.js'

// `parseFilter` is re-exported only so callers can `import { parseFilter } from 'kindred/discovery'`
// without reaching past kindred into tessera-kit; kindred's own functions take a parsed filter.
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

/** Current unix time in whole seconds (the kindred event `created_at` convention). */
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
  /** A member can always request removal (`buildOptOutRequest`); honoured on the next rebuild. */
  canExit: boolean
}

/** Compute the disclosure surface for a pool (keyed iff a salt is in play; open pools are
 *  cross-server discoverable for included members). */
export function disclosureFor(opts: { salt?: string }): DiscoveryDisclosure {
  const keyed = opts.salt !== undefined
  return {
    keyed,
    // Open (unsalted) pools test the raw pubkey, so an included member is locatable across every
    // open pool that holds them. Keyed pools hide that without the out-of-band salt.
    crossServerDiscoverable: !keyed,
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
 *   this mirrors it for kindred's namespace.
 * - `['n', namespace]` is the single-letter relay-indexable tag the aggregator queries (`#n`).
 *
 * The base64-of-blob CONTENT and `EventTemplate` assembly are delegated to tessera-kit's generic
 * `./nostr` publisher (`buildPublicationTemplate`) so the wire mechanics live in ONE place; kindred
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

/**
 * Parse + verify a filter publication. Returns `null` (never throws) on ANY failure, in order:
 *   1. the Nostr event signature is invalid (`verifyEvent`);
 *   2. the kind is not `KINDRED_FILTER_KIND`;
 *   3. the base64 content is missing/undecodable, or the blob exceeds tessera-kit's 64 MiB cap;
 *   4. the IN-BLOB Schnorr provenance signature is invalid (`verifyFilterBlob`) — the §10 invariant;
 *   5. the blob does not re-parse as a MembershipFilter (`parseFilter` throws → tampered header);
 *   6. the d-tag does not carry the `kindred:members:<ns>:<server>` shape;
 *   7. the event's `epoch`/`keyed` TAGS are present and DISAGREE with the blob's SIGNED values
 *      (defense-in-depth tampering signal);
 *   8. `opts.minEpoch` is set and the blob's SIGNED epoch `<= minEpoch` (monotonicity — rollback
 *      defense).
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
  opts?: { minEpoch?: number },
): FilterPublication | null {
  // 1. Nostr event signature (transport integrity).
  if (!verifyEvent(event)) return null
  // 2. Correct kind.
  if (event.kind !== KINDRED_FILTER_KIND) return null

  // 3. Decode the blob from base64 content, delegated to tessera-kit's `./nostr` helper. It caps the
  //    ENCODED length BEFORE decoding (so an oversized payload can't be expanded into memory),
  //    decodes, and re-asserts the decoded length — throwing on a non-string, an over-length, or
  //    malformed base64. We catch → null to keep this function's never-throws contract. Identical
  //    over-length-before-allocation behaviour to the previous hand-rolled cap.
  if (typeof event.content !== 'string') return null
  let blob: Uint8Array
  try {
    blob = decodeFilterPublicationContent(event.content, MAX_BLOB_BYTES)
  } catch {
    return null
  }

  // 4. In-blob Schnorr provenance signature (§10 invariant: consumers verify the in-blob sig).
  const sigCheck = verifyFilterBlob(blob)
  if (!sigCheck.ok) return null

  // 5. Parse the blob with tessera-kit's hardened parser to recover the SIGNED epoch + keyed flag from
  //    the KFLT header (covered by the in-blob Schnorr sig verified in step 4). These — NOT the event
  //    tags — are authoritative for the rollback check and the returned value (see the doc note above).
  //    `parseFilter` validates the header and throws on a malformed/over-cap blob; catch → null to keep
  //    the never-throws contract. (verifyFilterBlob already passed, so a throw here is unexpected, but
  //    we stay defensive.)
  let signedEpoch: number
  let signedKeyed: boolean
  try {
    const f = parseFilter(blob)
    signedEpoch = f.epoch
    signedKeyed = f.keyed
  } catch {
    return null
  }
  if (!Number.isFinite(signedEpoch)) return null

  // 6. Parse the d-tag → namespace / serverId. Prefix is `kindred:members:`; the namespace is the
  //    segment up to the NEXT colon, and the serverId is the rest (so a serverId may itself contain
  //    colons, e.g. a `wss://host:port/path` URL). namespace/serverId are NOT in the blob, so the
  //    d-tag is authoritative for them — that's correct and unchanged.
  const dTag = event.tags.find((t) => t[0] === 'd')?.[1]
  if (typeof dTag !== 'string' || !dTag.startsWith(D_TAG_PREFIX)) return null
  const rest = dTag.slice(D_TAG_PREFIX.length)
  const firstColon = rest.indexOf(':')
  if (firstColon < 0) return null
  const namespace = rest.slice(0, firstColon)
  const serverId = rest.slice(firstColon + 1)
  if (namespace.length === 0 || serverId.length === 0) return null

  // 7. Defense-in-depth: if the (UNSIGNED) event tags are PRESENT and DISAGREE with the blob's SIGNED
  //    values, treat it as a tampering signal and reject. (A publisher MAY omit the tags entirely —
  //    the blob is the source of truth — but if they assert them, they must match what the server
  //    signed.) The epoch tag is compared numerically so '0007' vs 7 is not a false mismatch.
  const epochTag = event.tags.find((t) => t[0] === 'epoch')?.[1]
  if (epochTag !== undefined) {
    const taggedEpoch = Number(epochTag)
    if (!Number.isFinite(taggedEpoch) || taggedEpoch !== signedEpoch) return null
  }
  const keyedTag = event.tags.find((t) => t[0] === 'keyed')?.[1]
  if (keyedTag !== undefined && (keyedTag === '1') !== signedKeyed) return null

  // 8. Epoch monotonicity (replay/rollback defense) — against the blob's SIGNED epoch, never the tag.
  if (opts?.minEpoch !== undefined && signedEpoch <= opts.minEpoch) return null

  return {
    namespace,
    serverId,
    blob,
    keyed: signedKeyed,
    epoch: signedEpoch,
    signerPubkeyHex: sigCheck.signerPubkeyHex,
  }
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
 */
export function buildOptOutRequest(
  p: { namespace: string; serverId: string },
  memberPrivHex: string,
): EventTemplate {
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

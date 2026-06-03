// kindred ./discovery — local presence intersection over a sibling `tessera-kit` membership filter,
// plus signed Nostr filter publications (kind 30444) and the opt-out request (kind 30445).
//
// Spec: signet-plans/docs/plans/2026-06-02-kindred-primitive-spec.md §8 (discovery) + §11 (opt-out).
// Publication shape matches tessera-kit PROTOCOL.md §6 byte-for-byte (kind 30444, d-tag
// `kindred:members:<namespace>:<serverId>`, indexable `['n', namespace]` tag, base64-of-KFLT-blob
// content). The Nostr event signature (NIP-01) and the in-blob Schnorr provenance signature (§4) are
// DISTINCT; `parseFilterPublication` verifies BOTH before returning anything trustable.
//
// This layer holds no state, opens no sockets, and never enumerates a server's membership — it only
// tests the consumer's OWN contacts against a published filter (presence, not a member list).

import { parseFilter, testMembership, memberKey, verifyFilterBlob, type MembershipFilter } from 'tessera-kit'
import { verifyEvent } from 'nostr-tools/pure'
import { schnorr } from '@noble/curves/secp256k1.js'
import { bytesToHex, hexToBytes } from '@noble/hashes/utils.js'
import { base64 } from '@scure/base'
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
 *   `(namespace, serverId)`; a newer epoch replaces the older addressable event).
 * - `['n', namespace]` is the single-letter relay-indexable tag the aggregator queries (`#n`).
 */
export function buildFilterPublication(p: {
  namespace: string
  serverId: string
  blob: Uint8Array
  keyed: boolean
  epoch: number
}): EventTemplate {
  return {
    kind: KINDRED_FILTER_KIND,
    tags: [
      ['d', `${D_TAG_PREFIX}${p.namespace}:${p.serverId}`],
      ['n', p.namespace],
      ['epoch', String(p.epoch)],
      ['keyed', p.keyed ? '1' : '0'],
    ],
    content: base64.encode(p.blob),
    created_at: Math.floor(Date.now() / 1000),
  }
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
 *   5. the d-tag does not carry the `kindred:members:<ns>:<server>` shape;
 *   6. `opts.minEpoch` is set and `epoch <= minEpoch` (monotonicity — replay/rollback defense).
 *
 * Returns the namespace/serverId (from the d-tag), epoch + keyed (from their tags), the decoded blob,
 * and the in-blob `signerPubkeyHex` for the consumer's pin check.
 */
export function parseFilterPublication(
  event: NostrEvent,
  opts?: { minEpoch?: number },
): FilterPublication | null {
  // 1. Nostr event signature (transport integrity).
  if (!verifyEvent(event)) return null
  // 2. Correct kind.
  if (event.kind !== KINDRED_FILTER_KIND) return null

  // 3. Decode the blob from base64 content. Cap the encoded length before decoding so an oversized
  //    payload can't be expanded into memory (base64 expands ~4/3, so cap the encoded form too).
  if (typeof event.content !== 'string') return null
  if (event.content.length > Math.ceil((MAX_BLOB_BYTES * 4) / 3) + 4) return null
  let blob: Uint8Array
  try {
    blob = base64.decode(event.content)
  } catch {
    return null
  }
  if (blob.length > MAX_BLOB_BYTES) return null

  // 4. In-blob Schnorr provenance signature (§10 invariant: consumers verify the in-blob sig).
  const sigCheck = verifyFilterBlob(blob)
  if (!sigCheck.valid) return null

  // 5. Parse the d-tag → namespace / serverId. Prefix is `kindred:members:`; the namespace is the
  //    segment up to the NEXT colon, and the serverId is the rest (so a serverId may itself contain
  //    colons, e.g. a `wss://host:port/path` URL).
  const dTag = event.tags.find((t) => t[0] === 'd')?.[1]
  if (typeof dTag !== 'string' || !dTag.startsWith(D_TAG_PREFIX)) return null
  const rest = dTag.slice(D_TAG_PREFIX.length)
  const firstColon = rest.indexOf(':')
  if (firstColon < 0) return null
  const namespace = rest.slice(0, firstColon)
  const serverId = rest.slice(firstColon + 1)
  if (namespace.length === 0 || serverId.length === 0) return null

  // epoch from the epoch tag; keyed from the keyed tag.
  const epochTag = event.tags.find((t) => t[0] === 'epoch')?.[1]
  const epoch = epochTag !== undefined ? Number(epochTag) : NaN
  if (!Number.isFinite(epoch)) return null
  const keyed = event.tags.find((t) => t[0] === 'keyed')?.[1] === '1'

  // 6. Epoch monotonicity (replay/rollback defense).
  if (opts?.minEpoch !== undefined && epoch <= opts.minEpoch) return null

  return { namespace, serverId, blob, keyed, epoch, signerPubkeyHex: sigCheck.signerPubkeyHex }
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

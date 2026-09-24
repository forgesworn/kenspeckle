// kenspeckle ./discovery — tests.
//
// `discovery` is the thin LOCAL-INTERSECTION layer over a sibling `tessera-kit` membership filter:
// the consumer holds a set of `KindredEntry`s (their kith/kin/ken contacts, all scoped to ONE of
// their persona pubkeys) and tests which of those contacts are present in a server's published
// filter — WITHOUT enumerating the server's membership. It also packages a server's filter blob as
// a signed Nostr publication (kind 30444) and parses one back, verifying BOTH the Nostr event
// signature AND the in-blob Schnorr provenance signature before returning anything trustable.
//
// These tests build REAL tessera-kit filters (`buildMembershipFilter` → `serializeFilter` →
// `signFilterBlob`) and REAL signed Nostr events (`finalizeEvent` from nostr-tools/pure) — no mocks.

import { describe, it, expect } from 'vitest'
import {
  buildMembershipFilter,
  serializeFilter,
  signFilterBlob,
  verifyFilterBlob,
  parseFilter,
  memberKey,
} from '@forgesworn/tessera-kit'
import { finalizeEvent, generateSecretKey, getPublicKey } from 'nostr-tools/pure'
import { bytesToHex } from '@noble/hashes/utils.js'
import { base64 } from '@scure/base'
import {
  KINDRED_FILTER_KIND,
  KINDRED_OPTOUT_KIND,
  discoverPresent,
  disclosureFor,
  buildFilterPublication,
  parseFilterPublication,
  parseFilterPublicationResult,
  filterSignatureContext,
  aggregatorQuery,
  buildOptOutRequest,
} from './discovery.js'
import type { KindredEntry, KinEntry, KithEntry, KenEntry, NostrEvent } from './types.js'

// --- Fixtures -------------------------------------------------------------------------------------

const NAMESPACE = 'com.example.game'
const SERVER_ID = 'play.example.com'
const SALT = 'deadbeefcafe' // keyed-pool salt (even-length hex)
const CONTEXT = filterSignatureContext(NAMESPACE, SERVER_ID) // the kindred convention's default test context

/** A fresh real keypair: 32-byte secret + 64-hex x-only pubkey. */
function freshKeypair(): { sk: Uint8Array; priv: string; pk: string } {
  const sk = generateSecretKey()
  return { sk, priv: bytesToHex(sk), pk: getPublicKey(sk) }
}

/** Minimal kith entry (mutual tier) scoped to `owner`. */
function kithEntry(pubkey: string, owner: string): KithEntry {
  return {
    tier: 'kith',
    pubkey,
    ownerPubkey: owner,
    sharedSecret: 'ff'.repeat(32),
    verifiedAt: 1700000000,
    addedAt: 1700000000,
  }
}

/** Minimal kin entry (mutual tier) scoped to `owner`. */
function kinEntry(pubkey: string, owner: string): KinEntry {
  return {
    tier: 'kin',
    pubkey,
    ownerPubkey: owner,
    relationship: 'sibling',
    sharedSecret: 'ee'.repeat(32),
    verifiedAt: 1700000000,
    addedAt: 1700000000,
  }
}

/** Minimal ken entry (one-way tier) scoped to `owner`. */
function kenEntry(pubkey: string, owner: string): KenEntry {
  return {
    tier: 'ken',
    pubkey,
    ownerPubkey: owner,
    provenance: { source: 'manual', locator: 'test', confirmedAt: 1700000000 },
    addedAt: 1700000000,
  }
}

/**
 * Build a REAL signed KFLT blob over the given member pubkeys for `serverPriv`.
 * Open pool when `salt` is undefined; keyed pool when a salt is supplied.
 * `context` (tessera-kit 0.2.0 — required by `signFilterBlob`) defaults to the standard
 * `(NAMESPACE, SERVER_ID)` test fixture's context; pass a different one to build a blob signed for a
 * DIFFERENT deployment (e.g. the cross-server-substitution tests below).
 */
function buildSignedBlob(
  memberPubkeys: string[],
  serverPriv: string,
  epoch: number,
  salt?: string,
  context: string = CONTEXT,
): Uint8Array {
  const keys = memberPubkeys.map((pk) => memberKey(pk, salt))
  const filt = buildMembershipFilter(keys, salt === undefined ? { epoch } : { epoch, salt })
  return signFilterBlob(serializeFilter(filt), serverPriv, context)
}

/** Drop the nostr-tools `verifiedSymbol` cache so `verifyEvent` actually re-checks the sig. */
function fromWire(ev: ReturnType<typeof finalizeEvent>): NostrEvent {
  return JSON.parse(JSON.stringify(ev)) as NostrEvent
}

// --- discoverPresent: local intersection ----------------------------------------------------------

describe('discoverPresent — local intersection over a tessera-kit filter', () => {
  it('returns exactly the present kith/kin entries for an OPEN pool (non-member absent)', () => {
    const owner = freshKeypair().pk
    const server = freshKeypair()

    const a = freshKeypair().pk
    const b = freshKeypair().pk
    const c = freshKeypair().pk
    const nonMember = freshKeypair().pk

    // Server's pool contains a, b, c (+ another non-contact member).
    const otherMember = freshKeypair().pk
    const blob = buildSignedBlob([a, b, c, otherMember], server.priv, 100)
    const filter = parseFilter(blob)

    // My contacts: a (kith), b (kin), nonMember (kith — NOT in the pool).
    const entries: KindredEntry[] = [
      kithEntry(a, owner),
      kinEntry(b, owner),
      kithEntry(nonMember, owner),
    ]

    const present = discoverPresent(filter, entries, owner)
    const presentPks = present.map((e) => e.pubkey).sort()
    expect(presentPks).toEqual([a, b].sort())
    expect(present.map((e) => e.pubkey)).not.toContain(nonMember)
    // No truncation locally — every matching entry is returned (KindredEntry[] per spec §8.1).
    expect(present.length).toBe(2)
  })

  it('returns the present entries for a KEYED pool when the matching salt is supplied', () => {
    const owner = freshKeypair().pk
    const server = freshKeypair()

    const a = freshKeypair().pk
    const b = freshKeypair().pk
    const nonMember = freshKeypair().pk

    const blob = buildSignedBlob([a, b], server.priv, 100, SALT)
    const filter = parseFilter(blob)
    expect(filter.keyed).toBe(true)

    const entries: KindredEntry[] = [
      kithEntry(a, owner),
      kenEntry(b, owner),
      kithEntry(nonMember, owner),
    ]

    // With the salt, a and b match.
    const present = discoverPresent(filter, entries, owner, SALT)
    expect(present.map((e) => e.pubkey).sort()).toEqual([a, b].sort())

    // Without the salt, the filter KNOWS it's keyed — silently testing the open-form memberKey would
    // return [] ("no friends here"), a doxxing-adjacent footgun (a wrong "nobody you know is here"
    // answer). It must THROW instead, telling the caller to pass the keyed-pool salt.
    expect(() => discoverPresent(filter, entries, owner)).toThrow(/keyed but no salt/i)
  })

  it('THROWS on mixed-persona input (entries with differing ownerPubkey) — anti-correlation', () => {
    const ownerA = freshKeypair().pk
    const ownerB = freshKeypair().pk
    const server = freshKeypair()

    const a = freshKeypair().pk
    const b = freshKeypair().pk
    const blob = buildSignedBlob([a, b], server.priv, 100)
    const filter = parseFilter(blob)

    const mixed: KindredEntry[] = [kithEntry(a, ownerA), kithEntry(b, ownerB)]
    expect(() => discoverPresent(filter, mixed, ownerA)).toThrow(/mixed-persona/i)
  })

  it('THROWS when the declared owner does not match every entry (case-insensitive compare)', () => {
    const owner = freshKeypair().pk
    const server = freshKeypair()
    const a = freshKeypair().pk
    const blob = buildSignedBlob([a], server.priv, 100)
    const filter = parseFilter(blob)

    // Single entry whose owner differs from the declared owner → throw.
    const entries: KindredEntry[] = [kithEntry(a, owner)]
    const otherOwner = freshKeypair().pk
    expect(() => discoverPresent(filter, entries, otherOwner)).toThrow(/mixed-persona/i)

    // Same owner but UPPERCASED declared-owner still passes the case-insensitive check.
    const presentUpper = discoverPresent(filter, entries, owner.toUpperCase())
    expect(presentUpper.map((e) => e.pubkey)).toEqual([a])
  })

  it('returns [] for an empty entries array (vacuously persona-consistent)', () => {
    const owner = freshKeypair().pk
    const server = freshKeypair()
    const blob = buildSignedBlob([freshKeypair().pk], server.priv, 100)
    const filter = parseFilter(blob)
    expect(discoverPresent(filter, [], owner)).toEqual([])
  })

  it('THROWS when an OPEN filter is given a salt anyway (M3 audit finding — mirror of the keyed-without-salt guard)', () => {
    const owner = freshKeypair().pk
    const server = freshKeypair()
    const a = freshKeypair().pk
    // Open (unsalted) pool containing `a`.
    const blob = buildSignedBlob([a], server.priv, 100)
    const filter = parseFilter(blob)
    expect(filter.keyed).toBe(false)

    const entries: KindredEntry[] = [kithEntry(a, owner)]
    // Passing a salt to an OPEN filter would hash every candidate as if the pool were keyed, so
    // NOTHING matches and this would silently return [] — a false "no friends here". It must THROW.
    expect(() => discoverPresent(filter, entries, owner, SALT)).toThrow(/open \(unkeyed\) but a salt/i)
    // Without the (wrongly-supplied) salt, the real match is found.
    expect(discoverPresent(filter, entries, owner).map((e) => e.pubkey)).toEqual([a])
  })

  it('THROWS when a KEYED filter is given an EMPTY-STRING salt (tessera-kit 0.2.0 — empty salt is never valid)', () => {
    // tessera-kit 0.2.0: `memberKey`/`buildMembershipFilter` now REJECT an empty-string salt outright
    // (`sha256('' || pk)` is computable by anyone holding the bare pubkey — no out-of-band salt
    // needed, so it gives away nothing a KEYED pool exists to hide). `discoverPresent` catches this
    // itself, before ever calling `memberKey`, in the same fail-loud style as the other salt guards —
    // never a raw tessera-kit `TesseraError` (`INPUT_SALT_INVALID`).
    const owner = freshKeypair().pk
    const server = freshKeypair()
    const a = freshKeypair().pk
    const blob = buildSignedBlob([a], server.priv, 100, SALT)
    const filter = parseFilter(blob)
    expect(filter.keyed).toBe(true)

    const entries: KindredEntry[] = [kithEntry(a, owner)]
    expect(() => discoverPresent(filter, entries, owner, '')).toThrow(/empty-string salt/i)
    // The real (non-empty) salt still works.
    expect(discoverPresent(filter, entries, owner, SALT).map((e) => e.pubkey)).toEqual([a])
  })
})

// --- disclosureFor: honest privacy surface --------------------------------------------------------

describe('disclosureFor — honest disclosure surface (takes the PARSED FILTER, L6 audit finding)', () => {
  it('reports an OPEN pool: not keyed, cross-server discoverable', () => {
    const server = freshKeypair()
    const blob = buildSignedBlob([freshKeypair().pk], server.priv, 1)
    const filter = parseFilter(blob)
    expect(filter.keyed).toBe(false)
    const d = disclosureFor(filter)
    expect(d).toEqual({
      keyed: false,
      crossServerDiscoverable: true,
      optIn: true,
      canExit: true,
    })
  })

  it('reports a KEYED pool: keyed, NOT cross-server discoverable', () => {
    const server = freshKeypair()
    const blob = buildSignedBlob([freshKeypair().pk], server.priv, 1, SALT)
    const filter = parseFilter(blob)
    expect(filter.keyed).toBe(true)
    const d = disclosureFor(filter)
    expect(d).toEqual({
      keyed: true,
      crossServerDiscoverable: false,
      optIn: true,
      canExit: true,
    })
  })

  it('derives `keyed` from the filter itself, not a separately-supplied salt — the two can never disagree', () => {
    // Before the L6 fix, `disclosureFor({ salt })` derived `keyed` from salt PRESENCE — a second,
    // independent source of truth that could disagree with the filter's own `keyed` flag. Deriving
    // it from `f.keyed` directly makes that disagreement structurally impossible: there is no salt
    // parameter left to pass at all.
    const server = freshKeypair()
    const openBlob = buildSignedBlob([freshKeypair().pk], server.priv, 1)
    expect(disclosureFor(parseFilter(openBlob)).keyed).toBe(false)
    const keyedBlob = buildSignedBlob([freshKeypair().pk], server.priv, 1, SALT)
    expect(disclosureFor(parseFilter(keyedBlob)).keyed).toBe(true)
  })
})

// --- buildFilterPublication / parseFilterPublication round-trip -----------------------------------

describe('filter publication — build → sign → parse round-trip', () => {
  it('round-trips namespace/serverId/epoch/keyed/signerPubkeyHex and the blob', () => {
    const server = freshKeypair()
    const a = freshKeypair().pk
    const b = freshKeypair().pk
    const blob = buildSignedBlob([a, b], server.priv, 1234, undefined)

    const template = buildFilterPublication({
      namespace: NAMESPACE,
      serverId: SERVER_ID,
      blob,
      keyed: false,
      epoch: 1234,
    })
    expect(template.kind).toBe(KINDRED_FILTER_KIND)
    expect(template.created_at).toBeTypeOf('number')

    // The server signs the outer event with the SAME key it used for the in-blob provenance
    // signature — the genuine-publication shape `requireAuthorIsSigner` (default true, M2 audit
    // finding) requires: the event signer and the in-blob signer are the same identity, so the
    // NIP-01 event signature (which covers every tag, including d/n) transitively binds the
    // namespace/serverId to what the server actually signed.
    const signed = fromWire(finalizeEvent(template, server.sk))

    const parsed = parseFilterPublication(signed, { namespace: NAMESPACE, serverId: SERVER_ID })
    expect(parsed).not.toBeNull()
    expect(parsed!.namespace).toBe(NAMESPACE)
    expect(parsed!.serverId).toBe(SERVER_ID)
    expect(parsed!.epoch).toBe(1234)
    expect(parsed!.keyed).toBe(false)
    // signerPubkeyHex is the IN-BLOB server key (provenance), not the event/publisher key.
    expect(parsed!.signerPubkeyHex).toBe(server.pk)

    // The blob round-trips byte-identically and re-verifies (bound to the SAME context it was
    // published under — tessera-kit 0.2.0).
    expect(bytesToHex(parsed!.blob)).toBe(bytesToHex(blob))
    expect(verifyFilterBlob(parsed!.blob, CONTEXT).ok).toBe(true)
  })

  it('emits the canonical d-tag and indexable n-tag matching tessera-kit PROTOCOL.md', () => {
    const server = freshKeypair()
    const blob = buildSignedBlob([freshKeypair().pk], server.priv, 5, SALT)
    const template = buildFilterPublication({
      namespace: NAMESPACE,
      serverId: SERVER_ID,
      blob,
      keyed: true,
      epoch: 5,
    })
    const dTag = template.tags.find((t) => t[0] === 'd')
    const nTag = template.tags.find((t) => t[0] === 'n')
    const keyedTag = template.tags.find((t) => t[0] === 'keyed')
    const epochTag = template.tags.find((t) => t[0] === 'epoch')
    expect(dTag).toEqual(['d', `kindred:members:${NAMESPACE}:${SERVER_ID}`])
    expect(dTag![1]).toBe(CONTEXT) // the d-tag value IS the filter-signature context (§4.3/§6)
    expect(nTag).toEqual(['n', NAMESPACE])
    expect(keyedTag).toEqual(['keyed', '1'])
    expect(epochTag).toEqual(['epoch', '5'])
    expect(template.content).toBe(base64.encode(blob))
  })

  it('REJECTS a namespace containing a colon (d-tag misparse guard); reverse-DNS is fine', () => {
    const server = freshKeypair()
    const blob = buildSignedBlob([freshKeypair().pk], server.priv, 1, SALT)
    // A namespace with a colon would shift the `kindred:members:<ns>:<serverId>` boundary. Reject at
    // build, before the (unrelated) context-verification step even runs.
    expect(() =>
      buildFilterPublication({ namespace: 'com:evil', serverId: SERVER_ID, blob, keyed: true, epoch: 1 }),
    ).toThrow(/namespace must not contain a colon/i)
    // A normal reverse-DNS namespace (colon-free) builds fine.
    expect(() =>
      buildFilterPublication({ namespace: 'com.example.game', serverId: SERVER_ID, blob, keyed: true, epoch: 1 }),
    ).not.toThrow()
  })

  it('round-trips keyed:true and a serverId containing colons', () => {
    const server = freshKeypair()
    const colonServer = 'wss://host:4848/path' // serverId with internal colons
    const blob = buildSignedBlob([freshKeypair().pk], server.priv, 9, SALT, filterSignatureContext(NAMESPACE, colonServer))
    const template = buildFilterPublication({
      namespace: NAMESPACE,
      serverId: colonServer,
      blob,
      keyed: true,
      epoch: 9,
    })
    // Signed by the server's OWN key — see the requireAuthorIsSigner note above.
    const signed = fromWire(finalizeEvent(template, server.sk))
    const parsed = parseFilterPublication(signed, { namespace: NAMESPACE, serverId: colonServer })
    expect(parsed).not.toBeNull()
    expect(parsed!.namespace).toBe(NAMESPACE)
    expect(parsed!.serverId).toBe(colonServer)
    expect(parsed!.keyed).toBe(true)
  })

  it('buildFilterPublication REJECTS a blob signed for a DIFFERENT serverId\'s context', () => {
    // tessera-kit 0.2.0: `buildFilterPublication` verifies `p.blob` against
    // `filterSignatureContext(p.namespace, p.serverId)` before ever publishing it, so a blob signed
    // for the wrong deployment is caught here — not left for a consumer to discover later.
    const server = freshKeypair()
    const blobForA = buildSignedBlob(
      [freshKeypair().pk],
      server.priv,
      10,
      undefined,
      filterSignatureContext(NAMESPACE, 'serverA'),
    )
    expect(() =>
      buildFilterPublication({ namespace: NAMESPACE, serverId: 'serverB', blob: blobForA, keyed: false, epoch: 10 }),
    ).toThrow(/does not verify/i)
    // The SAME blob publishes fine under the serverId it was actually signed for.
    expect(() =>
      buildFilterPublication({ namespace: NAMESPACE, serverId: 'serverA', blob: blobForA, keyed: false, epoch: 10 }),
    ).not.toThrow()
  })
})

// --- parseFilterPublication rejection paths (returns null, never throws) --------------------------

describe('parseFilterPublication — rejects on any failure (returns null)', () => {
  function validSigned(epoch = 100): {
    signed: NostrEvent
    server: ReturnType<typeof freshKeypair>
    blob: Uint8Array
  } {
    const server = freshKeypair()
    const blob = buildSignedBlob([freshKeypair().pk, freshKeypair().pk], server.priv, epoch)
    const template = buildFilterPublication({
      namespace: NAMESPACE,
      serverId: SERVER_ID,
      blob,
      keyed: false,
      epoch,
    })
    // Signed by the server's own key (genuine-publication shape; see requireAuthorIsSigner above).
    const signed = fromWire(finalizeEvent(template, server.sk))
    return { signed, server, blob }
  }

  it('returns null for a BAD event signature (tampered created_at — content stays valid base64)', () => {
    // Tamper `created_at` rather than `content`: the content remains decodable base64 AND the in-blob
    // Schnorr sig stays valid, so the ONLY rejection path that can fire is the failed `verifyEvent`
    // (the event id no longer matches the signed payload). `signed` came through `fromWire`, so it
    // carries no nostr-tools verifiedSymbol cache — `verifyEvent` genuinely re-checks the signature.
    const { signed } = validSigned()
    const tampered: NostrEvent = { ...signed, created_at: signed.created_at + 1 }
    expect(parseFilterPublication(tampered, { namespace: NAMESPACE, serverId: SERVER_ID })).toBeNull()
  })

  it('returns null for the WRONG kind', () => {
    const { server } = validSigned()
    const blob = buildSignedBlob([freshKeypair().pk], server.priv, 100)
    // Build an event with a non-30444 kind but otherwise correct shape, sign it for real.
    const wrongKind = {
      kind: 1,
      tags: [
        ['d', CONTEXT],
        ['n', NAMESPACE],
        ['epoch', '100'],
        ['keyed', '0'],
      ],
      content: base64.encode(blob),
      created_at: Math.floor(Date.now() / 1000),
    }
    const signed = fromWire(finalizeEvent(wrongKind, generateSecretKey()))
    expect(parseFilterPublication(signed, { namespace: NAMESPACE, serverId: SERVER_ID })).toBeNull()
  })

  it('returns null when the IN-BLOB Schnorr signature is invalid (tamper a blob byte)', () => {
    const server = freshKeypair()
    const blob = buildSignedBlob([freshKeypair().pk, freshKeypair().pk], server.priv, 100)
    // Flip a byte in the fingerprint array (offset >= 128) so the in-blob sig no longer verifies. A
    // tampered blob can no longer go through `buildFilterPublication` (it now verifies before
    // publishing), so the wire event is assembled by hand here, exactly as a hostile relay would.
    const tamperedBlob = new Uint8Array(blob)
    tamperedBlob[140] = tamperedBlob[140]! ^ 0xff
    expect(verifyFilterBlob(tamperedBlob, CONTEXT).ok).toBe(false)

    const bad = {
      kind: KINDRED_FILTER_KIND,
      tags: [
        ['d', CONTEXT],
        ['n', NAMESPACE],
        ['epoch', '100'],
        ['keyed', '0'],
      ],
      content: base64.encode(tamperedBlob),
      created_at: Math.floor(Date.now() / 1000),
    }
    const signed = fromWire(finalizeEvent(bad, generateSecretKey()))
    expect(parseFilterPublication(signed, { namespace: NAMESPACE, serverId: SERVER_ID })).toBeNull()
  })

  it('returns null for non-base64 / undecodable content (with a valid event sig)', () => {
    const bad = {
      kind: KINDRED_FILTER_KIND,
      tags: [
        ['d', CONTEXT],
        ['n', NAMESPACE],
        ['epoch', '100'],
        ['keyed', '0'],
      ],
      content: '@@@not base64@@@',
      created_at: Math.floor(Date.now() / 1000),
    }
    const signed = fromWire(finalizeEvent(bad, generateSecretKey()))
    expect(parseFilterPublication(signed, { namespace: NAMESPACE, serverId: SERVER_ID })).toBeNull()
  })

  it('returns null for a malformed d-tag (missing the kindred:members: prefix)', () => {
    const server = freshKeypair()
    const blob = buildSignedBlob([freshKeypair().pk], server.priv, 100)
    const bad = {
      kind: KINDRED_FILTER_KIND,
      tags: [
        ['d', `wrong:prefix:${NAMESPACE}:${SERVER_ID}`],
        ['n', NAMESPACE],
        ['epoch', '100'],
        ['keyed', '0'],
      ],
      content: base64.encode(blob),
      created_at: Math.floor(Date.now() / 1000),
    }
    const signed = fromWire(finalizeEvent(bad, generateSecretKey()))
    expect(parseFilterPublication(signed, { namespace: NAMESPACE, serverId: SERVER_ID })).toBeNull()
  })

  it('returns null when opts is missing/invalid (namespace/serverId required as of tessera-kit 0.2.0)', () => {
    const { signed } = validSigned()
    expect(parseFilterPublication(signed, undefined as unknown as { namespace: string; serverId: string })).toBeNull()
    expect(parseFilterPublication(signed, { namespace: '', serverId: SERVER_ID })).toBeNull()
    expect(parseFilterPublication(signed, { namespace: NAMESPACE, serverId: '' })).toBeNull()
  })

  it('enforces epoch monotonicity: returns null when epoch <= minEpoch, accepts when greater', () => {
    const { signed } = validSigned(50)
    // epoch (50) <= minEpoch (50) → reject (replay/rollback defense).
    expect(parseFilterPublication(signed, { namespace: NAMESPACE, serverId: SERVER_ID, minEpoch: 50 })).toBeNull()
    // epoch (50) <= minEpoch (60) → reject.
    expect(parseFilterPublication(signed, { namespace: NAMESPACE, serverId: SERVER_ID, minEpoch: 60 })).toBeNull()
    // epoch (50) > minEpoch (49) → accept.
    const ok = parseFilterPublication(signed, { namespace: NAMESPACE, serverId: SERVER_ID, minEpoch: 49 })
    expect(ok).not.toBeNull()
    expect(ok!.epoch).toBe(50)
  })
})

// --- epoch/keyed rollback hardening: the SIGNED blob is authoritative, NOT the event tags ----------
//
// The KFLT blob header carries a SIGNED epoch (+ keyed flag), covered by the in-blob Schnorr sig. A
// malicious republisher can take the server's OLD signed blob (in-blob epoch=5) and wrap it in a NEW
// event THEY sign, with an `epoch` TAG forged to 9999: `verifyEvent` passes (their key), the in-blob
// sig is still the real server's (a consumer's pinned-key check would pass), but if the minEpoch
// rollback guard trusted the FORGED TAG, the stale blob would sail through. The guard MUST compare the
// blob's SIGNED epoch (5), so the stale blob is rejected.
describe('parseFilterPublication — epoch/keyed read from the SIGNED blob, not the event tags', () => {
  it('REJECTS a forged-high epoch TAG wrapping an OLD low-epoch signed blob (rollback defense)', () => {
    const server = freshKeypair()
    // Real server-signed blob with in-blob epoch = 5 (the authoritative, signed value).
    const blob = buildSignedBlob([freshKeypair().pk, freshKeypair().pk], server.priv, 5)
    expect(parseFilter(blob).epoch).toBe(5) // sanity: the SIGNED epoch is genuinely 5

    // A malicious republisher wraps that OLD blob in a NEW event with a FORGED epoch tag of 9999,
    // signed by THEIR OWN nostr key (verifyEvent will pass — it's their event).
    const template = buildFilterPublication({
      namespace: NAMESPACE,
      serverId: SERVER_ID,
      blob,
      keyed: false,
      epoch: 9999, // FORGED tag — does not match the blob's signed epoch (5)
    })
    const forged = fromWire(finalizeEvent(template, generateSecretKey()))

    // requireAuthorIsSigner:false isolates the mechanism this test targets (the epoch-rollback
    // guard) from the SEPARATE author-binding guard, which would otherwise also reject this
    // attacker-signed event and mask which defense actually fired.
    // The rollback guard must use the blob's SIGNED epoch (5), not the forged tag (9999). With
    // minEpoch:10, the real epoch 5 <= 10 → REJECTED. Trusting the tag (9999 > 10) would WRONGLY accept.
    expect(
      parseFilterPublication(forged, {
        namespace: NAMESPACE,
        serverId: SERVER_ID,
        minEpoch: 10,
        requireAuthorIsSigner: false,
      }),
    ).toBeNull()
  })

  it('defense-in-depth: a forged epoch TAG that DISAGREES with the blob → null even with no minEpoch', () => {
    const server = freshKeypair()
    const blob = buildSignedBlob([freshKeypair().pk], server.priv, 5)
    const template = buildFilterPublication({
      namespace: NAMESPACE,
      serverId: SERVER_ID,
      blob,
      keyed: false,
      epoch: 9999, // disagrees with the blob's signed epoch (5)
    })
    const forged = fromWire(finalizeEvent(template, generateSecretKey()))
    // Even WITHOUT a minEpoch, a tag/blob epoch disagreement is a tampering signal → reject.
    // requireAuthorIsSigner:false isolates this from the separate author-binding guard.
    expect(
      parseFilterPublication(forged, { namespace: NAMESPACE, serverId: SERVER_ID, requireAuthorIsSigner: false }),
    ).toBeNull()
  })

  it('defense-in-depth: a forged KEYED tag that DISAGREES with the blob → null', () => {
    const server = freshKeypair()
    // Build an OPEN (unkeyed) blob → blob.keyed === false …
    const blob = buildSignedBlob([freshKeypair().pk], server.priv, 7)
    expect(parseFilter(blob).keyed).toBe(false)
    // … but forge the keyed TAG to '1' (claims keyed). Tag disagrees with the signed flag → reject.
    const template = buildFilterPublication({
      namespace: NAMESPACE,
      serverId: SERVER_ID,
      blob,
      keyed: true, // FORGED — blob is actually open
      epoch: 7,
    })
    const forged = fromWire(finalizeEvent(template, generateSecretKey()))
    expect(
      parseFilterPublication(forged, { namespace: NAMESPACE, serverId: SERVER_ID, requireAuthorIsSigner: false }),
    ).toBeNull()
  })

  it('uses the SIGNED blob epoch/keyed for the returned FilterPublication (well-formed, agreeing tags)', () => {
    const server = freshKeypair()
    // A genuine, keyed publication where the tags AGREE with the signed blob.
    const blob = buildSignedBlob([freshKeypair().pk, freshKeypair().pk], server.priv, 42, SALT)
    const pf = parseFilter(blob)
    expect(pf.epoch).toBe(42)
    expect(pf.keyed).toBe(true)
    const template = buildFilterPublication({
      namespace: NAMESPACE,
      serverId: SERVER_ID,
      blob,
      keyed: true,
      epoch: 42,
    })
    // Signed by the server's own key — the genuine-publication shape (see requireAuthorIsSigner note).
    const signed = fromWire(finalizeEvent(template, server.sk))
    const parsed = parseFilterPublication(signed, { namespace: NAMESPACE, serverId: SERVER_ID })
    expect(parsed).not.toBeNull()
    // The returned epoch/keyed are the SIGNED values (which here equal the agreeing tags).
    expect(parsed!.epoch).toBe(42)
    expect(parsed!.keyed).toBe(true)
    // And the rollback guard now compares the SIGNED epoch (42): minEpoch 41 accepts, 42 rejects.
    expect(parseFilterPublication(signed, { namespace: NAMESPACE, serverId: SERVER_ID, minEpoch: 41 })).not.toBeNull()
    expect(parseFilterPublication(signed, { namespace: NAMESPACE, serverId: SERVER_ID, minEpoch: 42 })).toBeNull()
  })
})

// --- context + address binding (tessera-kit 0.2.0) ---------------------------------------------------
//
// tessera-kit 0.2.0 binds every filter-blob signature to a caller-supplied `context` (PROTOCOL.md
// §4.1/§4.3/§6). For the kindred convention `context = filterSignatureContext(namespace, serverId)`,
// identical to the d-tag value. `parseFilterPublicationResult`/`parseFilterPublication` build this
// `context` SOLELY from `opts.namespace`/`opts.serverId` — the address the CALLER asked for — never
// from the received event's own tags. The tests below exercise the two distinct layers this gives:
// (1) `buildFilterPublication`'s own build-time guard (a blob signed for the wrong deployment can't
// even be published), and (2) `parseFilterPublicationResult`'s consumer-side rejection of a blob
// whose crypto content doesn't match the context the caller actually asked for, regardless of what
// label a hostile relay dresses the event up in.
describe('parseFilterPublication — context binding (tessera-kit 0.2.0)', () => {
  it('REJECTS a blob signed for server A, presented under an event whose d-tag was REWRITTEN to server B — proves context comes from opts, not the event', () => {
    // `server` genuinely signs a blob for `(NAMESPACE, 'serverA')`'s context.
    const server = freshKeypair()
    const blobForA = buildSignedBlob(
      [freshKeypair().pk, freshKeypair().pk],
      server.priv,
      10,
      undefined,
      filterSignatureContext(NAMESPACE, 'serverA'),
    )

    // An attacker (or a relay under the same signing key) rewraps that SAME blob under an event whose
    // d-tag claims `serverB` instead — assembled BY HAND, since `buildFilterPublication` now refuses
    // to build this (see the previous describe block). Signed by the REAL server key, so the OUTER
    // NIP-01 signature and the in-blob signer agree (isolates this test from the separate
    // `author-not-signer` check) — the only thing wrong is the CONTEXT the blob was actually signed
    // for versus the address this event claims to be.
    const rewrapped = {
      kind: KINDRED_FILTER_KIND,
      tags: [
        ['d', filterSignatureContext(NAMESPACE, 'serverB')],
        ['n', NAMESPACE],
        ['epoch', '10'],
        ['keyed', '0'],
      ],
      content: base64.encode(blobForA),
      created_at: Math.floor(Date.now() / 1000),
    }
    const signed = fromWire(finalizeEvent(rewrapped, server.sk))

    // A consumer asking about server B (opts.serverId: 'serverB') builds context ONLY from that —
    // never from the d-tag above, even though the d-tag ALSO happens to say 'serverB'. Because the
    // blob's REAL signed context was 'serverA', the in-blob signature check fails no matter what the
    // event's own tag claims — the rejection is driven by `opts`, not by the (attacker-controlled)
    // tag agreeing with itself.
    expect(parseFilterPublication(signed, { namespace: NAMESPACE, serverId: 'serverB' })).toBeNull()
    expect(parseFilterPublicationResult(signed, { namespace: NAMESPACE, serverId: 'serverB' })).toEqual({
      ok: false,
      reason: 'bad-blob-signature',
    })
  })

  it('address-mismatch: the event d-tag does not equal filterSignatureContext(opts.namespace, opts.serverId)', () => {
    const server = freshKeypair()
    const blob = buildSignedBlob([freshKeypair().pk], server.priv, 1)
    const bad = {
      kind: KINDRED_FILTER_KIND,
      tags: [
        ['d', 'kindred:members:totally:different'],
        ['n', NAMESPACE],
        ['epoch', '1'],
        ['keyed', '0'],
      ],
      content: base64.encode(blob),
      created_at: Math.floor(Date.now() / 1000),
    }
    const signed = fromWire(finalizeEvent(bad, server.sk))
    expect(parseFilterPublicationResult(signed, { namespace: NAMESPACE, serverId: SERVER_ID })).toEqual({
      ok: false,
      reason: 'address-mismatch',
    })
  })

  it('address-mismatch: the d-tag is absent', () => {
    const server = freshKeypair()
    const blob = buildSignedBlob([freshKeypair().pk], server.priv, 1)
    const bad = {
      kind: KINDRED_FILTER_KIND,
      tags: [
        ['n', NAMESPACE],
        ['epoch', '1'],
        ['keyed', '0'],
      ],
      content: base64.encode(blob),
      created_at: Math.floor(Date.now() / 1000),
    }
    const signed = fromWire(finalizeEvent(bad, server.sk))
    expect(parseFilterPublicationResult(signed, { namespace: NAMESPACE, serverId: SERVER_ID })).toEqual({
      ok: false,
      reason: 'address-mismatch',
    })
  })

  it('author-not-signer: a genuinely-context-bound blob re-wrapped and signed by a DIFFERENT key', () => {
    const server = freshKeypair()
    const blob = buildSignedBlob([freshKeypair().pk], server.priv, 10) // context matches NAMESPACE/SERVER_ID
    const template = buildFilterPublication({ namespace: NAMESPACE, serverId: SERVER_ID, blob, keyed: false, epoch: 10 })
    const republished = fromWire(finalizeEvent(template, generateSecretKey()))
    expect(parseFilterPublicationResult(republished, { namespace: NAMESPACE, serverId: SERVER_ID })).toEqual({
      ok: false,
      reason: 'author-not-signer',
    })
  })

  it('accepts a re-signed republication when the caller opts out via requireAuthorIsSigner:false', () => {
    const server = freshKeypair()
    const blob = buildSignedBlob([freshKeypair().pk], server.priv, 10)
    const template = buildFilterPublication({ namespace: NAMESPACE, serverId: SERVER_ID, blob, keyed: false, epoch: 10 })
    const republished = fromWire(finalizeEvent(template, generateSecretKey()))
    const parsed = parseFilterPublication(republished, {
      namespace: NAMESPACE,
      serverId: SERVER_ID,
      requireAuthorIsSigner: false,
    })
    expect(parsed).not.toBeNull()
    expect(parsed!.serverId).toBe(SERVER_ID)
    expect(parsed!.signerPubkeyHex).toBe(server.pk)
  })

  it('REJECTS when the n tag disagrees with opts.namespace', () => {
    const server = freshKeypair()
    const blob = buildSignedBlob([freshKeypair().pk], server.priv, 1)
    const bad = {
      kind: KINDRED_FILTER_KIND,
      tags: [
        ['d', CONTEXT],
        ['n', 'com.different.namespace'], // disagrees with opts.namespace
        ['epoch', '1'],
        ['keyed', '0'],
      ],
      content: base64.encode(blob),
      created_at: Math.floor(Date.now() / 1000),
    }
    const signed = fromWire(finalizeEvent(bad, server.sk))
    expect(parseFilterPublication(signed, { namespace: NAMESPACE, serverId: SERVER_ID })).toBeNull()
  })
})

// --- parseFilterPublicationResult — one reason code per parseFilterPublication rejection path -------
//
// `parseFilterPublication` collapses every failure to `null`; `parseFilterPublicationResult` is the
// additive surface that names WHICH check failed. `non-finite-epoch` is documented, not exercised,
// below because a genuine wire event can never reach it through `parseFilter` as currently
// implemented — see its comment.
describe('parseFilterPublicationResult — reason codes', () => {
  it('invalid-opts: opts is missing entirely', () => {
    const server = freshKeypair()
    const blob = buildSignedBlob([freshKeypair().pk], server.priv, 100)
    const template = buildFilterPublication({ namespace: NAMESPACE, serverId: SERVER_ID, blob, keyed: false, epoch: 100 })
    const signed = fromWire(finalizeEvent(template, server.sk))
    expect(parseFilterPublicationResult(signed, undefined as unknown as { namespace: string; serverId: string })).toEqual({
      ok: false,
      reason: 'invalid-opts',
    })
  })

  it('invalid-opts: opts.namespace is an empty string', () => {
    const server = freshKeypair()
    const blob = buildSignedBlob([freshKeypair().pk], server.priv, 100)
    const template = buildFilterPublication({ namespace: NAMESPACE, serverId: SERVER_ID, blob, keyed: false, epoch: 100 })
    const signed = fromWire(finalizeEvent(template, server.sk))
    expect(parseFilterPublicationResult(signed, { namespace: '', serverId: SERVER_ID })).toEqual({
      ok: false,
      reason: 'invalid-opts',
    })
  })

  it('invalid-opts: opts.serverId is missing (not a string)', () => {
    const server = freshKeypair()
    const blob = buildSignedBlob([freshKeypair().pk], server.priv, 100)
    const template = buildFilterPublication({ namespace: NAMESPACE, serverId: SERVER_ID, blob, keyed: false, epoch: 100 })
    const signed = fromWire(finalizeEvent(template, server.sk))
    expect(
      parseFilterPublicationResult(signed, { namespace: NAMESPACE } as unknown as { namespace: string; serverId: string }),
    ).toEqual({ ok: false, reason: 'invalid-opts' })
  })

  it('bad-signature: a tampered event (bad id/sig)', () => {
    const server = freshKeypair()
    const blob = buildSignedBlob([freshKeypair().pk], server.priv, 100)
    const template = buildFilterPublication({ namespace: NAMESPACE, serverId: SERVER_ID, blob, keyed: false, epoch: 100 })
    const signed = fromWire(finalizeEvent(template, server.sk))
    const tampered: NostrEvent = { ...signed, created_at: signed.created_at + 1 }
    expect(parseFilterPublicationResult(tampered, { namespace: NAMESPACE, serverId: SERVER_ID })).toEqual({
      ok: false,
      reason: 'bad-signature',
    })
  })

  it('wrong-kind: a correctly-signed event of the wrong kind', () => {
    const server = freshKeypair()
    const blob = buildSignedBlob([freshKeypair().pk], server.priv, 100)
    const wrongKind = {
      kind: 1,
      tags: [
        ['d', CONTEXT],
        ['n', NAMESPACE],
        ['epoch', '100'],
        ['keyed', '0'],
      ],
      content: base64.encode(blob),
      created_at: Math.floor(Date.now() / 1000),
    }
    const signed = fromWire(finalizeEvent(wrongKind, server.sk))
    expect(parseFilterPublicationResult(signed, { namespace: NAMESPACE, serverId: SERVER_ID })).toEqual({
      ok: false,
      reason: 'wrong-kind',
    })
  })

  it('bad-content: an in-place content mutation on a stale-verifiedSymbol event slips past verifyEvent', () => {
    // A real wire event can NEVER reach this: nostr-tools' `verifyEvent` recomputes the event id via
    // `validateEvent`, which requires `content` to be a string, so a non-string content always fails
    // step 2 (`bad-signature`) first. This check exists as defense-in-depth against a CALLER bug —
    // reusing a `finalizeEvent` object (which carries an internal `verifiedSymbol:true` cache) directly
    // and mutating it afterwards, rather than treating it as immutable / wire-cloning it first (see the
    // `fromWire` helper's doc comment, and `verifyBondAttestation`'s doc comment in ./invite.ts for the
    // same caveat). Deliberately NOT using `fromWire` here — that is the point of this test.
    const server = freshKeypair()
    const blob = buildSignedBlob([freshKeypair().pk], server.priv, 1)
    const template = buildFilterPublication({ namespace: NAMESPACE, serverId: SERVER_ID, blob, keyed: false, epoch: 1 })
    const signed = finalizeEvent(template, server.sk) as unknown as NostrEvent
    ;(signed as unknown as { content: unknown }).content = 12345
    expect(parseFilterPublicationResult(signed, { namespace: NAMESPACE, serverId: SERVER_ID })).toEqual({
      ok: false,
      reason: 'bad-content',
    })
  })

  it('bad-blob: non-base64 / undecodable content', () => {
    const bad = {
      kind: KINDRED_FILTER_KIND,
      tags: [
        ['d', CONTEXT],
        ['n', NAMESPACE],
        ['epoch', '100'],
        ['keyed', '0'],
      ],
      content: '@@@not base64@@@',
      created_at: Math.floor(Date.now() / 1000),
    }
    const signed = fromWire(finalizeEvent(bad, generateSecretKey()))
    expect(parseFilterPublicationResult(signed, { namespace: NAMESPACE, serverId: SERVER_ID })).toEqual({
      ok: false,
      reason: 'bad-blob',
    })
  })

  it('bad-blob-signature: a tampered fingerprint byte invalidates the in-blob Schnorr sig', () => {
    const server = freshKeypair()
    const blob = buildSignedBlob([freshKeypair().pk, freshKeypair().pk], server.priv, 100)
    const tamperedBlob = new Uint8Array(blob)
    tamperedBlob[140] = tamperedBlob[140]! ^ 0xff
    // Built by hand — `buildFilterPublication` would itself refuse a blob that fails to verify.
    const bad = {
      kind: KINDRED_FILTER_KIND,
      tags: [
        ['d', CONTEXT],
        ['n', NAMESPACE],
        ['epoch', '100'],
        ['keyed', '0'],
      ],
      content: base64.encode(tamperedBlob),
      created_at: Math.floor(Date.now() / 1000),
    }
    const signed = fromWire(finalizeEvent(bad, generateSecretKey()))
    expect(parseFilterPublicationResult(signed, { namespace: NAMESPACE, serverId: SERVER_ID })).toEqual({
      ok: false,
      reason: 'bad-blob-signature',
    })
  })

  it('unparseable-blob: a self-consistently-signed blob whose length disagrees with its own header geometry', () => {
    // verifyFilterBlob only checks the Schnorr signature over [0,64) + sha256([128,end)) — it does NOT
    // validate KFLT header geometry, so it is happy to sign (and verify) a blob with GARBAGE trailing
    // bytes appended after the real fingerprint array. `parseFilter` recomputes the expected length from
    // the header and rejects the mismatch. This is exactly how a blob can pass the signature check and
    // still fail the structural parse.
    const server = freshKeypair()
    const filt = buildMembershipFilter([memberKey(freshKeypair().pk)], { epoch: 1 })
    const unsigned = serializeFilter(filt)
    const withGarbage = new Uint8Array(unsigned.length + 8)
    withGarbage.set(unsigned)
    withGarbage.set([1, 2, 3, 4, 5, 6, 7, 8], unsigned.length)
    const blob = signFilterBlob(withGarbage, server.priv, CONTEXT)
    expect(verifyFilterBlob(blob, CONTEXT).ok).toBe(true) // signature covers the WHOLE (garbage-padded) buffer
    expect(() => parseFilter(blob)).toThrow(/length mismatch/)

    const template = buildFilterPublication({ namespace: NAMESPACE, serverId: SERVER_ID, blob, keyed: false, epoch: 1 })
    const signed = fromWire(finalizeEvent(template, server.sk))
    expect(parseFilterPublicationResult(signed, { namespace: NAMESPACE, serverId: SERVER_ID })).toEqual({
      ok: false,
      reason: 'unparseable-blob',
    })
  })

  // non-finite-epoch is unreachable through a genuine tessera-kit blob: `parseFilter` always returns
  // `epoch` via `Number(dataView.getBigUint64(...))`, and every u64 value converts to a finite Number
  // (u64's max is ~1.8e19, far under Number.MAX_VALUE) — so `Number.isFinite(signedEpoch)` can never be
  // false for real tessera-kit output. The check is kept as defense-in-depth against a future codec
  // change (or a hostile tessera-kit build) that stops guaranteeing that, not something reachable today.

  it('n-tag-mismatch: the n tag disagrees with opts.namespace', () => {
    const server = freshKeypair()
    const blob = buildSignedBlob([freshKeypair().pk], server.priv, 1)
    const bad = {
      kind: KINDRED_FILTER_KIND,
      tags: [
        ['d', CONTEXT],
        ['n', 'com.different.namespace'],
        ['epoch', '1'],
        ['keyed', '0'],
      ],
      content: base64.encode(blob),
      created_at: Math.floor(Date.now() / 1000),
    }
    const signed = fromWire(finalizeEvent(bad, server.sk))
    expect(parseFilterPublicationResult(signed, { namespace: NAMESPACE, serverId: SERVER_ID })).toEqual({
      ok: false,
      reason: 'n-tag-mismatch',
    })
  })

  it('epoch-tag-mismatch: a forged epoch tag disagreeing with the blob signed epoch', () => {
    const server = freshKeypair()
    const blob = buildSignedBlob([freshKeypair().pk], server.priv, 5)
    const template = buildFilterPublication({ namespace: NAMESPACE, serverId: SERVER_ID, blob, keyed: false, epoch: 9999 })
    const forged = fromWire(finalizeEvent(template, generateSecretKey()))
    expect(
      parseFilterPublicationResult(forged, { namespace: NAMESPACE, serverId: SERVER_ID, requireAuthorIsSigner: false }),
    ).toEqual({
      ok: false,
      reason: 'epoch-tag-mismatch',
    })
  })

  it('keyed-tag-mismatch: a forged keyed tag disagreeing with the blob signed keyed flag', () => {
    const server = freshKeypair()
    const blob = buildSignedBlob([freshKeypair().pk], server.priv, 7)
    const template = buildFilterPublication({ namespace: NAMESPACE, serverId: SERVER_ID, blob, keyed: true, epoch: 7 })
    const forged = fromWire(finalizeEvent(template, generateSecretKey()))
    expect(
      parseFilterPublicationResult(forged, { namespace: NAMESPACE, serverId: SERVER_ID, requireAuthorIsSigner: false }),
    ).toEqual({
      ok: false,
      reason: 'keyed-tag-mismatch',
    })
  })

  it('stale-epoch: the signed epoch is <= opts.minEpoch', () => {
    const server = freshKeypair()
    const blob = buildSignedBlob([freshKeypair().pk], server.priv, 50)
    const template = buildFilterPublication({ namespace: NAMESPACE, serverId: SERVER_ID, blob, keyed: false, epoch: 50 })
    const signed = fromWire(finalizeEvent(template, server.sk))
    expect(
      parseFilterPublicationResult(signed, { namespace: NAMESPACE, serverId: SERVER_ID, minEpoch: 50 }),
    ).toEqual({ ok: false, reason: 'stale-epoch' })
  })

  it('ok:true carries the same value parseFilterPublication returns', () => {
    const server = freshKeypair()
    const blob = buildSignedBlob([freshKeypair().pk], server.priv, 3)
    const template = buildFilterPublication({ namespace: NAMESPACE, serverId: SERVER_ID, blob, keyed: false, epoch: 3 })
    const signed = fromWire(finalizeEvent(template, server.sk))
    const result = parseFilterPublicationResult(signed, { namespace: NAMESPACE, serverId: SERVER_ID })
    expect(result.ok).toBe(true)
    if (result.ok) {
      expect(result.value).toEqual(parseFilterPublication(signed, { namespace: NAMESPACE, serverId: SERVER_ID }))
    }
  })
})

// --- filterSignatureContext -----------------------------------------------------------------------

describe('filterSignatureContext', () => {
  it('equals the d-tag value buildFilterPublication emits — the two can never drift apart', () => {
    const server = freshKeypair()
    const blob = buildSignedBlob([freshKeypair().pk], server.priv, 1)
    const template = buildFilterPublication({ namespace: NAMESPACE, serverId: SERVER_ID, blob, keyed: false, epoch: 1 })
    const dTag = template.tags.find((t) => t[0] === 'd')
    expect(dTag).toEqual(['d', filterSignatureContext(NAMESPACE, SERVER_ID)])
  })

  it('is exactly "kindred:members:<namespace>:<serverId>"', () => {
    expect(filterSignatureContext('com.example.game', 'play.example.com')).toBe(
      'kindred:members:com.example.game:play.example.com',
    )
  })
})

// --- aggregatorQuery + buildOptOutRequest ---------------------------------------------------------

describe('aggregatorQuery', () => {
  it('queries by kind and the indexable #n namespace tag', () => {
    expect(aggregatorQuery(NAMESPACE)).toEqual({
      kinds: [KINDRED_FILTER_KIND],
      '#n': [NAMESPACE],
    })
  })
})

describe('buildOptOutRequest', () => {
  it('builds a kind-30445 EventTemplate with the d-tag, a self-identifying p-tag, and opt-out content', () => {
    const member = freshKeypair()
    const template = buildOptOutRequest({ namespace: NAMESPACE, serverId: SERVER_ID }, member.priv)
    expect(template.kind).toBe(KINDRED_OPTOUT_KIND)
    expect(template.content).toBe('opt-out')
    expect(template.created_at).toBeTypeOf('number')
    const dTag = template.tags.find((t) => t[0] === 'd')
    const pTag = template.tags.find((t) => t[0] === 'p')
    expect(dTag).toEqual(['d', `kindred:members:${NAMESPACE}:${SERVER_ID}`])
    // The p-tag self-identifies the opter as the member's own x-only pubkey.
    expect(pTag).toEqual(['p', member.pk])
  })

  it('rejects a non-64-hex memberPrivHex', () => {
    expect(() => buildOptOutRequest({ namespace: NAMESPACE, serverId: SERVER_ID }, 'nothex')).toThrow()
    expect(() =>
      buildOptOutRequest({ namespace: NAMESPACE, serverId: SERVER_ID }, 'ab'.repeat(31)),
    ).toThrow()
  })

  it('REJECTS a namespace containing a colon (d-tag misparse guard, L5 audit finding — mirrors buildFilterPublication)', () => {
    const member = freshKeypair()
    expect(() =>
      buildOptOutRequest({ namespace: 'com:evil', serverId: SERVER_ID }, member.priv),
    ).toThrow(/namespace must not contain a colon/i)
    expect(() =>
      buildOptOutRequest({ namespace: NAMESPACE, serverId: SERVER_ID }, member.priv),
    ).not.toThrow()
  })

  it('produces a template that finalizes into a valid signed event under the member key', () => {
    const member = freshKeypair()
    const template = buildOptOutRequest({ namespace: NAMESPACE, serverId: SERVER_ID }, member.priv)
    // The consumer signs the template with the SAME member key.
    const signed = fromWire(finalizeEvent(template, member.sk))
    expect(signed.pubkey).toBe(member.pk)
    // Round-trip the kind/tags through a real signed event.
    expect(signed.kind).toBe(KINDRED_OPTOUT_KIND)
  })
})

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
  aggregatorQuery,
  buildOptOutRequest,
} from './discovery.js'
import type { KindredEntry, KinEntry, KithEntry, KenEntry, NostrEvent } from './types.js'

// --- Fixtures -------------------------------------------------------------------------------------

const NAMESPACE = 'com.example.game'
const SERVER_ID = 'play.example.com'
const SALT = 'deadbeefcafe' // keyed-pool salt (even-length hex)

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
 */
function buildSignedBlob(
  memberPubkeys: string[],
  serverPriv: string,
  epoch: number,
  salt?: string,
): Uint8Array {
  const keys = memberPubkeys.map((pk) => memberKey(pk, salt))
  const filt = buildMembershipFilter(keys, salt === undefined ? { epoch } : { epoch, salt })
  return signFilterBlob(serializeFilter(filt), serverPriv)
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
})

// --- disclosureFor: honest privacy surface --------------------------------------------------------

describe('disclosureFor — honest disclosure surface', () => {
  it('reports an OPEN pool: not keyed, cross-server discoverable', () => {
    const d = disclosureFor({})
    expect(d).toEqual({
      keyed: false,
      crossServerDiscoverable: true,
      optIn: true,
      canExit: true,
    })
  })

  it('reports a KEYED pool: keyed, NOT cross-server discoverable', () => {
    const d = disclosureFor({ salt: SALT })
    expect(d).toEqual({
      keyed: true,
      crossServerDiscoverable: false,
      optIn: true,
      canExit: true,
    })
  })

  it('treats an empty-string salt as keyed (salt presence, not content)', () => {
    expect(disclosureFor({ salt: '' }).keyed).toBe(true)
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

    // The publisher's Nostr key signs the event (separate from the in-blob server key).
    const publisherSk = generateSecretKey()
    const signed = fromWire(finalizeEvent(template, publisherSk))

    const parsed = parseFilterPublication(signed)
    expect(parsed).not.toBeNull()
    expect(parsed!.namespace).toBe(NAMESPACE)
    expect(parsed!.serverId).toBe(SERVER_ID)
    expect(parsed!.epoch).toBe(1234)
    expect(parsed!.keyed).toBe(false)
    // signerPubkeyHex is the IN-BLOB server key (provenance), not the event/publisher key.
    expect(parsed!.signerPubkeyHex).toBe(server.pk)

    // The blob round-trips byte-identically and re-verifies.
    expect(bytesToHex(parsed!.blob)).toBe(bytesToHex(blob))
    expect(verifyFilterBlob(parsed!.blob).ok).toBe(true)
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
    expect(nTag).toEqual(['n', NAMESPACE])
    expect(keyedTag).toEqual(['keyed', '1'])
    expect(epochTag).toEqual(['epoch', '5'])
    expect(template.content).toBe(base64.encode(blob))
  })

  it('REJECTS a namespace containing a colon (d-tag misparse guard); reverse-DNS is fine', () => {
    const server = freshKeypair()
    const blob = buildSignedBlob([freshKeypair().pk], server.priv, 1, SALT)
    // A namespace with a colon would shift the `kindred:members:<ns>:<serverId>` boundary that
    // parseFilterPublication splits on (first colon after the prefix) → mis-parse. Reject at build.
    expect(() =>
      buildFilterPublication({ namespace: 'com:evil', serverId: SERVER_ID, blob, keyed: true, epoch: 1 }),
    ).toThrow(/namespace must not contain a colon/i)
    // A normal reverse-DNS namespace (colon-free) builds fine.
    expect(() =>
      buildFilterPublication({ namespace: 'com.example.game', serverId: SERVER_ID, blob, keyed: true, epoch: 1 }),
    ).not.toThrow()
  })

  it('round-trips keyed:true and a serverId containing colons (split on the prefix only)', () => {
    const server = freshKeypair()
    const blob = buildSignedBlob([freshKeypair().pk], server.priv, 9, SALT)
    const colonServer = 'wss://host:4848/path' // serverId with internal colons
    const template = buildFilterPublication({
      namespace: NAMESPACE,
      serverId: colonServer,
      blob,
      keyed: true,
      epoch: 9,
    })
    const signed = fromWire(finalizeEvent(template, generateSecretKey()))
    const parsed = parseFilterPublication(signed)
    expect(parsed).not.toBeNull()
    expect(parsed!.namespace).toBe(NAMESPACE)
    expect(parsed!.serverId).toBe(colonServer)
    expect(parsed!.keyed).toBe(true)
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
    const signed = fromWire(finalizeEvent(template, generateSecretKey()))
    return { signed, server, blob }
  }

  it('returns null for a BAD event signature (tampered created_at — content stays valid base64)', () => {
    // Tamper `created_at` rather than `content`: the content remains decodable base64 AND the in-blob
    // Schnorr sig stays valid, so the ONLY rejection path that can fire is the failed `verifyEvent`
    // (the event id no longer matches the signed payload). `signed` came through `fromWire`, so it
    // carries no nostr-tools verifiedSymbol cache — `verifyEvent` genuinely re-checks the signature.
    const { signed } = validSigned()
    const tampered: NostrEvent = { ...signed, created_at: signed.created_at + 1 }
    expect(parseFilterPublication(tampered)).toBeNull()
  })

  it('returns null for the WRONG kind', () => {
    const { server } = validSigned()
    const blob = buildSignedBlob([freshKeypair().pk], server.priv, 100)
    // Build an event with a non-30444 kind but otherwise correct shape, sign it for real.
    const wrongKind = {
      kind: 1,
      tags: [
        ['d', `kindred:members:${NAMESPACE}:${SERVER_ID}`],
        ['n', NAMESPACE],
        ['epoch', '100'],
        ['keyed', '0'],
      ],
      content: base64.encode(blob),
      created_at: Math.floor(Date.now() / 1000),
    }
    const signed = fromWire(finalizeEvent(wrongKind, generateSecretKey()))
    expect(parseFilterPublication(signed)).toBeNull()
  })

  it('returns null when the IN-BLOB Schnorr signature is invalid (tamper a blob byte)', () => {
    const server = freshKeypair()
    const blob = buildSignedBlob([freshKeypair().pk, freshKeypair().pk], server.priv, 100)
    // Flip a byte in the fingerprint array (offset >= 128) so the in-blob sig no longer verifies,
    // but the OUTER nostr event is freshly + validly signed over the tampered content.
    const tamperedBlob = new Uint8Array(blob)
    tamperedBlob[140] = tamperedBlob[140]! ^ 0xff
    expect(verifyFilterBlob(tamperedBlob).ok).toBe(false)

    const template = buildFilterPublication({
      namespace: NAMESPACE,
      serverId: SERVER_ID,
      blob: tamperedBlob,
      keyed: false,
      epoch: 100,
    })
    const signed = fromWire(finalizeEvent(template, generateSecretKey()))
    expect(parseFilterPublication(signed)).toBeNull()
  })

  it('returns null for non-base64 / undecodable content (with a valid event sig)', () => {
    const bad = {
      kind: KINDRED_FILTER_KIND,
      tags: [
        ['d', `kindred:members:${NAMESPACE}:${SERVER_ID}`],
        ['n', NAMESPACE],
        ['epoch', '100'],
        ['keyed', '0'],
      ],
      content: '@@@not base64@@@',
      created_at: Math.floor(Date.now() / 1000),
    }
    const signed = fromWire(finalizeEvent(bad, generateSecretKey()))
    expect(parseFilterPublication(signed)).toBeNull()
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
    expect(parseFilterPublication(signed)).toBeNull()
  })

  it('enforces epoch monotonicity: returns null when epoch <= minEpoch, accepts when greater', () => {
    const { signed } = validSigned(50)
    // epoch (50) <= minEpoch (50) → reject (replay/rollback defense).
    expect(parseFilterPublication(signed, { minEpoch: 50 })).toBeNull()
    // epoch (50) <= minEpoch (60) → reject.
    expect(parseFilterPublication(signed, { minEpoch: 60 })).toBeNull()
    // epoch (50) > minEpoch (49) → accept.
    const ok = parseFilterPublication(signed, { minEpoch: 49 })
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
// blob's SIGNED epoch (5), so the stale blob is rejected. (namespace/serverId still come from the
// d-tag — they aren't in the blob; unchanged.)
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

    // The rollback guard must use the blob's SIGNED epoch (5), not the forged tag (9999). With
    // minEpoch:10, the real epoch 5 <= 10 → REJECTED. Trusting the tag (9999 > 10) would WRONGLY accept.
    expect(parseFilterPublication(forged, { minEpoch: 10 })).toBeNull()
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
    expect(parseFilterPublication(forged)).toBeNull()
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
    expect(parseFilterPublication(forged)).toBeNull()
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
    const signed = fromWire(finalizeEvent(template, generateSecretKey()))
    const parsed = parseFilterPublication(signed)
    expect(parsed).not.toBeNull()
    // The returned epoch/keyed are the SIGNED values (which here equal the agreeing tags).
    expect(parsed!.epoch).toBe(42)
    expect(parsed!.keyed).toBe(true)
    // And the rollback guard now compares the SIGNED epoch (42): minEpoch 41 accepts, 42 rejects.
    expect(parseFilterPublication(signed, { minEpoch: 41 })).not.toBeNull()
    expect(parseFilterPublication(signed, { minEpoch: 42 })).toBeNull()
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

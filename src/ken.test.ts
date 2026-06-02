// kindred ./ken — tests.
//
// `ken` is the ONE-WAY recognition tier: pin a public key you didn't bond with (a public figure,
// an org, a NIP-05 handle), then (a) prove LIVE control of that key with a fresh challenge nonce
// (impersonation-resistant — replay-impossible), (b) attribute possibly-OLD signed artifacts to the
// CURRENT pin only, and (c) rotate/revoke safely (propose-not-auto-flip; fail-closed on revoke).
//
// Every signed event in these tests is a REAL nostr event built with `finalizeEvent` over a freshly
// generated secp256k1 keypair (`generateSecretKey`/`getPublicKey`), so `verifyEvent` exercises a true
// Schnorr signature + event-id check — not a mock.

import { describe, it, expect } from 'vitest'
import { finalizeEvent, generateSecretKey, getPublicKey } from 'nostr-tools/pure'
import {
  pinKen,
  pinKenFromNip05,
  buildKeyControlChallenge,
  verifyKeyControl,
  attributeSignature,
  resolveKen,
  acceptKenRotation,
  revokeKen,
  dropKen,
} from './ken.js'
import type { KenEntry, NostrEvent } from './types.js'

// --- Fixtures -------------------------------------------------------------------------------------

const OWNER = 'aa'.repeat(32) // one of MY persona pubkeys (any 64-hex; not signature-checked here)

/** A fresh real keypair: returns the 32-byte secret and its 64-hex x-only pubkey. */
function freshKeypair(): { sk: Uint8Array; pk: string } {
  const sk = generateSecretKey()
  return { sk, pk: getPublicKey(sk) }
}

/** Build a real, signed nostr event whose `content` is `content`, signed by `sk`. */
function signEvent(sk: Uint8Array, content: string) {
  return finalizeEvent(
    { kind: 1, tags: [], content, created_at: Math.floor(Date.now() / 1000) },
    sk,
  )
}

/**
 * Model an event as it would arrive FROM THE WIRE: a plain JSON object with no in-process trust.
 *
 * `finalizeEvent` returns a `VerifiedEvent` carrying nostr-tools' internal `verifiedSymbol: true`
 * cache; `verifyEvent` short-circuits on that symbol and SKIPS re-checking the signature. A real
 * attacker-supplied event is just deserialized JSON (no symbol), so any tampering we want
 * `verifyEvent` to actually catch must be applied to a wire-shaped clone — otherwise the stale cache
 * would make a tampered event spuriously "verify". This round-trip drops the symbol and tampers.
 */
function tamperedFromWire(
  ev: ReturnType<typeof signEvent>,
  mutate: (e: Record<string, unknown>) => void,
): NostrEvent {
  const wire = JSON.parse(JSON.stringify(ev)) as Record<string, unknown>
  mutate(wire)
  return wire as unknown as NostrEvent
}

/** Pin a manual-provenance ken for a given pubkey (the common test setup). */
function pinManual(pubkeyHex: string, extra?: Partial<KenEntry>): KenEntry {
  return {
    ...pinKen({
      pubkeyHex,
      ownerPubkeyHex: OWNER,
      provenance: { source: 'manual', locator: 'met at a talk', confirmedAt: 1_700_000_000 },
    }),
    ...extra,
  }
}

/** A fake `fetch` that returns one well-known nostr.json body for any URL. */
function fakeFetchJson(body: unknown, status = 200): typeof globalThis.fetch {
  return (async () =>
    ({
      ok: status >= 200 && status < 300,
      status,
      json: async () => body,
    }) as Response) as typeof globalThis.fetch
}

// --- pinKen ---------------------------------------------------------------------------------------

describe('pinKen', () => {
  it('builds a tier:ken entry with provenance + addedAt', () => {
    const { pk } = freshKeypair()
    const entry = pinKen({
      pubkeyHex: pk,
      ownerPubkeyHex: OWNER,
      displayName: 'Alice Org',
      provenance: { source: 'manual', locator: 'business card', confirmedAt: 1_700_000_000 },
    })
    expect(entry.tier).toBe('ken')
    expect(entry.pubkey).toBe(pk)
    expect(entry.ownerPubkey).toBe(OWNER)
    expect(entry.displayName).toBe('Alice Org')
    expect(entry.provenance).toEqual({ source: 'manual', locator: 'business card', confirmedAt: 1_700_000_000 })
    expect(typeof entry.addedAt).toBe('number')
    expect(Number.isInteger(entry.addedAt)).toBe(true)
    // ken is one-way: NO shared secret ever.
    expect('sharedSecret' in entry).toBe(false)
  })

  it('lowercase-normalizes the pinned + owner pubkeys', () => {
    const { pk } = freshKeypair()
    const entry = pinKen({
      pubkeyHex: pk.toUpperCase(),
      ownerPubkeyHex: OWNER.toUpperCase(),
      provenance: { source: 'manual', locator: 'x', confirmedAt: 1 },
    })
    expect(entry.pubkey).toBe(pk)
    expect(entry.ownerPubkey).toBe(OWNER)
  })

  it('carries an optional nip05 when provided', () => {
    const { pk } = freshKeypair()
    const entry = pinKen({
      pubkeyHex: pk,
      ownerPubkeyHex: OWNER,
      nip05: 'alice@example.com',
      provenance: { source: 'nip05', locator: 'alice@example.com', confirmedAt: 1 },
    })
    expect(entry.nip05).toBe('alice@example.com')
  })

  it('rejects a malformed pinned pubkey (bad hex / wrong length)', () => {
    expect(() =>
      pinKen({ pubkeyHex: 'nothex', ownerPubkeyHex: OWNER, provenance: { source: 'manual', locator: 'x', confirmedAt: 1 } }),
    ).toThrow(/64 hex/)
    expect(() =>
      pinKen({ pubkeyHex: 'ab'.repeat(31), ownerPubkeyHex: OWNER, provenance: { source: 'manual', locator: 'x', confirmedAt: 1 } }),
    ).toThrow(/64 hex/)
  })

  it('rejects a malformed owner pubkey', () => {
    const { pk } = freshKeypair()
    expect(() =>
      pinKen({ pubkeyHex: pk, ownerPubkeyHex: 'short', provenance: { source: 'manual', locator: 'x', confirmedAt: 1 } }),
    ).toThrow(/64 hex/)
  })
})

// --- buildKeyControlChallenge ---------------------------------------------------------------------

describe('buildKeyControlChallenge', () => {
  it('returns a 32-byte (64 hex) nonce + integer createdAt', () => {
    const c = buildKeyControlChallenge()
    expect(c.nonce).toMatch(/^[0-9a-f]{64}$/)
    expect(Number.isInteger(c.createdAt)).toBe(true)
  })

  it('returns a fresh random nonce each call (replay defence relies on this)', () => {
    const a = buildKeyControlChallenge()
    const b = buildKeyControlChallenge()
    expect(a.nonce).not.toBe(b.nonce)
  })
})

// --- verifyKeyControl (LIVE control; fail-closed) -------------------------------------------------

describe('verifyKeyControl — proves LIVE key control (replay-resistant)', () => {
  it('proven:true when the pinned key signs an event whose content === nonce', () => {
    const { sk, pk } = freshKeypair()
    const entry = pinManual(pk)
    const { nonce } = buildKeyControlChallenge()
    const ev = signEvent(sk, nonce)
    expect(verifyKeyControl(entry, nonce, ev)).toEqual({ proven: true })
  })

  it('nonce-mismatch when the signed content is not exactly the challenge nonce', () => {
    const { sk, pk } = freshKeypair()
    const entry = pinManual(pk)
    const { nonce } = buildKeyControlChallenge()
    const ev = signEvent(sk, 'some other content') // valid sig, wrong content
    expect(verifyKeyControl(entry, nonce, ev)).toEqual({ proven: false, reason: 'nonce-mismatch' })
  })

  it('pubkey-not-current-pin when a DIFFERENT key signs the nonce', () => {
    const pinned = freshKeypair()
    const impostor = freshKeypair()
    const entry = pinManual(pinned.pk)
    const { nonce } = buildKeyControlChallenge()
    const ev = signEvent(impostor.sk, nonce) // impostor signs the fresh nonce correctly...
    // ...but it's not the pinned key → fail closed.
    expect(verifyKeyControl(entry, nonce, ev)).toEqual({ proven: false, reason: 'pubkey-not-current-pin' })
  })

  it('does NOT accept a previousPubkeys key (must be the CURRENT pin)', () => {
    const old = freshKeypair()
    const cur = freshKeypair()
    const entry = pinManual(cur.pk, { previousPubkeys: [old.pk] })
    const { nonce } = buildKeyControlChallenge()
    const ev = signEvent(old.sk, nonce)
    expect(verifyKeyControl(entry, nonce, ev)).toEqual({ proven: false, reason: 'pubkey-not-current-pin' })
  })

  it('revoked when the entry is revoked (checked FIRST, before pubkey/nonce/sig)', () => {
    const { sk, pk } = freshKeypair()
    const entry = pinManual(pk, { revoked: true })
    const { nonce } = buildKeyControlChallenge()
    const ev = signEvent(sk, nonce) // even a perfect proof must fail closed once revoked
    expect(verifyKeyControl(entry, nonce, ev)).toEqual({ proven: false, reason: 'revoked' })
  })

  it('bad-signature when the event is tampered after signing (content mutated, not re-signed)', () => {
    const { sk, pk } = freshKeypair()
    const entry = pinManual(pk)
    const { nonce } = buildKeyControlChallenge()
    const ev = signEvent(sk, nonce)
    // Tamper: keep content === nonce (so the nonce check passes) but corrupt the signature so the
    // sig/id binding breaks. Applied to a wire-shaped clone so verifyEvent actually re-checks.
    const tampered = tamperedFromWire(ev, (e) => {
      e.sig = (ev.sig.slice(0, -1) + (ev.sig.endsWith('a') ? 'b' : 'a'))
    })
    const r = verifyKeyControl(entry, nonce, tampered)
    expect(r).toEqual({ proven: false, reason: 'bad-signature' })
  })
})

// --- attributeSignature (possibly-OLD artifact; current-pin only) ---------------------------------

describe('attributeSignature — attributes a signed artifact to the CURRENT pin only', () => {
  it('genuine:true for an event signed by the current pin', () => {
    const { sk, pk } = freshKeypair()
    const entry = pinManual(pk)
    const ev = signEvent(sk, 'a signed statement from the figure')
    expect(attributeSignature(entry, ev)).toEqual({ genuine: true })
  })

  it('rotated-away-key for an event whose pubkey is in previousPubkeys', () => {
    const old = freshKeypair()
    const cur = freshKeypair()
    const entry = pinManual(cur.pk, { previousPubkeys: [old.pk] })
    const ev = signEvent(old.sk, 'old statement')
    expect(attributeSignature(entry, ev)).toEqual({ genuine: false, reason: 'rotated-away-key' })
  })

  it('revoked (checked first) even for an otherwise-genuine current-pin event', () => {
    const { sk, pk } = freshKeypair()
    const entry = pinManual(pk, { revoked: true })
    const ev = signEvent(sk, 'statement')
    expect(attributeSignature(entry, ev)).toEqual({ genuine: false, reason: 'revoked' })
  })

  it('pubkey-mismatch for an unrelated key (not the pin, not a previous key)', () => {
    const { pk } = freshKeypair()
    const other = freshKeypair()
    const entry = pinManual(pk)
    const ev = signEvent(other.sk, 'statement')
    expect(attributeSignature(entry, ev)).toEqual({ genuine: false, reason: 'pubkey-mismatch' })
  })

  it('bad-signature for a current-pin event with a broken signature', () => {
    const { sk, pk } = freshKeypair()
    const entry = pinManual(pk)
    const ev = signEvent(sk, 'statement')
    // Mutate content on a wire-shaped clone: id/sig no longer match → verifyEvent rejects.
    const tampered = tamperedFromWire(ev, (e) => {
      e.content = 'a different statement'
    })
    expect(attributeSignature(entry, tampered)).toEqual({ genuine: false, reason: 'bad-signature' })
  })
})

// --- pinKenFromNip05 (TOFU anchor; https-only; refuse-on-mismatch) --------------------------------

describe('pinKenFromNip05', () => {
  it('pins when nostr.json resolves the local name to a 64-hex pubkey', async () => {
    const { pk } = freshKeypair()
    const fetch = fakeFetchJson({ names: { alice: pk } })
    const entry = await pinKenFromNip05('alice@example.com', OWNER, fetch)
    expect(entry.tier).toBe('ken')
    expect(entry.pubkey).toBe(pk)
    expect(entry.nip05).toBe('alice@example.com')
    expect(entry.provenance.source).toBe('nip05')
    expect(entry.provenance.locator).toBe('alice@example.com')
  })

  it('lowercase-normalizes a mixed-case resolved pubkey', async () => {
    const { pk } = freshKeypair()
    const fetch = fakeFetchJson({ names: { alice: pk.toUpperCase() } })
    const entry = await pinKenFromNip05('alice@example.com', OWNER, fetch)
    expect(entry.pubkey).toBe(pk)
  })

  it('throws when the name is present but not 64-hex', async () => {
    const fetch = fakeFetchJson({ names: { alice: 'not-a-valid-pubkey' } })
    await expect(pinKenFromNip05('alice@example.com', OWNER, fetch)).rejects.toThrow()
  })

  it('throws when the local name is absent from names', async () => {
    const { pk } = freshKeypair()
    const fetch = fakeFetchJson({ names: { bob: pk } }) // alice not present
    await expect(pinKenFromNip05('alice@example.com', OWNER, fetch)).rejects.toThrow()
  })

  it('throws when names is not an object (malformed body)', async () => {
    const fetch = fakeFetchJson({ names: 'oops' })
    await expect(pinKenFromNip05('alice@example.com', OWNER, fetch)).rejects.toThrow()
  })

  it('throws when the body is not an object at all', async () => {
    const fetch = fakeFetchJson(42)
    await expect(pinKenFromNip05('alice@example.com', OWNER, fetch)).rejects.toThrow()
  })

  it('requests the well-known nostr.json over HTTPS only (no http scheme path)', async () => {
    // NIP-05 carries no scheme — the resolver MUST construct an https:// URL. Assert it does by
    // capturing the URL the injected fetch is asked for.
    const { pk } = freshKeypair()
    let requestedUrl = ''
    const fetch = (async (input: string | URL | Request) => {
      requestedUrl = String(input)
      return { ok: true, status: 200, json: async () => ({ names: { alice: pk } }) } as Response
    }) as typeof globalThis.fetch
    await pinKenFromNip05('alice@example.com', OWNER, fetch)
    expect(requestedUrl.startsWith('https://')).toBe(true)
    expect(requestedUrl).toContain('/.well-known/nostr.json?name=alice')
  })

  it('throws on a malformed nip05 (no @, or empty local/domain)', async () => {
    const { pk } = freshKeypair()
    const fetch = fakeFetchJson({ names: { alice: pk } })
    await expect(pinKenFromNip05('not-an-nip05', OWNER, fetch)).rejects.toThrow(/nip05/i)
    await expect(pinKenFromNip05('@example.com', OWNER, fetch)).rejects.toThrow(/nip05/i)
    await expect(pinKenFromNip05('alice@', OWNER, fetch)).rejects.toThrow(/nip05/i)
  })

  it('throws when the HTTP response is not ok', async () => {
    const fetch = fakeFetchJson({}, 404)
    await expect(pinKenFromNip05('alice@example.com', OWNER, fetch)).rejects.toThrow()
  })
})

// --- resolveKen (propose-not-flip) ----------------------------------------------------------------

describe('resolveKen — re-resolves nip05; proposes rotation but never auto-flips', () => {
  it('proposes a rotation{accepted:false} when the resolved key differs — pubkey UNCHANGED', async () => {
    const original = freshKeypair()
    const rotated = freshKeypair()
    const entry = pinKen({
      pubkeyHex: original.pk,
      ownerPubkeyHex: OWNER,
      nip05: 'alice@example.com',
      provenance: { source: 'nip05', locator: 'alice@example.com', confirmedAt: 1 },
    })
    const fetch = fakeFetchJson({ names: { alice: rotated.pk } })
    const out = await resolveKen(entry, fetch)
    // CRITICAL: the pin must NOT move — a NIP-05 key change is an UNTRUSTED signal.
    expect(out.pubkey).toBe(original.pk)
    expect(out.rotation).toBeDefined()
    expect(out.rotation!.newPubkey).toBe(rotated.pk)
    expect(out.rotation!.accepted).toBe(false)
    expect(out.rotation!.via).toBe('nip05')
    expect(typeof out.rotation!.observedAt).toBe('number')
    expect(typeof out.lastResolvedAt).toBe('number')
  })

  it('no rotation when the resolved key matches the pin; sets lastResolvedAt', async () => {
    const { pk } = freshKeypair()
    const entry = pinKen({
      pubkeyHex: pk,
      ownerPubkeyHex: OWNER,
      nip05: 'alice@example.com',
      provenance: { source: 'nip05', locator: 'alice@example.com', confirmedAt: 1 },
    })
    const fetch = fakeFetchJson({ names: { alice: pk } })
    const out = await resolveKen(entry, fetch)
    expect(out.pubkey).toBe(pk)
    expect(out.rotation).toBeUndefined()
    expect(typeof out.lastResolvedAt).toBe('number')
  })

  it('returns the entry UNCHANGED when there is no nip05 to resolve', async () => {
    const { pk } = freshKeypair()
    const entry = pinManual(pk) // manual provenance, no nip05
    let called = false
    const fetch = (async () => {
      called = true
      return { ok: true, status: 200, json: async () => ({}) } as Response
    }) as typeof globalThis.fetch
    const out = await resolveKen(entry, fetch)
    expect(out).toBe(entry) // same reference — no work done
    expect(called).toBe(false) // and no network call attempted
  })
})

// --- acceptKenRotation ----------------------------------------------------------------------------

describe('acceptKenRotation — explicit, user-confirmed pin move (no dual-accept window)', () => {
  it('moves pubkey→previousPubkeys, sets new pubkey, marks rotation accepted', () => {
    const original = freshKeypair()
    const rotated = freshKeypair()
    const proposed: KenEntry = {
      ...pinManual(original.pk),
      rotation: { newPubkey: rotated.pk, observedAt: 1_700_000_001, via: 'nip05', accepted: false },
    }
    const accepted = acceptKenRotation(proposed)
    expect(accepted.pubkey).toBe(rotated.pk)
    expect(accepted.previousPubkeys).toContain(original.pk)
    expect(accepted.rotation!.accepted).toBe(true)
  })

  it('after accept, attributeSignature REJECTS the old key as rotated-away', () => {
    const original = freshKeypair()
    const rotated = freshKeypair()
    const proposed: KenEntry = {
      ...pinManual(original.pk),
      rotation: { newPubkey: rotated.pk, observedAt: 1_700_000_001, via: 'nip05', accepted: false },
    }
    const accepted = acceptKenRotation(proposed)
    const oldEvent = signEvent(original.sk, 'old statement')
    expect(attributeSignature(accepted, oldEvent)).toEqual({ genuine: false, reason: 'rotated-away-key' })
    // and the NEW key now attributes genuinely.
    const newEvent = signEvent(rotated.sk, 'new statement')
    expect(attributeSignature(accepted, newEvent)).toEqual({ genuine: true })
  })

  it('appends to an existing previousPubkeys chain (multi-rotation history preserved)', () => {
    const k1 = freshKeypair()
    const k2 = freshKeypair()
    const k3 = freshKeypair()
    const proposed: KenEntry = {
      ...pinManual(k2.pk, { previousPubkeys: [k1.pk] }),
      rotation: { newPubkey: k3.pk, observedAt: 1, via: 'manual', accepted: false },
    }
    const accepted = acceptKenRotation(proposed)
    expect(accepted.pubkey).toBe(k3.pk)
    expect(accepted.previousPubkeys).toEqual([k1.pk, k2.pk])
  })

  it('throws when there is no pending rotation', () => {
    const { pk } = freshKeypair()
    expect(() => acceptKenRotation(pinManual(pk))).toThrow()
  })
})

// --- revokeKen (fail-closed) ----------------------------------------------------------------------

describe('revokeKen — compromise announced, no successor → fail closed', () => {
  it('sets revoked:true and makes attributeSignature + verifyKeyControl fail closed', () => {
    const { sk, pk } = freshKeypair()
    const revoked = revokeKen(pinManual(pk))
    expect(revoked.revoked).toBe(true)

    const ev = signEvent(sk, 'statement')
    expect(attributeSignature(revoked, ev)).toEqual({ genuine: false, reason: 'revoked' })

    const { nonce } = buildKeyControlChallenge()
    const proof = signEvent(sk, nonce)
    expect(verifyKeyControl(revoked, nonce, proof)).toEqual({ proven: false, reason: 'revoked' })
  })
})

// --- dropKen (consumer removes the record) --------------------------------------------------------

describe('dropKen', () => {
  it('is a void no-op marker (removal is the consumer\'s responsibility)', () => {
    const { pk } = freshKeypair()
    expect(dropKen(pinManual(pk))).toBeUndefined()
  })
})

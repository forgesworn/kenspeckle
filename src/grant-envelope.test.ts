import { describe, it, expect } from 'vitest'
import { toGrantView, buildGrantEnvelope, parseGrantEnvelope, GRANT_CONTACTS_CAP } from './grant-envelope.js'
import type { KinEntry, KithEntry, KenEntry } from './types.js'
import type { GrantScope, GrantContactView } from './grant-envelope.js'

const kin: KinEntry = {
  pubkey: 'a'.repeat(64), ownerPubkey: 'b'.repeat(64), tier: 'kin',
  displayName: 'Mum', addedAt: 100, verifiedAt: 100,
  sharedSecret: 'DEADBEEF-secret', relationship: 'parent',
  annotations: { label: 'private', note: 'secret note' },
}
const kith: KithEntry = {
  pubkey: 'c'.repeat(64), ownerPubkey: 'b'.repeat(64), tier: 'kith',
  displayName: 'Sam', addedAt: 200, verifiedAt: 200, sharedSecret: 'SECRET2',
}
const ken: KenEntry = {
  pubkey: 'd'.repeat(64), ownerPubkey: 'b'.repeat(64), tier: 'ken',
  displayName: 'Celeb', addedAt: 300, nip05: 'celeb@example.com',
  provenance: { source: 'nip05', locator: 'celeb@example.com', confirmedAt: 300 },
}

describe('toGrantView', () => {
  it('keeps read-and-pick fields for kin incl. relationship', () => {
    expect(toGrantView(kin)).toEqual({
      pubkey: 'a'.repeat(64), ownerPubkey: 'b'.repeat(64), tier: 'kin',
      displayName: 'Mum', addedAt: 100, relationship: 'parent',
    })
  })
  it('carries nip05 for ken', () => {
    expect(toGrantView(ken)).toMatchObject({ tier: 'ken', nip05: 'celeb@example.com' })
  })
  it('NEVER emits secret or private fields (strip invariant)', () => {
    for (const e of [kin, kith, ken]) {
      const json = JSON.stringify(toGrantView(e))
      for (const banned of ['sharedSecret', 'annotations', 'note', 'label', 'provenance', 'bondAssertion', 'rotation', 'previousPubkeys']) {
        expect(json).not.toContain(banned)
      }
    }
  })
})

const scope: GrantScope = { tiers: ['kin', 'kith'], personas: 'all' }
const views: GrantContactView[] = [
  { pubkey: 'a'.repeat(64), ownerPubkey: 'b'.repeat(64), tier: 'kin', displayName: 'Mum', addedAt: 100, relationship: 'parent' },
]

describe('grant envelope round-trip', () => {
  it('builds and parses back to an equal object', () => {
    const parsed = parseGrantEnvelope(buildGrantEnvelope(scope, views, 500))
    expect(parsed).toEqual({ v: 1, scope, contacts: views, publishedAt: 500 })
  })
  it('carries revoked marker + empty contacts on tombstone', () => {
    const parsed = parseGrantEnvelope(buildGrantEnvelope(scope, [], 600, { revoked: true }))
    expect(parsed).toMatchObject({ revoked: true, contacts: [] })
  })
  it('returns null on non-JSON', () => {
    expect(parseGrantEnvelope('not json')).toBeNull()
  })
  it('returns null on future schema version', () => {
    expect(parseGrantEnvelope(JSON.stringify({ v: 2, scope, contacts: [], publishedAt: 1 }))).toBeNull()
  })
  it('drops garbage contact entries but keeps valid ones', () => {
    const raw = JSON.stringify({
      v: 1, scope, publishedAt: 1,
      contacts: [
        { pubkey: 'x', ownerPubkey: 'b'.repeat(64), tier: 'kin', addedAt: 1 }, // bad pubkey
        { pubkey: 'a'.repeat(64), ownerPubkey: 'b'.repeat(64), tier: 'kith', addedAt: 2 }, // valid
      ],
    })
    const parsed = parseGrantEnvelope(raw)
    expect(parsed?.contacts).toHaveLength(1)
    expect(parsed?.contacts[0].pubkey).toBe('a'.repeat(64))
  })
  it('returns null when scope.tiers has an unknown token', () => {
    expect(parseGrantEnvelope(JSON.stringify({ v: 1, scope: { tiers: ['nope'], personas: 'all' }, contacts: [], publishedAt: 1 }))).toBeNull()
  })
  it('strips unknown kin relationship but keeps contact (forward-compat)', () => {
    const raw = JSON.stringify({
      v: 1, scope, publishedAt: 1,
      contacts: [
        { pubkey: 'a'.repeat(64), ownerPubkey: 'b'.repeat(64), tier: 'kin', addedAt: 1, relationship: 'boss' },
      ],
    })
    const parsed = parseGrantEnvelope(raw)
    expect(parsed?.contacts).toHaveLength(1)
    expect(parsed?.contacts[0].relationship).toBeUndefined()
  })
})

describe('grant envelope — timestamps (M2)', () => {
  const env = (publishedAt: string) => `{"v":1,"scope":{"tiers":["kin"],"personas":"all"},"contacts":[],"publishedAt":${publishedAt}}`

  it.each(['1e400', '-1', '1.5', '9007199254740993', 'null'])('rejects publishedAt=%s', (value) => {
    expect(parseGrantEnvelope(env(value))).toBeNull()
  })

  it('drops a contact whose addedAt is not a non-negative safe integer', () => {
    const raw = JSON.stringify({ v: 1, scope, publishedAt: 1, contacts: [
      { pubkey: 'a'.repeat(64), ownerPubkey: 'b'.repeat(64), tier: 'kin', addedAt: -5.5 },
    ] }).replace('-5.5', '1e400')
    expect(parseGrantEnvelope(raw)?.contacts).toEqual([])
  })

  it('build refuses a non-integer or negative publishedAt', () => {
    for (const bad of [Number.POSITIVE_INFINITY, -1, 1.5, Number.NaN]) {
      expect(() => buildGrantEnvelope(scope, [], bad)).toThrow(/publishedAt/)
    }
  })
})

describe('grant envelope — build projects an allowlist (M5)', () => {
  it('never serialises fields outside GrantContactView / GrantScope', () => {
    const leakyView = { ...views[0]!, sharedSecret: 'LEAK' } as GrantContactView
    const leakyScope = { ...scope, secret: 'S' } as GrantScope
    const json = buildGrantEnvelope(leakyScope, [leakyView], 1)
    expect(json).not.toContain('LEAK')
    expect(json).not.toContain('secret')
  })

  it('throws when a contact would be dropped by the parser (out of scope / bad key)', () => {
    const kithView: GrantContactView = { pubkey: 'c'.repeat(64), ownerPubkey: 'b'.repeat(64), tier: 'ken', addedAt: 1 }
    expect(() => buildGrantEnvelope(scope, [kithView], 1)).toThrow(/survive/)
    expect(() => buildGrantEnvelope(scope, [{ ...views[0]!, pubkey: 'x' }], 1)).toThrow(/survive/)
  })

  it('throws past the contacts cap', () => {
    const many = Array.from({ length: GRANT_CONTACTS_CAP + 1 }, () => views[0]!)
    expect(() => buildGrantEnvelope(scope, many, 1)).toThrow(/at most/)
  })
})

describe('grant envelope — parse consistency (L6)', () => {
  it('strips control / bidi characters from displayName (as the companion rail does)', () => {
    const raw = JSON.stringify({ v: 1, scope, publishedAt: 1, contacts: [
      { pubkey: 'a'.repeat(64), ownerPubkey: 'b'.repeat(64), tier: 'kith', addedAt: 1, displayName: 'evil\u202Egnp.exe' },
    ] })
    expect(parseGrantEnvelope(raw)?.contacts[0]?.displayName).toBe('evilgnp.exe')
  })

  it('lowercases uppercase hex instead of silently dropping the contact', () => {
    const raw = JSON.stringify({ v: 1, scope, publishedAt: 1, contacts: [
      { pubkey: 'A'.repeat(64), ownerPubkey: 'B'.repeat(64), tier: 'kith', addedAt: 1 },
    ] })
    expect(parseGrantEnvelope(raw)?.contacts).toEqual([{ pubkey: 'a'.repeat(64), ownerPubkey: 'b'.repeat(64), tier: 'kith', addedAt: 1 }])
  })

  it('returns a projected scope (unknown keys dropped)', () => {
    const raw = JSON.stringify({ v: 1, scope: { ...scope, extra: 1 }, publishedAt: 1, contacts: [] })
    expect(parseGrantEnvelope(raw)?.scope).toEqual(scope)
  })

  it('drops contacts outside the declared scope (tier or owner persona)', () => {
    const owner = 'b'.repeat(64)
    const other = 'e'.repeat(64)
    const raw = JSON.stringify({ v: 1, scope: { tiers: ['kin'], personas: [owner] }, publishedAt: 1, contacts: [
      { pubkey: 'a'.repeat(64), ownerPubkey: owner, tier: 'kith', addedAt: 1 }, // kith under kin-only scope
      { pubkey: 'c'.repeat(64), ownerPubkey: other, tier: 'kin', addedAt: 1 }, // owner not in personas
      { pubkey: 'd'.repeat(64), ownerPubkey: owner, tier: 'kin', addedAt: 1 }, // in scope
    ] })
    expect(parseGrantEnvelope(raw)?.contacts.map((c) => c.pubkey)).toEqual(['d'.repeat(64)])
  })

  it('reads at most GRANT_CONTACTS_CAP contacts', () => {
    const contact = { pubkey: 'a'.repeat(64), ownerPubkey: 'b'.repeat(64), tier: 'kin', addedAt: 1 }
    const raw = JSON.stringify({ v: 1, scope, publishedAt: 1, contacts: Array(GRANT_CONTACTS_CAP + 10).fill(contact) })
    expect(parseGrantEnvelope(raw)?.contacts).toHaveLength(GRANT_CONTACTS_CAP)
  })
})

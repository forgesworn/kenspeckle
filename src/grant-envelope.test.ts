import { describe, it, expect } from 'vitest'
import { toGrantView, buildGrantEnvelope, parseGrantEnvelope } from './grant-envelope.js'
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
})

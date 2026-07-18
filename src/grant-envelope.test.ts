import { describe, it, expect } from 'vitest'
import { toGrantView } from './grant-envelope.js'
import type { KinEntry, KithEntry, KenEntry } from './types.js'

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

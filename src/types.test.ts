import { describe, it, expect } from 'vitest'
import {
  hasSharedSecret,
  type KindredEntry,
  type KinEntry,
  type KithEntry,
  type KenEntry,
  type MutualEntry,
  type WireEntry,
} from './types.js'

const A = 'a'.repeat(64)
const B = 'b'.repeat(64)
const OWNER = 'c'.repeat(64)

const kin: KinEntry = {
  tier: 'kin',
  pubkey: A,
  ownerPubkey: OWNER,
  addedAt: 1,
  sharedSecret: '00'.repeat(32),
  verifiedAt: 1,
  relationship: 'child',
}

const kith: KithEntry = {
  tier: 'kith',
  pubkey: B,
  ownerPubkey: OWNER,
  addedAt: 2,
  sharedSecret: '11'.repeat(32),
  verifiedAt: 2,
}

const ken: KenEntry = {
  tier: 'ken',
  pubkey: A,
  ownerPubkey: OWNER,
  addedAt: 3,
  provenance: { source: 'nip05', locator: 'alice@example.com', confirmedAt: 3 },
}

describe('hasSharedSecret', () => {
  it('narrows a KinEntry to MutualEntry (true)', () => {
    const e: KindredEntry = kin
    expect(hasSharedSecret(e)).toBe(true)
    if (hasSharedSecret(e)) {
      // type-level: e is now MutualEntry — sharedSecret is accessible without a cast.
      const m: MutualEntry = e
      expect(m.sharedSecret).toBe('00'.repeat(32))
    } else {
      throw new Error('expected kin to have a shared secret')
    }
  })

  it('narrows a KithEntry to MutualEntry (true)', () => {
    const e: KindredEntry = kith
    expect(hasSharedSecret(e)).toBe(true)
    if (hasSharedSecret(e)) {
      const m: MutualEntry = e
      expect(m.sharedSecret).toBe('11'.repeat(32))
    } else {
      throw new Error('expected kith to have a shared secret')
    }
  })

  it('returns false for a KenEntry (no shared secret)', () => {
    const e: KindredEntry = ken
    expect(hasSharedSecret(e)).toBe(false)
  })
})

// NOTE on the WireEntry type-level invariant:
// The load-bearing compile-time proof that `WireEntry` excludes `annotations` lives in src/types.ts
// (`_WireAnnotationsExclusionCheck`), NOT here. Reason: the house tsconfig excludes `**/*.test.ts`
// from `tsc`, and vitest transpiles tests with esbuild (no type-checking) — so a `@ts-expect-error`
// or a type assertion placed in this file is never actually checked (a false green). Verified by
// breaking `WireEntry = KindredEntry` and confirming `npm run typecheck` then fails on types.ts.
// The runtime cases below cover the genuinely-runtime behaviour (the `hasSharedSecret` predicate and
// that annotations are an ordinary in-memory property on a KindredEntry).

describe('WireEntry', () => {
  it('a KindredEntry value carries annotations in memory (the local-only side of the invariant)', () => {
    const withAnnotations: KindredEntry = {
      ...kith,
      annotations: { groupId: 'g1', label: 'work', note: 'met at conf', blocked: false },
    }
    expect(withAnnotations.annotations?.label).toBe('work')
  })

  it('a WireEntry value never declares annotations (mirrors the type-level exclusion)', () => {
    // Build a wire view by structurally dropping annotations; this is what serializeEntry/toWire
    // (K-2) will do at runtime. The compile-time guarantee is enforced in src/types.ts.
    const { annotations: _dropped, ...wireShape } = {
      ...kith,
      annotations: { label: 'leak' },
    }
    const wire: WireEntry = wireShape
    expect('annotations' in wire).toBe(false)
  })
})

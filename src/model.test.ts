import { describe, it, expect } from 'vitest'
import {
  scopeToPersona,
  assertOwnedPersona,
  searchEntries,
  linkForRecall,
  unlink,
  toWire,
  serializeEntry,
  parseEntry,
} from './model.js'
import type { KindredEntry, KinEntry, KithEntry, KenEntry } from './types.js'

const A = 'a'.repeat(64)
const B = 'b'.repeat(64)
const C = 'c'.repeat(64)
const OWNER = 'd'.repeat(64)
const OWNER2 = 'e'.repeat(64)

const kin: KinEntry = {
  tier: 'kin',
  pubkey: A,
  ownerPubkey: OWNER,
  addedAt: 1,
  sharedSecret: '00'.repeat(32),
  verifiedAt: 1,
  relationship: 'child',
  displayName: 'Alice',
}

const kith: KithEntry = {
  tier: 'kith',
  pubkey: B,
  ownerPubkey: OWNER,
  addedAt: 2,
  sharedSecret: '11'.repeat(32),
  verifiedAt: 2,
  displayName: 'Bob',
}

const ken: KenEntry = {
  tier: 'ken',
  pubkey: C,
  ownerPubkey: OWNER,
  addedAt: 3,
  provenance: { source: 'nip05', locator: 'carol@example.com', confirmedAt: 3 },
  displayName: 'Carol',
}

describe('scopeToPersona', () => {
  it('sets ownerPubkey and preserves tier + all other fields', () => {
    const { ownerPubkey: _drop, ...withoutOwner } = kin
    const scoped = scopeToPersona(withoutOwner, OWNER2)
    expect(scoped.ownerPubkey).toBe(OWNER2)
    expect(scoped.tier).toBe('kin')
    expect(scoped.pubkey).toBe(A)
    expect(scoped.displayName).toBe('Alice')
    if (scoped.tier === 'kin') {
      expect(scoped.relationship).toBe('child')
      expect(scoped.sharedSecret).toBe('00'.repeat(32))
      expect(scoped.verifiedAt).toBe(1)
    } else {
      throw new Error('expected kin tier preserved')
    }
  })

  it('preserves ken provenance', () => {
    const { ownerPubkey: _drop, ...withoutOwner } = ken
    const scoped = scopeToPersona(withoutOwner, OWNER2)
    expect(scoped.ownerPubkey).toBe(OWNER2)
    if (scoped.tier === 'ken') {
      expect(scoped.provenance.locator).toBe('carol@example.com')
    } else {
      throw new Error('expected ken tier preserved')
    }
  })
})

describe('assertOwnedPersona', () => {
  it('does not throw when the persona is a leaf', () => {
    expect(() => assertOwnedPersona(OWNER, [A, OWNER, B])).not.toThrow()
  })

  it('matches case-insensitively', () => {
    expect(() => assertOwnedPersona(OWNER.toUpperCase(), [A, OWNER, B])).not.toThrow()
    expect(() => assertOwnedPersona(OWNER, [A, OWNER.toUpperCase(), B])).not.toThrow()
  })

  it('throws "persona not owned" for a non-leaf', () => {
    expect(() => assertOwnedPersona(C, [A, OWNER, B])).toThrow('persona not owned')
  })

  it('throws on an empty leaf set', () => {
    expect(() => assertOwnedPersona(OWNER, [])).toThrow('persona not owned')
  })
})

describe('searchEntries', () => {
  const entries: KindredEntry[] = [
    kin, // Alice, pubkey aaaa...
    kith, // Bob, pubkey bbbb...
    { ...ken, annotations: { label: 'plumber', note: 'fixed the boiler' } },
  ]

  it('returns all entries for an empty query', () => {
    expect(searchEntries(entries, '')).toHaveLength(3)
    expect(searchEntries(entries, '   ')).toHaveLength(3)
  })

  it('matches displayName case-insensitively', () => {
    const r = searchEntries(entries, 'alice')
    expect(r).toHaveLength(1)
    expect(r[0]!.pubkey).toBe(A)
  })

  it('matches a pubkey prefix', () => {
    const r = searchEntries(entries, B.slice(0, 10))
    expect(r).toHaveLength(1)
    expect(r[0]!.pubkey).toBe(B)
  })

  it('matches a pubkey substring', () => {
    const r = searchEntries(entries, 'bbbb')
    expect(r.some((e) => e.pubkey === B)).toBe(true)
  })

  it('matches a local annotation label', () => {
    const r = searchEntries(entries, 'plumber')
    expect(r).toHaveLength(1)
    expect(r[0]!.pubkey).toBe(C)
  })

  it('matches a local annotation note', () => {
    const r = searchEntries(entries, 'boiler')
    expect(r).toHaveLength(1)
    expect(r[0]!.pubkey).toBe(C)
  })

  it('returns empty for no match', () => {
    expect(searchEntries(entries, 'zzzz-nope')).toHaveLength(0)
  })
})

describe('linkForRecall / unlink', () => {
  it('assigns one shared groupId to the named entries', () => {
    const entries: KindredEntry[] = [{ ...kin }, { ...kith }, { ...ken }]
    const groupId = linkForRecall(entries, [A, B])
    expect(typeof groupId).toBe('string')
    expect(groupId.length).toBeGreaterThan(0)
    expect(entries[0]!.annotations?.groupId).toBe(groupId)
    expect(entries[1]!.annotations?.groupId).toBe(groupId)
    // unnamed entry untouched
    expect(entries[2]!.annotations?.groupId).toBeUndefined()
  })

  it('creates annotations object if absent and preserves existing annotation fields', () => {
    const entries: KindredEntry[] = [
      { ...kin, annotations: { label: 'keepme' } },
      { ...kith },
    ]
    const groupId = linkForRecall(entries, [A])
    expect(entries[0]!.annotations?.groupId).toBe(groupId)
    expect(entries[0]!.annotations?.label).toBe('keepme')
  })

  it('unlink clears one entry groupId; others keep theirs', () => {
    const entries: KindredEntry[] = [{ ...kin }, { ...kith }]
    const groupId = linkForRecall(entries, [A, B])
    unlink(entries, A)
    expect(entries[0]!.annotations?.groupId).toBeUndefined()
    expect(entries[1]!.annotations?.groupId).toBe(groupId)
  })

  it('unlink preserves other annotation fields on the cleared entry', () => {
    const entries: KindredEntry[] = [{ ...kin, annotations: { label: 'keep', note: 'n' } }]
    linkForRecall(entries, [A])
    unlink(entries, A)
    expect(entries[0]!.annotations?.groupId).toBeUndefined()
    expect(entries[0]!.annotations?.label).toBe('keep')
    expect(entries[0]!.annotations?.note).toBe('n')
  })
})

describe('toWire / serializeEntry — THE PRIVACY INVARIANT', () => {
  const withAnnotations: KithEntry = {
    ...kith,
    annotations: { groupId: 'g1', label: 'work', note: 'met at conf', blocked: true },
  }

  it('toWire strips annotations', () => {
    const wire = toWire(withAnnotations)
    expect('annotations' in wire).toBe(false)
    // non-annotation fields preserved
    expect(wire.pubkey).toBe(B)
    expect(wire.tier).toBe('kith')
  })

  it('serializeEntry NEVER includes an annotations key even when input has them', () => {
    const s = serializeEntry(withAnnotations)
    expect(s).not.toContain('annotations')
    expect(s).not.toContain('"work"')
    expect(s).not.toContain('met at conf')
    const parsed = JSON.parse(s)
    expect(parsed.annotations).toBeUndefined()
    expect('annotations' in parsed).toBe(false)
  })

  it('serializeEntry round-trips the non-annotation fields', () => {
    const s = serializeEntry(withAnnotations)
    const parsed = JSON.parse(s)
    expect(parsed.pubkey).toBe(B)
    expect(parsed.ownerPubkey).toBe(OWNER)
    expect(parsed.tier).toBe('kith')
    expect(parsed.sharedSecret).toBe('11'.repeat(32))
    expect(parsed.verifiedAt).toBe(2)
  })
})

describe('serializeEntry determinism', () => {
  it('two entries with identical fields in different insertion order serialize identically', () => {
    const e1: KinEntry = {
      tier: 'kin',
      pubkey: A,
      ownerPubkey: OWNER,
      addedAt: 1,
      sharedSecret: '00'.repeat(32),
      verifiedAt: 1,
      relationship: 'child',
      displayName: 'Alice',
    }
    // Same fields, different declaration/insertion order:
    const e2: KinEntry = {
      relationship: 'child',
      displayName: 'Alice',
      verifiedAt: 1,
      sharedSecret: '00'.repeat(32),
      addedAt: 1,
      ownerPubkey: OWNER,
      pubkey: A,
      tier: 'kin',
    }
    expect(serializeEntry(e1)).toBe(serializeEntry(e2))
  })

  it('sorts nested object keys (ken provenance)', () => {
    const p1: KenEntry = {
      tier: 'ken',
      pubkey: C,
      ownerPubkey: OWNER,
      addedAt: 3,
      provenance: { source: 'nip05', locator: 'carol@example.com', confirmedAt: 3 },
    }
    const p2: KenEntry = {
      tier: 'ken',
      pubkey: C,
      ownerPubkey: OWNER,
      addedAt: 3,
      provenance: { confirmedAt: 3, locator: 'carol@example.com', source: 'nip05' },
    }
    expect(serializeEntry(p1)).toBe(serializeEntry(p2))
  })
})

describe('parseEntry', () => {
  it('round-trips a serialized kin entry', () => {
    const parsed = parseEntry(serializeEntry(kin))
    expect(parsed.tier).toBe('kin')
    expect(parsed.pubkey).toBe(A)
    if (parsed.tier === 'kin') {
      expect(parsed.relationship).toBe('child')
      expect(parsed.sharedSecret).toBe('00'.repeat(32))
    }
  })

  it('round-trips a serialized kith entry', () => {
    const parsed = parseEntry(serializeEntry(kith))
    expect(parsed.tier).toBe('kith')
    if (parsed.tier === 'kith') {
      expect(parsed.sharedSecret).toBe('11'.repeat(32))
      expect(parsed.verifiedAt).toBe(2)
    }
  })

  it('round-trips a serialized ken entry', () => {
    const parsed = parseEntry(serializeEntry(ken))
    expect(parsed.tier).toBe('ken')
    if (parsed.tier === 'ken') {
      expect(parsed.provenance.source).toBe('nip05')
      expect(parsed.provenance.locator).toBe('carol@example.com')
    }
  })

  it('does NOT restore annotations (wire never had them)', () => {
    const withAnnotations: KithEntry = { ...kith, annotations: { label: 'secret' } }
    const parsed = parseEntry(serializeEntry(withAnnotations))
    expect(parsed.annotations).toBeUndefined()
  })

  it('rejects a bad tier', () => {
    const bad = JSON.stringify({ ...toWire(kith), tier: 'acquaintance' })
    expect(() => parseEntry(bad)).toThrow()
  })

  it('rejects a non-hex pubkey', () => {
    const bad = JSON.stringify({ ...toWire(kith), pubkey: 'not-hex' })
    expect(() => parseEntry(bad)).toThrow()
  })

  it('rejects a non-hex ownerPubkey', () => {
    const bad = JSON.stringify({ ...toWire(kith), ownerPubkey: 'zz'.repeat(32) })
    expect(() => parseEntry(bad)).toThrow()
  })

  it('rejects a missing sharedSecret on a kith (mutual)', () => {
    const { sharedSecret: _drop, ...rest } = toWire(kith) as KithEntry
    expect(() => parseEntry(JSON.stringify(rest))).toThrow()
  })

  it('rejects a missing verifiedAt on a kin', () => {
    const { verifiedAt: _drop, ...rest } = toWire(kin) as KinEntry
    expect(() => parseEntry(JSON.stringify(rest))).toThrow()
  })

  it('rejects a kin with an invalid relationship', () => {
    const bad = JSON.stringify({ ...toWire(kin), relationship: 'frenemy' })
    expect(() => parseEntry(bad)).toThrow()
  })

  it('rejects a missing provenance on a ken', () => {
    const { provenance: _drop, ...rest } = toWire(ken) as KenEntry
    expect(() => parseEntry(JSON.stringify(rest))).toThrow()
  })

  it('rejects a ken provenance missing required fields', () => {
    const bad = JSON.stringify({ ...toWire(ken), provenance: { source: 'nip05' } })
    expect(() => parseEntry(bad)).toThrow()
  })

  it('rejects a non-finite addedAt', () => {
    const bad = JSON.stringify({ ...toWire(kith), addedAt: 'soon' })
    expect(() => parseEntry(bad)).toThrow()
  })

  it('rejects non-object / non-JSON input', () => {
    expect(() => parseEntry('null')).toThrow()
    expect(() => parseEntry('[]')).toThrow()
    expect(() => parseEntry('42')).toThrow()
    expect(() => parseEntry('not json{')).toThrow()
  })

  it('LOWERCASES uppercase hex on parse (uppercase from a restored backup must not break equality)', () => {
    // A restored/imported backup can carry UPPERCASE hex. nostr-tools always emits lowercase
    // `event.pubkey`, so an uppercase `entry.pubkey` would silently fail strict-equality in
    // verifyKeyControl / attributeSignature. parseEntry must normalize to lowercase.
    const upperKin = {
      ...toWire(kin),
      pubkey: A.toUpperCase(),
      ownerPubkey: OWNER.toUpperCase(),
      sharedSecret: '00'.repeat(32).toUpperCase(),
    }
    const parsed = parseEntry(JSON.stringify(upperKin))
    expect(parsed.pubkey).toBe(A) // lowercase
    expect(parsed.ownerPubkey).toBe(OWNER)
    if (parsed.tier === 'kin') {
      expect(parsed.sharedSecret).toBe('00'.repeat(32))
    } else {
      throw new Error('expected kin tier')
    }
  })

  it('LOWERCASES uppercase ken rotation.newPubkey, previousPubkeys, and provenance fields on parse', () => {
    const old1 = 'a1'.repeat(32)
    const rotated = 'b2'.repeat(32)
    const upperKen = {
      ...toWire(ken),
      pubkey: C.toUpperCase(),
      ownerPubkey: OWNER.toUpperCase(),
      previousPubkeys: [old1.toUpperCase()],
      rotation: {
        newPubkey: rotated.toUpperCase(),
        observedAt: 5,
        via: 'nip05',
        accepted: false,
      },
    }
    const parsed = parseEntry(JSON.stringify(upperKen))
    expect(parsed.pubkey).toBe(C)
    expect(parsed.ownerPubkey).toBe(OWNER)
    if (parsed.tier === 'ken') {
      expect(parsed.previousPubkeys).toEqual([old1]) // lowercased element
      expect(parsed.rotation!.newPubkey).toBe(rotated) // lowercased
    } else {
      throw new Error('expected ken tier')
    }
  })
})

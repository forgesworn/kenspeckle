import { describe, it, expect } from 'vitest'
import {
  scopeToPersona,
  assertOwnedPersona,
  searchEntries,
  linkForRecall,
  unlink,
  toWire,
  serializeEntry,
  toSyncForm,
  serializeEntryForSync,
  parseEntry,
} from './model.js'
import type { KindredEntry, KinEntry, KithEntry, KenEntry } from './types.js'
import { MAX_CORROBORATIONS } from './validate.js'

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

describe('toWire / serializeEntry — THE PRIVACY INVARIANT (annotations AND sharedSecret, H4 audit finding)', () => {
  const withAnnotations: KithEntry = {
    ...kith,
    annotations: { groupId: 'g1', label: 'work', note: 'met at conf', blocked: true },
  }

  it('toWire strips annotations AND sharedSecret', () => {
    const wire = toWire(withAnnotations)
    expect('annotations' in wire).toBe(false)
    expect('sharedSecret' in wire).toBe(false)
    // non-secret, non-annotation fields preserved
    expect(wire.pubkey).toBe(B)
    expect(wire.tier).toBe('kith')
  })

  it('toWire is a no-op difference from toSyncForm on a ken (no sharedSecret to begin with)', () => {
    const wire = toWire(ken)
    expect(wire).toEqual(toSyncForm(ken))
  })

  it('serializeEntry NEVER includes an annotations OR a sharedSecret key even when input has them', () => {
    const s = serializeEntry(withAnnotations)
    expect(s).not.toContain('annotations')
    expect(s).not.toContain('"work"')
    expect(s).not.toContain('met at conf')
    expect(s).not.toContain('sharedSecret')
    expect(s).not.toContain('11'.repeat(32))
    const parsed = JSON.parse(s)
    expect(parsed.annotations).toBeUndefined()
    expect(parsed.sharedSecret).toBeUndefined()
    expect('annotations' in parsed).toBe(false)
    expect('sharedSecret' in parsed).toBe(false)
  })

  it('serializeEntry round-trips the non-secret, non-annotation fields', () => {
    const s = serializeEntry(withAnnotations)
    const parsed = JSON.parse(s)
    expect(parsed.pubkey).toBe(B)
    expect(parsed.ownerPubkey).toBe(OWNER)
    expect(parsed.tier).toBe('kith')
    expect(parsed.verifiedAt).toBe(2)
  })

  it('a kin/kith wire form cannot be round-tripped by parseEntry — sharedSecret is required and absent by design', () => {
    const s = serializeEntry(withAnnotations)
    expect(() => parseEntry(s)).toThrow(/sharedSecret/)
  })
})

describe('toSyncForm / serializeEntryForSync — KEEPS sharedSecret for cross-device sync (H4 audit finding)', () => {
  const withAnnotations: KithEntry = {
    ...kith,
    annotations: { groupId: 'g1', label: 'work', note: 'met at conf', blocked: true },
  }

  it('toSyncForm strips annotations but PRESERVES sharedSecret', () => {
    const sync = toSyncForm(withAnnotations)
    expect('annotations' in sync).toBe(false)
    expect(sync.sharedSecret).toBe('11'.repeat(32))
  })

  it('serializeEntryForSync round-trips through parseEntry, including sharedSecret', () => {
    const s = serializeEntryForSync(withAnnotations)
    expect(s).not.toContain('annotations')
    const parsed = parseEntry(s)
    expect(parsed.tier).toBe('kith')
    if (parsed.tier === 'kith') {
      expect(parsed.sharedSecret).toBe('11'.repeat(32))
      expect(parsed.verifiedAt).toBe(2)
    }
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
  it('round-trips a serialized kin entry VIA serializeEntryForSync (true wire form omits sharedSecret — see the H4 describe block above)', () => {
    const parsed = parseEntry(serializeEntryForSync(kin))
    expect(parsed.tier).toBe('kin')
    expect(parsed.pubkey).toBe(A)
    if (parsed.tier === 'kin') {
      expect(parsed.relationship).toBe('child')
      expect(parsed.sharedSecret).toBe('00'.repeat(32))
    }
  })

  it('round-trips a serialized kith entry VIA serializeEntryForSync', () => {
    const parsed = parseEntry(serializeEntryForSync(kith))
    expect(parsed.tier).toBe('kith')
    if (parsed.tier === 'kith') {
      expect(parsed.sharedSecret).toBe('11'.repeat(32))
      expect(parsed.verifiedAt).toBe(2)
    }
  })

  it('round-trips a serialized ken entry (no sharedSecret involved — serializeEntry and serializeEntryForSync agree)', () => {
    const parsed = parseEntry(serializeEntry(ken))
    expect(parsed.tier).toBe('ken')
    if (parsed.tier === 'ken') {
      expect(parsed.provenance.source).toBe('nip05')
      expect(parsed.provenance.locator).toBe('carol@example.com')
    }
  })

  it('does NOT restore annotations (neither serialised form carries them)', () => {
    const withAnnotations: KithEntry = { ...kith, annotations: { label: 'secret' } }
    const parsed = parseEntry(serializeEntryForSync(withAnnotations))
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
    // Base on `toSyncForm` (which KEEPS sharedSecret), then explicitly drop just that one field —
    // isolates this check from H4's unrelated "wire form omits sharedSecret by design" behaviour.
    const { sharedSecret: _drop, ...rest } = toSyncForm(kith) as KithEntry
    expect(() => parseEntry(JSON.stringify(rest))).toThrow(/sharedSecret/)
  })

  it('rejects a missing verifiedAt on a kin', () => {
    const { verifiedAt: _drop, ...rest } = toSyncForm(kin) as KinEntry
    expect(() => parseEntry(JSON.stringify(rest))).toThrow(/verifiedAt/)
  })

  it('rejects a kin with an invalid relationship', () => {
    const bad = JSON.stringify({ ...toSyncForm(kin), relationship: 'frenemy' })
    expect(() => parseEntry(bad)).toThrow(/relationship/)
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

// --- corroborated provenance (additive, MUST NOT break anything) --------------------------------
//
// `corroborations` lets "verified in person AND matches their domain" be expressed instead of
// keeping one source and discarding the rest. The load-bearing property is that it is ADDITIVE:
// every entry that existed before this field must serialise to the exact same bytes as before.

describe('ken corroborations — the NON-BREAKING guarantee', () => {
  // These two strings were captured from the code BEFORE `corroborations` existed, by running
  // `serializeEntry` against the then-current dist/ build. They are frozen on purpose: if adding a
  // field ever perturbs the bytes of an entry that does NOT use it, existing stored entries and
  // existing frozen vectors would silently drift and this test fails loudly instead.
  const FROZEN_MINIMAL =
    '{"addedAt":1750000000,"ownerPubkey":"' + 'b'.repeat(64) + '","provenance":{"confirmedAt":1749000000,' +
    '"locator":"companion:murmurate","source":"manual"},"pubkey":"' + 'a'.repeat(64) + '","tier":"ken"}'

  const FROZEN_FULL =
    '{"addedAt":1750000000,"displayName":"Wren","lastResolvedAt":1750000100,"nip05":"wren@example.org",' +
    '"ownerPubkey":"' + 'b'.repeat(64) + '","previousPubkeys":["' + 'c'.repeat(64) + '"],' +
    '"provenance":{"confirmedAt":1749000000,"locator":"peat-bog-collective/march-gathering","source":"in-person"},' +
    '"pubkey":"' + 'a'.repeat(64) + '","revoked":false,"rotation":{"accepted":false,"newPubkey":"' + 'd'.repeat(64) +
    '","observedAt":1750000200,"via":"nip05"},"tier":"ken"}'

  const minimalKen: KenEntry = {
    tier: 'ken',
    pubkey: 'a'.repeat(64),
    ownerPubkey: 'b'.repeat(64),
    addedAt: 1750000000,
    provenance: { source: 'manual', locator: 'companion:murmurate', confirmedAt: 1749000000 },
  }

  const fullKen: KenEntry = {
    tier: 'ken',
    pubkey: 'a'.repeat(64),
    ownerPubkey: 'b'.repeat(64),
    addedAt: 1750000000,
    displayName: 'Wren',
    provenance: { source: 'in-person', locator: 'peat-bog-collective/march-gathering', confirmedAt: 1749000000 },
    nip05: 'wren@example.org',
    lastResolvedAt: 1750000100,
    previousPubkeys: ['c'.repeat(64)],
    rotation: { newPubkey: 'd'.repeat(64), observedAt: 1750000200, via: 'nip05', accepted: false },
    revoked: false,
  }

  it('serialises an entry WITHOUT corroborations byte-identically to before the change', () => {
    expect(serializeEntry(minimalKen)).toBe(FROZEN_MINIMAL)
    expect(serializeEntry(fullKen)).toBe(FROZEN_FULL)
  })

  it('still emits no corroborations key after a parse/serialize round-trip', () => {
    // An old entry that travels through the NEW parser must come back byte-identical — this is what
    // makes landing kenspeckle ahead of a consumer safe for entries that predate the field.
    expect(serializeEntry(parseEntry(FROZEN_FULL))).toBe(FROZEN_FULL)
    expect(FROZEN_FULL).not.toContain('corroborations')
  })

  it('round-trips an entry WITH corroborations, preserving order and every field', () => {
    const corroborated: KenEntry = {
      ...fullKen,
      corroborations: [
        { source: 'dns', locator: 'wren.example.org', confirmedAt: 1749500000 },
        { source: 'social-channel', locator: 'https://example.social/@wren', confirmedAt: 1749900000 },
      ],
    }
    const parsed = parseEntry(serializeEntry(corroborated))
    if (parsed.tier !== 'ken') throw new Error('expected ken tier')
    expect(parsed.corroborations).toEqual(corroborated.corroborations)
    // Array element order is meaningful (observation order) and must survive stableSort.
    expect(parsed.corroborations!.map((c) => c.source)).toEqual(['dns', 'social-channel'])
    // The primary provenance is untouched by the presence of corroborations.
    expect(parsed.provenance).toEqual(fullKen.provenance)
    expect(serializeEntry(parsed)).toBe(serializeEntry(corroborated))
  })

  it('preserves an explicitly empty corroborations array (no silent shape mutation)', () => {
    const withEmpty = JSON.stringify({ ...toWire(minimalKen), corroborations: [] })
    const parsed = parseEntry(withEmpty)
    if (parsed.tier !== 'ken') throw new Error('expected ken tier')
    expect(parsed.corroborations).toEqual([])
  })

  it('REJECTS malformed corroborations rather than silently dropping evidence', () => {
    const bad = (corroborations: unknown) =>
      JSON.stringify({ ...toWire(minimalKen), corroborations })

    expect(() => parseEntry(bad('not-an-array'))).toThrow(/corroborations must be an array/)
    expect(() => parseEntry(bad([null]))).toThrow(/provenance must be an object/)
    expect(() => parseEntry(bad([{ source: 'dns', locator: 'x' }]))).toThrow(/confirmedAt/)
    expect(() => parseEntry(bad([{ source: 'dns', confirmedAt: 1 }]))).toThrow(/locator/)
    // An unknown source in a CORROBORATION is rejected by the same allow-list as the primary.
    expect(() => parseEntry(bad([{ source: 'telepathy', locator: 'x', confirmedAt: 1 }]))).toThrow(
      /provenance.source invalid/,
    )
    // One good + one bad rejects the whole entry — evidence that fails its guard is never quietly
    // discarded into an otherwise valid-looking record.
    expect(() =>
      parseEntry(bad([{ source: 'dns', locator: 'ok', confirmedAt: 1 }, { source: 'nope', locator: 'x', confirmedAt: 1 }])),
    ).toThrow(/provenance.source invalid/)
  })

  it('accepts EXACTLY the pre-existing source union — no value added, none removed', () => {
    // The union is frozen: adding a value would be BREAKING, because an older validator throws on an
    // unrecognised source and would reject the ENTIRE entry, not just the field.
    const FROZEN_SOURCES = ['nip05', 'dns', 'web', 'social-channel', 'in-person', 'manual']
    for (const source of FROZEN_SOURCES) {
      const json = JSON.stringify({
        ...toWire(minimalKen),
        corroborations: [{ source, locator: 'x', confirmedAt: 1 }],
      })
      const parsed = parseEntry(json)
      if (parsed.tier !== 'ken') throw new Error('expected ken tier')
      expect(parsed.corroborations![0].source).toBe(source)
    }
    for (const source of ['companion', 'qr-scan', 'in_person', 'NIP05', '']) {
      const json = JSON.stringify({
        ...toWire(minimalKen),
        corroborations: [{ source, locator: 'x', confirmedAt: 1 }],
      })
      expect(() => parseEntry(json)).toThrow(/provenance.source invalid/)
    }
  })

  it('does not reconstruct corroborations onto a non-ken tier', () => {
    // `corroborations` is a KEN field. `parseEntry` reconstructs from a whitelist, so a kith entry
    // carrying one comes back without it. (Note this is a statement about the PARSER: `toWire`/
    // `toSyncForm` are shallow copies, so a hand-built object with a stray key would still emit it —
    // same pre-existing behaviour as any other unknown key.) Based on `toSyncForm` (keeps
    // sharedSecret, required for a kith) since this test is about corroborations, not H4.
    const smuggled = JSON.stringify({
      ...toSyncForm(kith),
      corroborations: [{ source: 'dns', locator: 'x', confirmedAt: 1 }],
    })
    const parsed = parseEntry(smuggled)
    expect(parsed.tier).toBe('kith')
    expect(serializeEntry(parsed)).not.toContain('corroborations')
  })

  it('caps the corroborations array so a restored backup cannot amplify memory', () => {
    // Unlike `previousPubkeys` (uncapped, but fixed 64-char elements), a corroboration carries an
    // unbounded `locator`, so an uncapped array is a real amplification surface. Safe to cap: the
    // field is new, so no stored entry can trip it.
    const make = (n: number) => JSON.stringify({
      ...toWire(minimalKen),
      corroborations: Array.from({ length: n }, () => ({ source: 'web', locator: 'x', confirmedAt: 1 })),
    })
    expect(() => parseEntry(make(MAX_CORROBORATIONS))).not.toThrow()
    expect(() => parseEntry(make(MAX_CORROBORATIONS + 1))).toThrow(/at most 64 corroborations/)
  })
})

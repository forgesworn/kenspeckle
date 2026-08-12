import { describe, expect, it } from 'vitest'
import { buildGrantEnvelope } from './grant-envelope.js'
import { parseEntry, serializeEntry } from './model.js'
import {
  ACK_KIND,
  RETURN_ADDITIONS_CAP,
  RETURN_CORROBORATIONS_CAP,
  RETURN_D_TAG,
  RETURN_LOCATOR_MAX,
  SNAPSHOT_D_TAG,
  SNAPSHOT_KIND,
  applyCompanionSnapshot,
  buildPairingAck,
  buildPairingUri,
  buildReturnEnvelope,
  landReturnedKen,
  parsePairingAck,
  parsePairingRequest,
  parseReturnEnvelope,
} from './companion-rail.js'
import type { CompanionSnapshotState, PairingAck, WireKen } from './companion-rail.js'

const APP = 'a'.repeat(64)
const RAIL = 'b'.repeat(64)
const OWNER = 'c'.repeat(64)
const RELAY = 'wss://relay.example.com'
const CHALLENGE = 'D'.repeat(32)
const NOW = 1_700_000_000

describe('companion rail constants', () => {
  it('freezes the Signet/Fledgling wire identifiers', () => {
    expect(ACK_KIND).toBe(21237)
    expect(SNAPSHOT_KIND).toBe(30078)
    expect(SNAPSHOT_D_TAG).toBe('signet:companion-rail')
  })
})

describe('pairing request', () => {
  it('builds the Fledgling byte fixture and parses it as Signet', () => {
    const uri = buildPairingUri({
      appPubkey: APP,
      appName: 'Fledgling',
      scope: ['kith', 'kin'],
      relay: RELAY,
      nowSec: NOW,
      challenge: CHALLENGE,
    })
    expect(uri).toBe(
      'signet-grant://pair?app=' + APP +
      '&name=Fledgling&scope=kith%2Ckin&relay=wss%3A%2F%2Frelay.example.com&t=1700000000&challenge=' + CHALLENGE,
    )
    expect(parsePairingRequest(uri, { nowSec: NOW })).toEqual({
      request: {
        appPubkey: APP,
        appName: 'Fledgling',
        tiers: ['kith', 'kin'],
        rendezvousRelay: RELAY,
        t: NOW,
        challenge: CHALLENGE,
      },
      warnings: [],
    })
  })

  it('accepts HTTPS carrier URLs and sanitises display text', () => {
    const uri = `https://mysignet.app/?pair=1&app=${APP}&name=%E2%80%AEMy%00App&scope=kin&relay=${encodeURIComponent(RELAY)}&t=${NOW}&challenge=${CHALLENGE}`
    expect(parsePairingRequest(uri, { nowSec: NOW }).request?.appName).toBe('MyApp')
  })

  it('rejects stale requests and insecure production relays', () => {
    const valid = buildPairingUri({ appPubkey: APP, appName: 'App', scope: 'kin', relay: RELAY, nowSec: NOW, challenge: CHALLENGE })
    expect(parsePairingRequest(valid, { nowSec: NOW + 301 }).request).toBeNull()
    const insecure = valid.replace(encodeURIComponent(RELAY), encodeURIComponent('ws://relay.example.com'))
    expect(parsePairingRequest(insecure, { nowSec: NOW }).request).toBeNull()
  })

  it('drops unknown tiers, warns, and preserves the uppercase challenge verbatim', () => {
    const uri = buildPairingUri({ appPubkey: APP, appName: 'App', scope: 'kin,bogus', relay: RELAY, nowSec: NOW, challenge: CHALLENGE })
    const result = parsePairingRequest(uri, { nowSec: NOW })
    expect(result.request?.tiers).toEqual(['kin'])
    expect(result.request?.challenge).toBe(CHALLENGE)
    expect(result.warnings).toContain('scope-unknown-token')
  })
})

describe('pairing ack', () => {
  const ack: PairingAck = {
    v: 1,
    railPubkey: RAIL,
    dTag: SNAPSHOT_D_TAG,
    snapshotRelay: RELAY,
    grantedScope: { tiers: ['kin'], personas: 'all' },
    challenge: CHALLENGE,
  }

  it('builds and parses the producer ack', () => {
    expect(parsePairingAck(buildPairingAck(ack), CHALLENGE)).toEqual(ack)
  })

  it('rejects malformed, wrong-challenge and malformed-scope acks', () => {
    expect(parsePairingAck('not json', CHALLENGE)).toBeNull()
    expect(parsePairingAck(JSON.stringify(ack), 'e'.repeat(32))).toBeNull()
    expect(parsePairingAck(JSON.stringify({ ...ack, grantedScope: { tiers: ['bogus'], personas: 'all' } }), CHALLENGE)).toBeNull()
  })

  it('defaults a legacy missing d-tag to the frozen snapshot tag', () => {
    const { dTag: _dTag, ...legacy } = ack
    expect(parsePairingAck(JSON.stringify(legacy), CHALLENGE)?.dTag).toBe(SNAPSHOT_D_TAG)
  })
})

describe('monotonic snapshot reducer', () => {
  const state: CompanionSnapshotState = {
    pairing: {
      railPubkey: RAIL,
      dTag: SNAPSHOT_D_TAG,
      snapshotRelay: RELAY,
      grantedScope: { tiers: ['kin'], personas: 'all' },
      pairedAt: 100,
    },
    contacts: [],
    lastPublishedAt: 100,
  }
  const scope = { tiers: ['kin'] as const, personas: 'all' as const }
  const contacts = [{ pubkey: APP, ownerPubkey: OWNER, tier: 'kin' as const, relationship: 'child' as const, addedAt: 50 }]

  it('accepts a newer snapshot', () => {
    const next = applyCompanionSnapshot(state, buildGrantEnvelope(scope, contacts, 101))
    expect(next.contacts).toEqual(contacts)
    expect(next.lastPublishedAt).toBe(101)
    expect(next.revoked).toBe(false)
  })

  it('returns the exact state for stale or malformed input', () => {
    expect(applyCompanionSnapshot(state, buildGrantEnvelope(scope, contacts, 100))).toBe(state)
    expect(applyCompanionSnapshot(state, 'not json')).toBe(state)
  })

  it('purges pairing and contacts on a newer revocation', () => {
    const next = applyCompanionSnapshot(state, buildGrantEnvelope(scope, [], 102, { revoked: true }))
    expect(next.pairing).toBeUndefined()
    expect(next.contacts).toEqual([])
    expect(next.revoked).toBe(true)
    expect(next.lastPublishedAt).toBe(102)
  })
})

// --- return rail (design §10) ---------------------------------------------------------------------
//
// The companion is often where the evidence actually IS: meeting someone at a gathering and scanning
// their code standing next to them is `in-person` provenance with a real locator and timestamp.
// The rail must carry that CLAIM intact — while keeping it structurally distinguishable from
// something signet-app confirmed itself, because a claim is not a confirmation.

const BIDI = '‮' // right-to-left override — the display-spoofing class stripped at the boundary

describe('return rail', () => {
  const KEN = 'f'.repeat(64)
  const inPerson = { source: 'in-person' as const, locator: 'peat-bog-collective/march-gathering', confirmedAt: NOW - 100 }
  const dns = { source: 'dns' as const, locator: 'wren.example.org', confirmedAt: NOW - 50 }

  it('freezes the return d-tag and the abuse caps', () => {
    expect(RETURN_D_TAG).toBe('signet:companion-return')
    expect(RETURN_ADDITIONS_CAP).toBe(50)
    expect(RETURN_CORROBORATIONS_CAP).toBe(8)
  })

  it('round-trips a bare addition (no claim) — the pre-existing minimum', () => {
    const json = buildReturnEnvelope([{ pubkey: KEN }])
    expect(parseReturnEnvelope(json)).toEqual({ v: 1, additions: [{ pubkey: KEN }] })
  })

  it('carries the claimed provenance and corroborations across the wire', () => {
    const wire: WireKen = {
      pubkey: KEN,
      displayName: 'Wren',
      nip05: 'wren@example.org',
      claimedProvenance: inPerson,
      claimedCorroborations: [dns],
    }
    expect(parseReturnEnvelope(buildReturnEnvelope([wire]))).toEqual({ v: 1, additions: [wire] })
  })

  it('rejects structurally-bad envelopes and drops individually-bad additions', () => {
    expect(parseReturnEnvelope('not json')).toBeNull()
    expect(parseReturnEnvelope(JSON.stringify({ v: 2, additions: [] }))).toBeNull()
    expect(parseReturnEnvelope(JSON.stringify({ v: 1 }))).toBeNull()
    // A bad pubkey drops that addition only.
    const mixed = JSON.stringify({ v: 1, additions: [{ pubkey: 'short' }, { pubkey: KEN }] })
    expect(parseReturnEnvelope(mixed)!.additions).toEqual([{ pubkey: KEN }])
  })

  it('drops a claim with an unrecognised source instead of taking the app at its word', () => {
    const json = JSON.stringify({
      v: 1,
      additions: [{ pubkey: KEN, claimedProvenance: { source: 'telepathy', locator: 'x', confirmedAt: 1 } }],
    })
    expect(parseReturnEnvelope(json)!.additions).toEqual([{ pubkey: KEN }])
  })

  it('sanitises app-supplied display text and caps claimed corroborations', () => {
    const json = JSON.stringify({
      v: 1,
      additions: [{
        pubkey: KEN.toUpperCase(),
        displayName: `${BIDI}Wren `,
        claimedCorroborations: Array.from({ length: 20 }, (_, i) => ({ ...dns, confirmedAt: i })),
      }],
    })
    const parsed = parseReturnEnvelope(json)!.additions[0]
    expect(parsed.pubkey).toBe(KEN)          // lowercased
    expect(parsed.displayName).toBe('Wren')  // control/bidi stripped, then trimmed
    expect(parsed.claimedCorroborations).toHaveLength(RETURN_CORROBORATIONS_CAP)
  })

  it('refuses to build an envelope that would silently lose a claim', () => {
    expect(() => buildReturnEnvelope([{ pubkey: 'not-hex' }])).toThrow(/invalid return envelope/)
    expect(() => buildReturnEnvelope(
      Array.from({ length: RETURN_ADDITIONS_CAP + 1 }, () => ({ pubkey: KEN })),
    )).toThrow(/at most 50 additions/)

    // REGRESSION: a malformed claim on an otherwise-valid addition keeps the additions COUNT
    // identical while destroying exactly the evidence this rail exists to carry. Counting
    // additions alone missed it; the check now compares each addition byte-for-byte.
    expect(() => buildReturnEnvelope([
      { pubkey: KEN, claimedProvenance: { source: 'bogus' as never, locator: 'x', confirmedAt: 1 } },
    ])).toThrow(/would not survive the wire intact/)
    expect(() => buildReturnEnvelope([
      { pubkey: KEN, claimedProvenance: inPerson, claimedCorroborations: [{ ...dns, locator: '' }] },
    ])).toThrow(/would not survive the wire intact/)
    // Exceeding the per-addition cap is a hard error, never a silent truncation.
    expect(() => buildReturnEnvelope([
      { pubkey: KEN, claimedCorroborations: Array.from({ length: RETURN_CORROBORATIONS_CAP + 1 }, () => dns) },
    ])).toThrow(/would not survive the wire intact/)
    // Text that would be rewritten in transit is also caught, not silently mutated.
    expect(() => buildReturnEnvelope([{ pubkey: KEN, displayName: 'x'.repeat(500) }]))
      .toThrow(/would not survive the wire intact/)
  })

  it('never serialises fields outside WireKen, even when TS excess-property checking cannot help', () => {
    // Passing a non-literal defeats TS excess-property checks, so `entries.map(e => ({...e}))`
    // would otherwise ship `sharedSecret`/`annotations` onto the wire. The parser strips them on
    // receipt, which makes such a leak invisible to a round-trip test — hence an explicit check.
    const hostile = { pubkey: KEN, displayName: 'Wren', sharedSecret: 'd'.repeat(64), annotations: { note: 'private' } }
    const json = buildReturnEnvelope([hostile as WireKen])
    expect(json).not.toContain('sharedSecret')
    expect(json).not.toContain('annotations')
    expect(json).not.toContain('private')
  })

  it('lands a claim as CORROBORATION, leaving the primary provenance exactly as designed', () => {
    const entry = landReturnedKen(
      { pubkey: KEN, displayName: 'Wren', claimedProvenance: inPerson, claimedCorroborations: [dns] },
      { appName: 'Murmurate', ownerPubkeyHex: OWNER, nowSec: NOW },
    )

    // The primary is unchanged from the original §10.3 decision — it is what signet-app can itself
    // attest: this key arrived through that companion.
    expect(entry.provenance).toEqual({ source: 'manual', locator: 'companion:Murmurate', confirmedAt: NOW })
    expect(entry.tier).toBe('ken')
    expect(entry.ownerPubkey).toBe(OWNER)
    expect(entry.addedAt).toBe(NOW)

    // The evidence survives — `in-person` is still `in-person`, not flattened to `manual`.
    expect(entry.corroborations).toEqual([
      { source: 'in-person', locator: 'companion:Murmurate:peat-bog-collective/march-gathering', confirmedAt: NOW - 100 },
      { source: 'dns', locator: 'companion:Murmurate:wren.example.org', confirmedAt: NOW - 50 },
    ])
  })

  it('namespaces every claimed locator so a claim can never pass as a first-party confirmation', () => {
    const entry = landReturnedKen(
      { pubkey: KEN, claimedProvenance: { source: 'in-person', locator: 'anywhere', confirmedAt: NOW } },
      { appName: 'Murmurate', ownerPubkeyHex: OWNER, nowSec: NOW },
    )
    for (const c of entry.corroborations!) {
      expect(c.locator.startsWith('companion:Murmurate:')).toBe(true)
    }
  })

  it('clamps a future-dated claim so an app cannot poison recency reasoning', () => {
    const entry = landReturnedKen(
      { pubkey: KEN, claimedProvenance: { ...inPerson, confirmedAt: NOW + 999_999 } },
      { appName: 'Murmurate', ownerPubkeyHex: OWNER, nowSec: NOW },
    )
    expect(entry.corroborations![0].confirmedAt).toBe(NOW)
  })

  it('omits corroborations entirely when the app claims nothing', () => {
    const entry = landReturnedKen({ pubkey: KEN }, { appName: 'Murmurate', ownerPubkeyHex: OWNER, nowSec: NOW })
    expect(entry.corroborations).toBeUndefined()
    expect('corroborations' in entry).toBe(false)
  })

  it('produces an entry the canonical validator accepts', () => {
    const entry = landReturnedKen(
      { pubkey: KEN, displayName: 'Wren', nip05: 'wren@example.org', claimedProvenance: inPerson },
      { appName: 'Murmurate', ownerPubkeyHex: OWNER, nowSec: NOW },
    )
    expect(parseEntry(serializeEntry(entry))).toEqual(entry)
  })

  it('sanitises display text even on a hand-built WireKen that never met the parser', () => {
    // `landReturnedKen` is public and its output goes straight into the user's store, so it must
    // not rely on the caller having gone through `parseReturnEnvelope`.
    const entry = landReturnedKen(
      { pubkey: KEN, displayName: `${BIDI}Wren ` },
      { appName: 'Murmurate', ownerPubkeyHex: OWNER, nowSec: NOW },
    )
    expect(entry.displayName).toBe('Wren')
  })

  it('NEVER sets entry.nip05 from a claim — it is a re-resolution address, not a label', () => {
    // `KenEntry.nip05` is the address `resolveKen` re-fetches, and a key change seen there is
    // surfaced as `via:'nip05'` — a DNS/TLS-anchored signal. Copying an app-supplied identifier in
    // would let a paired companion choose the re-resolution authority for a ken and have its own
    // answer presented as authoritative. The claim is kept as namespaced evidence instead.
    const entry = landReturnedKen(
      { pubkey: KEN, nip05: 'wren@attacker.example' },
      { appName: 'Murmurate', ownerPubkeyHex: OWNER, nowSec: NOW },
    )
    expect(entry.nip05).toBeUndefined()
    expect('nip05' in entry).toBe(false)
    expect(entry.corroborations).toEqual([
      { source: 'nip05', locator: 'companion:Murmurate:wren@attacker.example', confirmedAt: NOW },
    ])
  })

  it('drops a claimed nip05 that is not local@domain — it would reach a fetch URL', () => {
    // `resolveNip05` documents that its input is "validated by the caller"; an unguarded value is
    // interpolated straight into an https:// URL.
    const injection = 'a@evil.example/pwn?x=1'
    expect(parseReturnEnvelope(JSON.stringify({ v: 1, additions: [{ pubkey: KEN, nip05: injection }] }))!
      .additions[0]!.nip05).toBeUndefined()
    const entry = landReturnedKen({ pubkey: KEN, nip05: injection }, { appName: 'A', ownerPubkeyHex: OWNER, nowSec: NOW })
    expect(entry.nip05).toBeUndefined()
    expect(entry.corroborations).toBeUndefined()
  })

  it('runs hand-built claims through the canonical validator, so one bad claim cannot brick a restore', () => {
    // `importEntries` maps `validateEntryShape` over the whole roster (backup.ts), so a single
    // corroboration outside KEN_SOURCES would abort the user's ENTIRE encrypted-backup restore.
    // Fail here on the one bad record instead of persisting a poison pill.
    expect(() => landReturnedKen(
      { pubkey: KEN, claimedProvenance: { source: 'ATTESTED-BY-SIGNET-CORE' as never, locator: 'x', confirmedAt: NOW } },
      { appName: 'Evil', ownerPubkeyHex: OWNER, nowSec: NOW },
    )).toThrow(/provenance.source invalid/)

    for (const locator of [undefined, '', null, { toString: () => 'PWN' }]) {
      expect(() => landReturnedKen(
        { pubkey: KEN, claimedProvenance: { source: 'web', locator, confirmedAt: NOW } as never },
        { appName: 'Evil', ownerPubkeyHex: OWNER, nowSec: NOW },
      )).toThrow(/locator must be a non-empty string/)
    }
  })

  it('strips control characters and bidi overrides from a CLAIMED locator', () => {
    // The locator is the field carrying the claim-vs-confirmation distinction, and it is rendered
    // in provenance and audit views. Without stripping, a hostile app forges an extra line that
    // reads like a first-party confirmation — the namespacing survives at the byte level but the
    // guarantee fails at the layer where a human actually reads it.
    const forged = `ok\n  confirmed by Signet (first party)${BIDI}gnp.exe`
    const entry = landReturnedKen(
      { pubkey: KEN, claimedProvenance: { ...inPerson, locator: forged } },
      { appName: 'Evil', ownerPubkeyHex: OWNER, nowSec: NOW },
    )
    const locator = entry.corroborations![0]!.locator
    expect(locator).toBe('companion:Evil:ok  confirmed by Signet (first party)gnp.exe')
    expect(locator).not.toMatch(/[\n\r‮]/)
    // Same on the untrusted parse path.
    const parsed = parseReturnEnvelope(JSON.stringify({
      v: 1, additions: [{ pubkey: KEN, claimedProvenance: { ...inPerson, locator: forged } }],
    }))!
    expect(parsed.additions[0]!.claimedProvenance!.locator).not.toMatch(/[\n\r‮]/)
  })

  it('caps claimed locator length so one event cannot amplify into unbounded storage', () => {
    const entry = landReturnedKen(
      { pubkey: KEN, claimedProvenance: { ...inPerson, locator: 'x'.repeat(5000) } },
      { appName: 'A', ownerPubkeyHex: OWNER, nowSec: NOW },
    )
    expect(entry.corroborations![0]!.locator.length).toBe('companion:A:'.length + RETURN_LOCATOR_MAX)
  })

  it('clamps an absurd past timestamp and floors to whole seconds', () => {
    const entry = landReturnedKen(
      { pubkey: KEN, claimedProvenance: { ...inPerson, locator: 'l', confirmedAt: -1e308 } },
      { appName: 'A', ownerPubkeyHex: OWNER, nowSec: NOW },
    )
    expect(entry.corroborations![0]!.confirmedAt).toBe(0)
  })

  it('escapes % as well as : so the appName segment stays decodable', () => {
    // Escaping only `:` left `Murmurate:trusted` and the literal `Murmurate%3Atrusted` both
    // mapping to `Murmurate%3Atrusted` — a consumer percent-decoding for display reads them as
    // one app. Escaping the escape character first makes the mapping injective.
    const a = landReturnedKen({ pubkey: KEN }, { appName: 'Murmurate:trusted', ownerPubkeyHex: OWNER, nowSec: NOW })
    const b = landReturnedKen({ pubkey: KEN }, { appName: 'Murmurate%3Atrusted', ownerPubkeyHex: OWNER, nowSec: NOW })
    expect(a.provenance.locator).toBe('companion:Murmurate%3Atrusted')
    expect(b.provenance.locator).toBe('companion:Murmurate%253Atrusted')
    expect(a.provenance.locator).not.toBe(b.provenance.locator)
  })

  it('throws its own namespaced error on null/missing input, not a property-access TypeError', () => {
    expect(() => landReturnedKen(null as never, { appName: 'A', ownerPubkeyHex: OWNER, nowSec: NOW }))
      .toThrow(/returned ken must be an object/)
    expect(() => landReturnedKen({} as never, { appName: 'A', ownerPubkeyHex: OWNER, nowSec: NOW }))
      .toThrow(/must be strings/)
    expect(() => landReturnedKen({ pubkey: KEN }, { appName: 'A' } as never))
      .toThrow(/must be strings/)
    expect(() => landReturnedKen({ pubkey: KEN }, { appName: 'A', ownerPubkeyHex: OWNER, nowSec: -1.5 }))
      .toThrow(/nowSec must be a non-negative integer/)
  })

  it('makes the locator namespace UNFORGEABLE by escaping the delimiter in appName', () => {
    // REGRESSION (real spoof): with a raw `:` allowed in appName the grammar is not injective —
    // app `Murmurate:trusted` claiming `y` produced a locator byte-identical to legitimate app
    // `Murmurate` claiming `trusted:y`, letting any app forge another's namespace.
    const legit = landReturnedKen(
      { pubkey: KEN, claimedProvenance: { ...inPerson, locator: 'trusted:y' } },
      { appName: 'Murmurate', ownerPubkeyHex: OWNER, nowSec: NOW },
    )
    const spoofer = landReturnedKen(
      { pubkey: KEN, claimedProvenance: { ...inPerson, locator: 'y' } },
      { appName: 'Murmurate:trusted', ownerPubkeyHex: OWNER, nowSec: NOW },
    )
    expect(legit.corroborations![0].locator).toBe('companion:Murmurate:trusted:y')
    expect(spoofer.corroborations![0].locator).toBe('companion:Murmurate%3Atrusted:y')
    expect(spoofer.corroborations![0].locator).not.toBe(legit.corroborations![0].locator)
    // The primary audit tag is disambiguated the same way.
    expect(spoofer.provenance.locator).toBe('companion:Murmurate%3Atrusted')
    // Ordinary names are untouched, so the resolved `companion:<appName>` format still holds.
    expect(legit.provenance.locator).toBe('companion:Murmurate')

    // Splitting on the first two colons always recovers (appName, claimed locator) exactly.
    const [, app, ...rest] = spoofer.corroborations![0].locator.split(':')
    expect(app).toBe('Murmurate%3Atrusted')
    expect(rest.join(':')).toBe('y')
  })

  it('rejects a non-finite claimed timestamp instead of emitting an invalid entry', () => {
    // REGRESSION: NaN survived `Math.min`, producing an entry kenspeckle's own validator rejects.
    for (const confirmedAt of [NaN, Infinity, -Infinity]) {
      expect(() => landReturnedKen(
        { pubkey: KEN, claimedProvenance: { ...inPerson, confirmedAt } },
        { appName: 'Murmurate', ownerPubkeyHex: OWNER, nowSec: NOW },
      )).toThrow(/confirmedAt must be a finite number/)
    }
  })

  it('sanitises a hostile appName and rejects bad keys', () => {
    const entry = landReturnedKen(
      { pubkey: KEN, claimedProvenance: inPerson },
      { appName: `${BIDI}Evil `, ownerPubkeyHex: OWNER.toUpperCase(), nowSec: NOW },
    )
    expect(entry.provenance.locator).toBe('companion:Evil')
    expect(entry.ownerPubkey).toBe(OWNER)

    expect(() => landReturnedKen({ pubkey: 'nope' }, { appName: 'A', ownerPubkeyHex: OWNER, nowSec: NOW })).toThrow(/64-hex/)
    expect(() => landReturnedKen({ pubkey: KEN }, { appName: 'A', ownerPubkeyHex: 'nope', nowSec: NOW })).toThrow(/64-hex/)
  })
})

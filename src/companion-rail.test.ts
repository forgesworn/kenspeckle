import { describe, expect, it } from 'vitest'
import { buildGrantEnvelope } from './grant-envelope.js'
import {
  ACK_KIND,
  SNAPSHOT_D_TAG,
  SNAPSHOT_KIND,
  applyCompanionSnapshot,
  buildPairingAck,
  buildPairingUri,
  parsePairingAck,
  parsePairingRequest,
} from './companion-rail.js'
import type { CompanionSnapshotState, PairingAck } from './companion-rail.js'

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

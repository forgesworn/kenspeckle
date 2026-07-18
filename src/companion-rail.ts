// Companion data rail — pure producer/consumer wire contract.
//
// This module deliberately contains no relay client, subscription, timer,
// storage, signing, encryption or UI code. Applications own those concerns;
// Kindred owns only the bytes and state transition they must agree on.

import type { GrantContactView, GrantScope } from './grant-envelope.js'
import { parseGrantEnvelope } from './grant-envelope.js'

export const PAIRING_SCHEME = 'signet-grant:'
export const ACK_KIND = 21237
export const SNAPSHOT_KIND = 30078
export const SNAPSHOT_D_TAG = 'signet:companion-rail'
export const DEFAULT_PAIRING_FRESHNESS_SECONDS = 5 * 60

const HEX64 = /^[0-9a-f]{64}$/
const CHALLENGE_HEX = /^[0-9a-f]{16,}$/i
const TIERS = ['kin', 'kith', 'ken'] as const
// Same display-boundary class used by Signet. Strip before trim before slice.
// eslint-disable-next-line no-control-regex
const CONTROL_BIDI = /[\x00-\x1f\x7f-\x9f\u200b-\u200f\u2028-\u202e\u2066-\u2069]/g

export type CompanionTier = (typeof TIERS)[number]

export interface PairingUriOptions {
  appPubkey: string
  appName: string
  scope: string | readonly CompanionTier[]
  relay: string
  nowSec: number
  challenge: string
}

export interface PairingRequest {
  appPubkey: string
  appName: string
  tiers: CompanionTier[]
  rendezvousRelay: string
  t: number
  challenge: string
}

export interface PairingRequestResult {
  request: PairingRequest | null
  warnings: string[]
}

export interface PairingAck {
  v: 1
  railPubkey: string
  dTag: string
  snapshotRelay: string
  grantedScope: GrantScope
  challenge: string
}

/** Consumer-side persisted pairing. `pairedAt` is local metadata, not wire. */
export interface CompanionPairing extends Omit<PairingAck, 'v' | 'challenge'> {
  pairedAt: number
}

/** Minimal state reduced by a decrypted companion snapshot. Extra app fields survive. */
export interface CompanionSnapshotState {
  pairing?: CompanionPairing
  lastPublishedAt?: number
  contacts: GrantContactView[]
  revoked?: boolean
}

/** Production relays require TLS; plaintext is reserved for loopback development. */
export function isValidCompanionRelayUrl(value: string): boolean {
  return /^wss:\/\//i.test(value) || /^ws:\/\/(localhost|127\.0\.0\.1)([:/]|$)/i.test(value)
}

/** Build the byte-stable URI scanned by the Signet producer. Parameter order is binding. */
export function buildPairingUri(opts: PairingUriOptions): string {
  if (!HEX64.test(opts.appPubkey)) throw new TypeError('companion rail: app pubkey must be lowercase 64-hex')
  if (!isValidCompanionRelayUrl(opts.relay)) throw new TypeError('companion rail: invalid relay URL')
  if (!Number.isInteger(opts.nowSec) || opts.nowSec < 0) throw new TypeError('companion rail: invalid timestamp')
  if (!CHALLENGE_HEX.test(opts.challenge)) throw new TypeError('companion rail: invalid challenge')

  const scope = typeof opts.scope === 'string' ? opts.scope : opts.scope.join(',')
  const params = new URLSearchParams()
  params.set('app', opts.appPubkey)
  params.set('name', opts.appName)
  params.set('scope', scope)
  params.set('relay', opts.relay)
  params.set('t', String(opts.nowSec))
  params.set('challenge', opts.challenge)
  return `${PAIRING_SCHEME}//pair?${params.toString()}`
}

/**
 * Parse either the native pairing URI, a bare query, or an HTTPS carrier URL.
 * The caller supplies `nowSec` in deterministic tests; production defaults to
 * the current clock. Unknown scope tokens are dropped and reported.
 */
export function parsePairingRequest(
  input: string,
  opts: { nowSec?: number; freshnessSeconds?: number } = {},
): PairingRequestResult {
  const warnings: string[] = []
  let params: URLSearchParams
  try {
    const qIndex = input.indexOf('?')
    params = new URLSearchParams(qIndex >= 0 ? input.slice(qIndex + 1) : input)
  } catch {
    return { request: null, warnings: ['malformed'] }
  }

  const appPubkey = (params.get('app') ?? '').toLowerCase()
  if (!HEX64.test(appPubkey)) return { request: null, warnings: ['bad-app-pubkey'] }

  const rendezvousRelay = params.get('relay') ?? ''
  if (!isValidCompanionRelayUrl(rendezvousRelay)) return { request: null, warnings: ['bad-relay'] }

  const t = Number(params.get('t'))
  if (!Number.isInteger(t) || t < 0) return { request: null, warnings: ['bad-timestamp'] }
  const nowSec = opts.nowSec ?? Math.floor(Date.now() / 1000)
  const freshnessSeconds = opts.freshnessSeconds ?? DEFAULT_PAIRING_FRESHNESS_SECONDS
  if (Math.abs(nowSec - t) > freshnessSeconds) return { request: null, warnings: ['stale-timestamp'] }

  // Validate case-insensitively but preserve verbatim: the ack echoes this
  // challenge byte-for-byte, including uppercase hex from another consumer.
  const challenge = params.get('challenge') ?? ''
  if (!CHALLENGE_HEX.test(challenge)) return { request: null, warnings: ['bad-challenge'] }

  const rawScope = (params.get('scope') ?? '').split(',').map((tier) => tier.trim()).filter(Boolean)
  const tiers = rawScope.filter((tier): tier is CompanionTier => TIERS.includes(tier as CompanionTier))
  if (rawScope.some((tier) => !TIERS.includes(tier as CompanionTier))) warnings.push('scope-unknown-token')
  if (tiers.length === 0) warnings.push('scope-empty-defaulted-all')

  const appName = (params.get('name') ?? '').replace(CONTROL_BIDI, '').trim().slice(0, 64) || 'Companion app'
  return {
    request: {
      appPubkey,
      appName,
      tiers: tiers.length > 0 ? tiers : [...TIERS],
      rendezvousRelay,
      t,
      challenge,
    },
    warnings,
  }
}

/** Build the JSON plaintext encrypted into the ephemeral kind-21237 ack. */
export function buildPairingAck(ack: PairingAck): string {
  if (!parsePairingAck(JSON.stringify(ack), ack.challenge)) {
    throw new TypeError('companion rail: invalid pairing ack')
  }
  return JSON.stringify(ack)
}

/** Parse and validate a decrypted ack, including challenge and grant scope. */
export function parsePairingAck(plaintext: string, expectedChallenge: string): PairingAck | null {
  let raw: unknown
  try {
    raw = JSON.parse(plaintext)
  } catch {
    return null
  }
  if (typeof raw !== 'object' || raw === null) return null
  const ack = raw as Record<string, unknown>
  if (ack.v !== 1) return null
  if (typeof ack.railPubkey !== 'string' || !HEX64.test(ack.railPubkey)) return null
  if (typeof ack.snapshotRelay !== 'string' || !isValidCompanionRelayUrl(ack.snapshotRelay)) return null
  if (typeof ack.challenge !== 'string' || ack.challenge !== expectedChallenge) return null

  const grantedScope = parseGrantScope(ack.grantedScope)
  if (!grantedScope) return null
  const dTag = ack.dTag === undefined ? SNAPSHOT_D_TAG : ack.dTag
  if (typeof dTag !== 'string' || dTag.length === 0) return null

  return {
    v: 1,
    railPubkey: ack.railPubkey,
    dTag,
    snapshotRelay: ack.snapshotRelay,
    grantedScope,
    challenge: ack.challenge,
  }
}

/**
 * Apply a decrypted snapshot monotonically. Malformed/stale envelopes return
 * the exact input object. A revocation purges contacts and pairing state.
 */
export function applyCompanionSnapshot<T extends CompanionSnapshotState>(state: T, envelopeJson: string): T {
  const envelope = parseGrantEnvelope(envelopeJson)
  if (!envelope) return state
  if (state.lastPublishedAt !== undefined && envelope.publishedAt <= state.lastPublishedAt) return state

  if (envelope.revoked === true) {
    return {
      ...state,
      pairing: undefined,
      contacts: [],
      revoked: true,
      lastPublishedAt: envelope.publishedAt,
    }
  }

  return {
    ...state,
    contacts: envelope.contacts,
    lastPublishedAt: envelope.publishedAt,
    revoked: false,
  }
}

function parseGrantScope(value: unknown): GrantScope | null {
  if (typeof value !== 'object' || value === null) return null
  const scope = value as Record<string, unknown>
  if (!Array.isArray(scope.tiers) || scope.tiers.some((tier) => !TIERS.includes(tier as CompanionTier))) return null

  if (scope.personas === 'all') return { tiers: [...scope.tiers] as CompanionTier[], personas: 'all' }
  if (!Array.isArray(scope.personas) || scope.personas.some((pubkey) => typeof pubkey !== 'string' || !HEX64.test(pubkey))) {
    return null
  }
  return { tiers: [...scope.tiers] as CompanionTier[], personas: [...scope.personas] as string[] }
}

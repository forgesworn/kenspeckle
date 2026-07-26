// Companion data rail — pure producer/consumer wire contract.
//
// This module deliberately contains no relay client, subscription, timer,
// storage, signing, encryption or UI code. Applications own those concerns;
// Kindred owns only the bytes and state transition they must agree on.

import type { GrantContactView, GrantScope } from './grant-envelope.js'
import { parseGrantEnvelope } from './grant-envelope.js'
import { COMPANION_LOCATOR_PREFIX } from './types.js'
import type { KenEntry, KenProvenance } from './types.js'
import { validateProvenance } from './validate.js'

export const PAIRING_SCHEME = 'signet-grant:'
export const ACK_KIND = 21237
export const SNAPSHOT_KIND = 30078
export const SNAPSHOT_D_TAG = 'signet:companion-rail'
export const RETURN_D_TAG = 'signet:companion-return'
export const DEFAULT_PAIRING_FRESHNESS_SECONDS = 5 * 60
/** Bound inbound abuse: a proposing app cannot flood the store in one snapshot (design §10.3). */
export const RETURN_ADDITIONS_CAP = 50
/** Bound one ken's claimed evidence so a single addition cannot carry an unbounded array. */
export const RETURN_CORROBORATIONS_CAP = 8

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

// --- return rail (design §10) ------------------------------------------------------------------
//
// The companion app holds NO identity keys, so it cannot mint kith/kin — those require an ECDH
// ceremony between identity keys. It can only capture a name + pubkey, which is a ken. So the
// return direction is kens-only, and every returned ken is a PROPOSAL, never a verification.
//
// WHY THE CLAIM TRAVELS: the companion is frequently where the evidence actually IS. Someone who
// meets a person at a gathering and scans their code standing next to them has `in-person`
// provenance with a real locator and a real timestamp. Flattening that to "manual, via some app"
// destroys the most valuable evidence in the system at exactly the moment it is captured. So the
// app states what it CLAIMS, and the claim survives the journey.
//
// WHY THE CLAIM IS STILL NOT TRUSTED: signet-app remains the sole authority on identity truth. A
// claim is not a confirmation. `landReturnedKen` therefore keeps the primary `provenance` as what
// signet-app can itself attest — "this arrived via companion X" — and files every claim as a
// CORROBORATION whose locator is namespaced `companion:<appName>:<claimed locator>`. The claim is
// preserved in full, and is structurally impossible to misread as a first-party confirmation.

/** A ken a companion app PROPOSES back to signet-app. No `ownerPubkey` (signet-app assigns it) and
 *  no secrets — the app has none to give. `claimed*` fields are assertions by the app, not facts. */
export interface WireKen {
  pubkey: string
  displayName?: string
  nip05?: string
  /** How the proposing app says it came to believe this key. Preserved, never auto-trusted. */
  claimedProvenance?: KenProvenance
  /** Further channels the app says also agree. Same claim status as `claimedProvenance`. */
  claimedCorroborations?: KenProvenance[]
}

export interface ReturnEnvelope {
  v: 1
  additions: WireKen[]
}

/** Sanitise app-supplied display text at the trust boundary (strip → trim → slice, as §7.1). */
function cleanText(value: unknown, max: number): string | undefined {
  if (typeof value !== 'string') return undefined
  const out = value.replace(CONTROL_BIDI, '').trim().slice(0, max)
  return out.length > 0 ? out : undefined
}

/**
 * The `<appName>` segment of a provenance locator, percent-escaping `%` then `:`.
 *
 * LOAD-BEARING, not cosmetic. Locators are structured `companion:<appName>` (primary) and
 * `companion:<appName>:<claimed locator>` (corroboration). If a raw `:` could appear in the app
 * name, that grammar is NOT injective and the namespace is forgeable: an app calling itself
 * `Murmurate:trusted` and claiming locator `y` produces `companion:Murmurate:trusted:y` — byte
 * identical to the legitimate app `Murmurate` claiming locator `trusted:y`.
 *
 * `%` MUST be escaped FIRST, and for the same reason: escaping only `:` leaves
 * `Murmurate:trusted` and the literal `Murmurate%3Atrusted` both mapping to `Murmurate%3Atrusted`,
 * so a consumer that percent-decodes the segment for display reads two different apps as one.
 * Escaping the escape character first makes the mapping injective and therefore decodable.
 *
 * Only `%` and `:` are touched, so ordinary names ("Murmurate", "Companion app") are unchanged and
 * the `companion:<appName>` audit tag keeps the format already resolved in the design doc.
 */
function appNamespace(appName: string): string {
  return (cleanText(appName, 64) ?? 'Companion app').replaceAll('%', '%25').replaceAll(':', '%3A')
}

/** Longest claimed locator kept. Unbounded locators are a persistent storage-amplification bug:
 *  the count caps alone still allow 50 × 9 unbounded strings from ONE relay event. */
export const RETURN_LOCATOR_MAX = 512

/**
 * Invisible / direction-controlling characters stripped from a CLAIMED locator.
 *
 * Wider than this module's `CONTROL_BIDI` (which is frozen: it defines already-shipped forward-rail
 * display sanitisation and is covered by the frozen vector). A locator is written by a hostile app
 * and later rendered in provenance lists and audit views, so it additionally excludes word-joiner /
 * BOM / Arabic-letter-mark / Mongolian vowel separator and the U+E0000 tag block — the standard
 * invisible-text-smuggling range. Newlines matter most: without stripping them a claim can forge an
 * extra line reading like a first-party confirmation, which defeats the namespacing at exactly the
 * layer where a human reads it.
 */
// eslint-disable-next-line no-control-regex
const LOCATOR_UNSAFE = /[\x00-\x1f\x7f-\x9f\u061c\u180e\u200b-\u200f\u2028-\u202e\u2060-\u2064\u2066-\u2069\ufeff]|[\u{e0000}-\u{e007f}]/gu

/** Sanitise a claimed locator for storage/display. Returns undefined if nothing survives. */
function cleanLocator(value: string): string | undefined {
  const out = value.replace(LOCATOR_UNSAFE, '').trim().slice(0, RETURN_LOCATOR_MAX)
  return out.length > 0 ? out : undefined
}

/** Validate one claimed provenance, reusing kindred's single `KEN_SOURCES` allow-list, then
 *  sanitise its locator. Returns null instead of throwing so one bad claim drops that claim, not
 *  the whole envelope. */
function parseClaimedProvenance(v: unknown): KenProvenance | null {
  let p: KenProvenance
  try {
    p = validateProvenance(v)
  } catch {
    return null
  }
  const locator = cleanLocator(p.locator)
  if (locator === undefined) return null
  return { source: p.source, locator, confirmedAt: p.confirmedAt }
}

/** Basic NIP-05 `local@domain` shape — the SAME guard `./ken` applies before resolving. A claimed
 *  identifier that fails this must never reach a URL constructor. Mirrors `ken.ts`'s `NIP05`. */
const NIP05 = /^[a-z0-9\-_.]+@[a-z0-9\-_.]+$/i

/** Project a `WireKen` to exactly its declared fields — never the caller's object.
 *
 *  Structural, not cosmetic: TypeScript's excess-property check does NOT apply to a non-literal
 *  argument, so `buildReturnEnvelope(entries.map(e => ({ ...e })))` type-checks and would otherwise
 *  serialise `sharedSecret` / `annotations` straight onto the wire. The parser strips them on
 *  receipt, which makes such a leak invisible to a round-trip test. Same discipline as `toWire`
 *  and `GrantContactView`: the projection is what guarantees the wire carries nothing else. */
function projectWireKen(k: WireKen): WireKen {
  const out: WireKen = { pubkey: k.pubkey }
  if (k.displayName !== undefined) out.displayName = k.displayName
  if (k.nip05 !== undefined) out.nip05 = k.nip05
  if (k.claimedProvenance !== undefined) out.claimedProvenance = k.claimedProvenance
  if (k.claimedCorroborations !== undefined) out.claimedCorroborations = k.claimedCorroborations
  return out
}

function parseWireKen(item: unknown): WireKen | null {
  if (typeof item !== 'object' || item === null) return null
  const k = item as Record<string, unknown>
  if (typeof k.pubkey !== 'string' || !HEX64.test(k.pubkey.toLowerCase())) return null

  const out: WireKen = { pubkey: k.pubkey.toLowerCase() }
  const displayName = cleanText(k.displayName, 200)
  if (displayName !== undefined) out.displayName = displayName
  // Shape-guard the claimed identifier here too: `resolveNip05` documents that its input is
  // "validated by the caller", and an unguarded value would be interpolated into a fetch URL.
  const nip05 = cleanText(k.nip05, 200)
  if (nip05 !== undefined && NIP05.test(nip05)) out.nip05 = nip05

  const claimed = parseClaimedProvenance(k.claimedProvenance)
  if (claimed) out.claimedProvenance = claimed

  if (Array.isArray(k.claimedCorroborations)) {
    const list = k.claimedCorroborations
      .slice(0, RETURN_CORROBORATIONS_CAP)
      .map(parseClaimedProvenance)
      .filter((p): p is KenProvenance => p !== null)
    if (list.length > 0) out.claimedCorroborations = list
  }
  return out
}

/**
 * Build the JSON plaintext encrypted into the kind-30078 `signet:companion-return` event.
 *
 * Serialises an explicit PROJECTION of each addition (never the caller's object — see
 * `projectWireKen`), then round-trips through the parser and throws unless every addition survives
 * BYTE-IDENTICALLY. A count-only check is not enough: a malformed `claimedProvenance`, an
 * over-long `displayName`, or a whitespace-only name is dropped or rewritten while the count stays
 * the same — losing exactly the evidence this rail exists to carry, silently. So a producer learns
 * at build time rather than discovering the loss after transit.
 *
 * This also makes the caps a hard error rather than a silent truncation: exceeding
 * `RETURN_CORROBORATIONS_CAP` on any addition throws here instead of quietly dropping claim nine.
 */
export function buildReturnEnvelope(additions: WireKen[]): string {
  if (!Array.isArray(additions)) throw new TypeError('companion rail: additions must be an array')
  if (additions.length > RETURN_ADDITIONS_CAP) {
    throw new TypeError(`companion rail: at most ${RETURN_ADDITIONS_CAP} additions per envelope`)
  }
  const projected = additions.map(projectWireKen)
  const json = JSON.stringify({ v: 1, additions: projected } satisfies ReturnEnvelope)
  const reparsed = parseReturnEnvelope(json)
  if (!reparsed || reparsed.additions.length !== projected.length) {
    throw new TypeError('companion rail: invalid return envelope')
  }
  for (const [i, addition] of projected.entries()) {
    const survived = reparsed.additions[i]
    if (!survived || JSON.stringify(survived) !== JSON.stringify(addition)) {
      throw new TypeError(`companion rail: addition ${i} would not survive the wire intact`)
    }
  }
  return json
}

/** Parse a decrypted return envelope. Structurally-bad envelopes yield null; individually-invalid
 *  additions are dropped (same fail-soft posture as `parseGrantEnvelope`). Caps the additions list. */
export function parseReturnEnvelope(json: string): ReturnEnvelope | null {
  let raw: unknown
  try {
    raw = JSON.parse(json)
  } catch {
    return null
  }
  if (typeof raw !== 'object' || raw === null) return null
  const env = raw as Record<string, unknown>
  if (env.v !== 1) return null
  if (!Array.isArray(env.additions)) return null

  const additions: WireKen[] = []
  for (const item of env.additions.slice(0, RETURN_ADDITIONS_CAP)) {
    const ken = parseWireKen(item)
    if (ken) additions.push(ken)
  }
  return { v: 1, additions }
}

/**
 * Project a proposed `WireKen` into a `KenEntry` signet-app can store.
 *
 * The primary `provenance` is UNCHANGED from the design's original decision —
 * `{ source:'manual', locator:'companion:<appName>' }` — because that is precisely what signet-app
 * can attest from its own knowledge: this key arrived through that companion. Everything the app
 * CLAIMED is preserved as corroboration, with two hardening rules applied here (in ONE place, so
 * they cannot drift):
 *
 *   1. **Namespaced locator** — every claimed locator becomes `companion:<appName>:<locator>`, so a
 *      claim can never be read as something signet-app confirmed itself. The claimed `source` is
 *      preserved verbatim: an `in-person` claim stays `in-person`, which is the entire point.
 *   2. **Clamped timestamp** — `confirmedAt` is clamped into `[0, nowSec]`. An app must not be able
 *      to claim a confirmation from the future (or the pre-epoch past) and poison recency reasoning.
 *
 * ── `nip05` IS NOT SET FROM A CLAIM ───────────────────────────────────────────────────────────────
 * `KenEntry.nip05` is not a label — it is the ADDRESS `resolveKen` re-fetches, and a key change
 * observed there is surfaced to the user as `via:'nip05'`, i.e. a DNS/TLS-anchored signal. Copying
 * an unverified companion-supplied identifier into it would let a paired app choose the
 * re-resolution authority for a ken and have its answer presented as an authoritative rotation
 * proposal — precisely the "no app but signet-app is a source of identity truth" rule this rail is
 * built around. So a claimed `nip05` is recorded as a namespaced CORROBORATION (evidence) and
 * `entry.nip05` is left UNSET. signet-app sets it only after resolving the identifier itself
 * (`pinKenFromNip05` / `resolveKen`), which is the only step that makes it a confirmation.
 *
 * `nowSec` is injected rather than read from the clock so this stays pure and deterministically
 * testable, matching the rest of this module.
 *
 * @throws if `pubkey` / `ownerPubkeyHex` are not 64-hex, `nowSec` is not a non-negative integer, or
 *         any claim fails kindred's canonical `validateProvenance`.
 */
export function landReturnedKen(
  wire: WireKen,
  opts: { appName: string; ownerPubkeyHex: string; nowSec: number },
): KenEntry {
  // Guard shapes BEFORE touching them: a null/!object `wire` or a missing `ownerPubkeyHex` must
  // produce this module's namespaced error, not a bare "cannot read properties of undefined".
  if (typeof wire !== 'object' || wire === null) {
    throw new TypeError('companion rail: returned ken must be an object')
  }
  if (typeof wire.pubkey !== 'string' || typeof opts?.ownerPubkeyHex !== 'string') {
    throw new TypeError('companion rail: returned ken pubkey and ownerPubkey must be strings')
  }
  const pubkey = wire.pubkey.toLowerCase()
  const ownerPubkey = opts.ownerPubkeyHex.toLowerCase()
  if (!HEX64.test(pubkey)) throw new TypeError('companion rail: returned ken pubkey must be 64-hex')
  if (!HEX64.test(ownerPubkey)) throw new TypeError('companion rail: ownerPubkey must be 64-hex')
  // Non-negative integer, matching `buildPairingUri`'s timestamp guard in this module.
  if (!Number.isInteger(opts.nowSec) || opts.nowSec < 0) {
    throw new TypeError('companion rail: nowSec must be a non-negative integer')
  }

  // Re-sanitise appName at this boundary too: it originated in the pairing request, and this
  // function may be called with a stored value rather than a freshly-parsed one. `appNamespace`
  // also escapes `:` so the locator grammar stays unforgeable — see its doc comment.
  const appName = appNamespace(opts.appName)

  const claimed: KenProvenance[] = [
    ...(wire.claimedProvenance ? [wire.claimedProvenance] : []),
    ...(wire.claimedCorroborations ?? []),
  ]
  // Run every claim through kindred's CANONICAL validator, not an ad-hoc check. This function is
  // public and may be handed a hand-built `WireKen` that never met `parseReturnEnvelope`; an
  // unvalidated claim would produce an entry that `validateEntryShape` later rejects, and because
  // `importEntries` maps the validator over the whole roster, ONE bad corroboration would abort the
  // user's entire backup restore. Fail here, loudly, on the single bad record instead.
  const claims = claimed.map((c) => {
    const p = validateProvenance(c)
    const locator = cleanLocator(p.locator)
    if (locator === undefined) {
      throw new TypeError('companion rail: claimed locator is empty after sanitisation')
    }
    return { source: p.source, locator, confirmedAt: p.confirmedAt }
  })

  const entry: KenEntry = {
    tier: 'ken',
    pubkey,
    ownerPubkey,
    addedAt: opts.nowSec,
    provenance: { source: 'manual', locator: `${COMPANION_LOCATOR_PREFIX}${appName}`, confirmedAt: opts.nowSec },
  }
  // Re-sanitise here as well as in `parseWireKen`, for the same hand-built-input reason: this
  // output goes straight into the user's store.
  const displayName = cleanText(wire.displayName, 200)
  if (displayName !== undefined) entry.displayName = displayName

  // A claimed nip05 is EVIDENCE, not an address — see the note above. Shape-guard it (it would
  // otherwise be interpolated into a fetch URL by `resolveNip05`) and file it as a corroboration.
  const claimedNip05 = cleanText(wire.nip05, 200)
  if (claimedNip05 !== undefined && NIP05.test(claimedNip05)) {
    claims.push({ source: 'nip05', locator: claimedNip05, confirmedAt: opts.nowSec })
  }

  if (claims.length > 0) {
    entry.corroborations = claims.map((c) => ({
      source: c.source,
      locator: `${COMPANION_LOCATOR_PREFIX}${appName}:${c.locator}`,
      // Clamp into [0, nowSec] and floor to whole seconds. The upper bound stops an app claiming a
      // future confirmation; the lower bound stops an absurd pre-epoch value (finite, so
      // `validateProvenance` accepts it) landing in `summarizeKenProvenance().oldestAt` and
      // rendering as an Invalid Date. Floor keeps kindred's whole-second timestamp convention.
      confirmedAt: Math.floor(Math.min(Math.max(c.confirmedAt, 0), opts.nowSec)),
    }))
  }
  return entry
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

// kenspeckle — shared runtime field guards for untrusted `KindredEntry` input.
//
// One validator backs both `parseEntry` (wire form — annotations stripped) and the encrypted
// self-backup importer (annotations legitimately preserved). The `allowAnnotations` flag is the
// only behavioural difference: when false, a present `annotations` key on the input is dropped
// (wire form never carries them); when true, a present `annotations` object is validated and kept.
//
// Per signet-app security conventions, every field of attacker/disk-controlled input is checked
// before it is trusted: tiers are allow-listed, pubkeys are 64-hex, timestamps are finite numbers,
// mutual tiers require a 64-hex shared secret + verifiedAt, ken requires a structured provenance.

import type {
  KindredEntry,
  KinEntry,
  KithEntry,
  KenEntry,
  KenProvenance,
  KenRotation,
  PrivateAnnotations,
} from './types.js'

const HEX64 = /^[0-9a-f]{64}$/i

const KIN_RELATIONSHIPS = new Set([
  'parent',
  'child',
  'sibling',
  'grandparent',
  'partner',
  'guardian',
  'dependant',
  'other',
])

const KEN_SOURCES = new Set(['nip05', 'dns', 'web', 'social-channel', 'in-person', 'manual'])

/** Upper bound on `KenEntry.corroborations` — see the note at its validation site. */
export const MAX_CORROBORATIONS = 64
const KEN_ROTATION_VIA = new Set(['nip05', 'announcement', 'manual'])

function isRecord(v: unknown): v is Record<string, unknown> {
  return v !== null && typeof v === 'object' && !Array.isArray(v)
}

function reqHex64(o: Record<string, unknown>, field: string): string {
  const v = o[field]
  if (typeof v !== 'string' || !HEX64.test(v)) {
    throw new Error(`kenspeckle entry: ${field} must be 64 hex chars`)
  }
  // Lowercase-normalize on parse. A restored/imported backup can carry UPPERCASE hex; nostr-tools
  // always emits lowercase `event.pubkey`, so an uppercase `pubkey`/`ownerPubkey`/`sharedSecret`
  // would silently break strict-equality in verifyKeyControl / attributeSignature downstream.
  return v.toLowerCase()
}

function reqFiniteNumber(o: Record<string, unknown>, field: string): number {
  const v = o[field]
  if (typeof v !== 'number' || !Number.isFinite(v)) {
    throw new Error(`kenspeckle entry: ${field} must be a finite number`)
  }
  return v
}

function optString(o: Record<string, unknown>, field: string): string | undefined {
  const v = o[field]
  if (v === undefined) return undefined
  if (typeof v !== 'string') throw new Error(`kenspeckle entry: ${field} must be a string`)
  return v
}

/** Exported so the companion RETURN rail validates claimed provenance against the SAME allow-list.
 *  One `KEN_SOURCES` set in the codebase — a second copy is how the two silently drift apart. */
export function validateProvenance(v: unknown): KenProvenance {
  if (!isRecord(v)) throw new Error('kenspeckle ken: provenance must be an object')
  const source = v.source
  if (typeof source !== 'string' || !KEN_SOURCES.has(source)) {
    throw new Error('kenspeckle ken: provenance.source invalid')
  }
  if (typeof v.locator !== 'string' || v.locator.length === 0) {
    throw new Error('kenspeckle ken: provenance.locator must be a non-empty string')
  }
  if (typeof v.confirmedAt !== 'number' || !Number.isFinite(v.confirmedAt)) {
    throw new Error('kenspeckle ken: provenance.confirmedAt must be a finite number')
  }
  return { source: source as KenProvenance['source'], locator: v.locator, confirmedAt: v.confirmedAt }
}

function validateRotation(v: unknown): KenRotation {
  if (!isRecord(v)) throw new Error('kenspeckle ken: rotation must be an object')
  if (typeof v.newPubkey !== 'string' || !HEX64.test(v.newPubkey)) {
    throw new Error('kenspeckle ken: rotation.newPubkey must be 64 hex')
  }
  if (typeof v.observedAt !== 'number' || !Number.isFinite(v.observedAt)) {
    throw new Error('kenspeckle ken: rotation.observedAt must be a finite number')
  }
  if (typeof v.via !== 'string' || !KEN_ROTATION_VIA.has(v.via)) {
    throw new Error('kenspeckle ken: rotation.via invalid')
  }
  if (typeof v.accepted !== 'boolean') {
    throw new Error('kenspeckle ken: rotation.accepted must be a boolean')
  }
  const out: KenRotation = {
    // Lowercase-normalize (same reason as reqHex64: must strict-equal nostr-tools' lowercase pubkey).
    newPubkey: v.newPubkey.toLowerCase(),
    observedAt: v.observedAt,
    via: v.via as KenRotation['via'],
    accepted: v.accepted,
  }
  if (v.announcementEventId !== undefined) {
    if (typeof v.announcementEventId !== 'string') {
      throw new Error('kenspeckle ken: rotation.announcementEventId must be a string')
    }
    out.announcementEventId = v.announcementEventId
  }
  return out
}

function validateAnnotations(v: unknown): PrivateAnnotations {
  if (!isRecord(v)) throw new Error('kenspeckle entry: annotations must be an object')
  const out: PrivateAnnotations = {}
  if (v.groupId !== undefined) {
    if (typeof v.groupId !== 'string') throw new Error('kenspeckle entry: annotations.groupId must be a string')
    // groupId is a hex-shaped recall id (`linkForRecall` emits `bytesToHex(randomBytes(8))`);
    // lowercase-normalize so a restored uppercase value still groups/compares correctly.
    out.groupId = v.groupId.toLowerCase()
  }
  if (v.label !== undefined) {
    if (typeof v.label !== 'string') throw new Error('kenspeckle entry: annotations.label must be a string')
    out.label = v.label
  }
  if (v.note !== undefined) {
    if (typeof v.note !== 'string') throw new Error('kenspeckle entry: annotations.note must be a string')
    out.note = v.note
  }
  if (v.blocked !== undefined) {
    if (typeof v.blocked !== 'boolean') throw new Error('kenspeckle entry: annotations.blocked must be a boolean')
    out.blocked = v.blocked
  }
  return out
}

/**
 * Validate an untrusted value into a typed `KindredEntry`.
 * @param raw  the parsed JSON value (untrusted).
 * @param allowAnnotations  when true a present `annotations` object is validated and preserved
 *   (encrypted self-backup, §6.7); when false annotations are dropped (wire form).
 */
export function validateEntryShape(raw: unknown, allowAnnotations: boolean): KindredEntry {
  if (!isRecord(raw)) throw new Error('kenspeckle entry: not an object')
  const tier = raw.tier
  if (tier !== 'kin' && tier !== 'kith' && tier !== 'ken') {
    throw new Error('kenspeckle entry: tier must be kin | kith | ken')
  }

  const pubkey = reqHex64(raw, 'pubkey')
  const ownerPubkey = reqHex64(raw, 'ownerPubkey')
  const addedAt = reqFiniteNumber(raw, 'addedAt')
  const displayName = optString(raw, 'displayName')

  let annotations: PrivateAnnotations | undefined
  if (allowAnnotations && raw.annotations !== undefined) {
    annotations = validateAnnotations(raw.annotations)
  }

  if (tier === 'kin' || tier === 'kith') {
    const sharedSecret = reqHex64(raw, 'sharedSecret')
    const verifiedAt = reqFiniteNumber(raw, 'verifiedAt')

    if (tier === 'kin') {
      const relationship = raw.relationship
      if (typeof relationship !== 'string' || !KIN_RELATIONSHIPS.has(relationship)) {
        throw new Error('kenspeckle kin: relationship invalid')
      }
      const entry: KinEntry = {
        tier: 'kin',
        pubkey,
        ownerPubkey,
        addedAt,
        sharedSecret,
        verifiedAt,
        relationship: relationship as KinEntry['relationship'],
      }
      if (displayName !== undefined) entry.displayName = displayName
      if (annotations !== undefined) entry.annotations = annotations
      return entry
    }

    const entry: KithEntry = { tier: 'kith', pubkey, ownerPubkey, addedAt, sharedSecret, verifiedAt }
    if (displayName !== undefined) entry.displayName = displayName
    if (annotations !== undefined) entry.annotations = annotations
    // bondAssertion is optional metadata; preserve it shallowly if structurally present.
    if (isRecord(raw.bondAssertion)) {
      const ba = raw.bondAssertion
      if (
        typeof ba.mineId === 'string' &&
        typeof ba.relay === 'string' &&
        typeof ba.createdAt === 'number' &&
        Number.isFinite(ba.createdAt)
      ) {
        entry.bondAssertion = {
          mineId: ba.mineId,
          relay: ba.relay,
          createdAt: ba.createdAt,
          ...(typeof ba.theirsId === 'string' ? { theirsId: ba.theirsId } : {}),
        }
      }
    }
    return entry
  }

  // tier === 'ken'
  const provenance = validateProvenance(raw.provenance)
  const entry: KenEntry = { tier: 'ken', pubkey, ownerPubkey, addedAt, provenance }
  if (displayName !== undefined) entry.displayName = displayName
  if (annotations !== undefined) entry.annotations = annotations
  const nip05 = optString(raw, 'nip05')
  if (nip05 !== undefined) entry.nip05 = nip05
  if (raw.lastResolvedAt !== undefined) {
    if (typeof raw.lastResolvedAt !== 'number' || !Number.isFinite(raw.lastResolvedAt)) {
      throw new Error('kenspeckle ken: lastResolvedAt must be a finite number')
    }
    entry.lastResolvedAt = raw.lastResolvedAt
  }
  if (raw.previousPubkeys !== undefined) {
    if (!Array.isArray(raw.previousPubkeys) || !raw.previousPubkeys.every((p) => typeof p === 'string' && HEX64.test(p))) {
      throw new Error('kenspeckle ken: previousPubkeys must be an array of 64-hex strings')
    }
    // Lowercase each element (same equality-safety reason as reqHex64).
    entry.previousPubkeys = (raw.previousPubkeys as string[]).map((p) => p.toLowerCase())
  }
  if (raw.rotation !== undefined) entry.rotation = validateRotation(raw.rotation)
  // Corroborations: additional independent confirmations (§3.2). Each element is validated by the
  // SAME `validateProvenance` used for the primary, so the `source` allow-list is shared — there is
  // exactly one KEN_SOURCES set and corroborations can never widen it. Malformed input THROWS
  // (matching `previousPubkeys` / `rotation`) rather than being silently dropped: a corroboration is
  // evidence, and evidence that fails its guard must not be quietly discarded into a valid-looking
  // entry. An empty array is preserved as-is (same as `previousPubkeys: []`) so parse/serialize
  // round-trips faithfully rather than silently mutating the caller's shape.
  if (raw.corroborations !== undefined) {
    if (!Array.isArray(raw.corroborations)) {
      throw new Error('kenspeckle ken: corroborations must be an array')
    }
    // Bounded, unlike `previousPubkeys`. That precedent is uncapped but its elements are fixed
    // 64-char hex, so its worst case is bounded per element; a corroboration carries an unbounded
    // `locator` string, so an uncapped array is a genuine memory-amplification surface for a
    // restored backup or a synced entry. The cap is far above any real ken (that would be 64
    // separate re-checks of one key) and this is a NEW field, so no stored entry can trip it.
    if (raw.corroborations.length > MAX_CORROBORATIONS) {
      throw new Error(`kenspeckle ken: at most ${MAX_CORROBORATIONS} corroborations`)
    }
    entry.corroborations = raw.corroborations.map(validateProvenance)
  }
  if (raw.revoked !== undefined) {
    if (typeof raw.revoked !== 'boolean') throw new Error('kenspeckle ken: revoked must be a boolean')
    entry.revoked = raw.revoked
  }
  return entry
}

// kindred — shared runtime field guards for untrusted `KindredEntry` input.
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
const KEN_ROTATION_VIA = new Set(['nip05', 'announcement', 'manual'])

function isRecord(v: unknown): v is Record<string, unknown> {
  return v !== null && typeof v === 'object' && !Array.isArray(v)
}

function reqHex64(o: Record<string, unknown>, field: string): string {
  const v = o[field]
  if (typeof v !== 'string' || !HEX64.test(v)) {
    throw new Error(`kindred entry: ${field} must be 64 hex chars`)
  }
  return v
}

function reqFiniteNumber(o: Record<string, unknown>, field: string): number {
  const v = o[field]
  if (typeof v !== 'number' || !Number.isFinite(v)) {
    throw new Error(`kindred entry: ${field} must be a finite number`)
  }
  return v
}

function optString(o: Record<string, unknown>, field: string): string | undefined {
  const v = o[field]
  if (v === undefined) return undefined
  if (typeof v !== 'string') throw new Error(`kindred entry: ${field} must be a string`)
  return v
}

function validateProvenance(v: unknown): KenProvenance {
  if (!isRecord(v)) throw new Error('kindred ken: provenance must be an object')
  const source = v.source
  if (typeof source !== 'string' || !KEN_SOURCES.has(source)) {
    throw new Error('kindred ken: provenance.source invalid')
  }
  if (typeof v.locator !== 'string' || v.locator.length === 0) {
    throw new Error('kindred ken: provenance.locator must be a non-empty string')
  }
  if (typeof v.confirmedAt !== 'number' || !Number.isFinite(v.confirmedAt)) {
    throw new Error('kindred ken: provenance.confirmedAt must be a finite number')
  }
  return { source: source as KenProvenance['source'], locator: v.locator, confirmedAt: v.confirmedAt }
}

function validateRotation(v: unknown): KenRotation {
  if (!isRecord(v)) throw new Error('kindred ken: rotation must be an object')
  if (typeof v.newPubkey !== 'string' || !HEX64.test(v.newPubkey)) {
    throw new Error('kindred ken: rotation.newPubkey must be 64 hex')
  }
  if (typeof v.observedAt !== 'number' || !Number.isFinite(v.observedAt)) {
    throw new Error('kindred ken: rotation.observedAt must be a finite number')
  }
  if (typeof v.via !== 'string' || !KEN_ROTATION_VIA.has(v.via)) {
    throw new Error('kindred ken: rotation.via invalid')
  }
  if (typeof v.accepted !== 'boolean') {
    throw new Error('kindred ken: rotation.accepted must be a boolean')
  }
  const out: KenRotation = {
    newPubkey: v.newPubkey,
    observedAt: v.observedAt,
    via: v.via as KenRotation['via'],
    accepted: v.accepted,
  }
  if (v.announcementEventId !== undefined) {
    if (typeof v.announcementEventId !== 'string') {
      throw new Error('kindred ken: rotation.announcementEventId must be a string')
    }
    out.announcementEventId = v.announcementEventId
  }
  return out
}

function validateAnnotations(v: unknown): PrivateAnnotations {
  if (!isRecord(v)) throw new Error('kindred entry: annotations must be an object')
  const out: PrivateAnnotations = {}
  if (v.groupId !== undefined) {
    if (typeof v.groupId !== 'string') throw new Error('kindred entry: annotations.groupId must be a string')
    out.groupId = v.groupId
  }
  if (v.label !== undefined) {
    if (typeof v.label !== 'string') throw new Error('kindred entry: annotations.label must be a string')
    out.label = v.label
  }
  if (v.note !== undefined) {
    if (typeof v.note !== 'string') throw new Error('kindred entry: annotations.note must be a string')
    out.note = v.note
  }
  if (v.blocked !== undefined) {
    if (typeof v.blocked !== 'boolean') throw new Error('kindred entry: annotations.blocked must be a boolean')
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
  if (!isRecord(raw)) throw new Error('kindred entry: not an object')
  const tier = raw.tier
  if (tier !== 'kin' && tier !== 'kith' && tier !== 'ken') {
    throw new Error('kindred entry: tier must be kin | kith | ken')
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
        throw new Error('kindred kin: relationship invalid')
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
      throw new Error('kindred ken: lastResolvedAt must be a finite number')
    }
    entry.lastResolvedAt = raw.lastResolvedAt
  }
  if (raw.previousPubkeys !== undefined) {
    if (!Array.isArray(raw.previousPubkeys) || !raw.previousPubkeys.every((p) => typeof p === 'string' && HEX64.test(p))) {
      throw new Error('kindred ken: previousPubkeys must be an array of 64-hex strings')
    }
    entry.previousPubkeys = raw.previousPubkeys as string[]
  }
  if (raw.rotation !== undefined) entry.rotation = validateRotation(raw.rotation)
  if (raw.revoked !== undefined) {
    if (typeof raw.revoked !== 'boolean') throw new Error('kindred ken: revoked must be a boolean')
    entry.revoked = raw.revoked
  }
  return entry
}

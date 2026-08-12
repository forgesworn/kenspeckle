// kenspeckle — `.` surface local relationship operations (spec §4, §12.1).
//
// Pure functions over plain `KindredEntry` data. No storage, no UI, no graph traversal.
//
// The load-bearing privacy invariant (spec §4): `PrivateAnnotations` are LOCAL-ONLY. They are
// searchable in-memory (`searchEntries`) but MUST NEVER be serialised onto any wire. `toWire`
// strips them structurally and `serializeEntry` is built on top of `toWire`, so the canonical
// JSON can never carry an `annotations` key. The encrypted self-backup (`backup.ts`) is the one
// exception — it INCLUDES annotations because it is the user's own AES-sealed copy (§6.7), not a
// graph disclosure.

import { randomBytes } from '@noble/ciphers/utils.js'
import { bytesToHex } from '@noble/hashes/utils.js'
import type {
  KindredEntry,
  KinEntry,
  KithEntry,
  KenEntry,
  PrivateAnnotations,
  WireEntry,
} from './types.js'
import { validateEntryShape } from './validate.js'

// --- persona scoping (spec §4) ---------------------------------------------------------------

/** Re-attach a persona pubkey as the entry owner. The input omits `ownerPubkey`; we stamp it on
 *  and return the value typed as the correct `KindredEntry` union member (tier preserved). */
export function scopeToPersona(
  entry: Omit<KindredEntry, 'ownerPubkey'>,
  personaPubkeyHex: string,
): KindredEntry {
  // The spread re-introduces the only missing discriminant-independent field. Because `entry` is a
  // distributed `Omit` over the union, `{...entry, ownerPubkey}` is assignable back to the union.
  return { ...entry, ownerPubkey: personaPubkeyHex } as KindredEntry
}

/** Throw unless `personaPubkeyHex` is one of MY persona leaves (case-insensitive membership).
 *  Consumer supplies `myLeaves` (hex) from nsec-tree — kenspeckle makes no runtime nsec-tree call. */
export function assertOwnedPersona(personaPubkeyHex: string, myLeaves: string[]): void {
  const needle = personaPubkeyHex.toLowerCase()
  if (!myLeaves.some((l) => l.toLowerCase() === needle)) {
    throw new Error('persona not owned')
  }
}

// --- local search (spec §4 — annotations searchable LOCALLY) ---------------------------------

/** Case-insensitive search over `displayName`, `pubkey` (prefix or substring), and the LOCAL
 *  annotations `label`/`note`. Annotations ARE searchable here — they are simply never serialised.
 *  An empty/whitespace-only query returns all entries (the input list, filtered by nothing). */
export function searchEntries(entries: KindredEntry[], query: string): KindredEntry[] {
  const q = query.trim().toLowerCase()
  if (q === '') return entries.slice()
  return entries.filter((e) => {
    if (e.displayName && e.displayName.toLowerCase().includes(q)) return true
    if (e.pubkey.toLowerCase().includes(q)) return true // covers prefix and substring
    const a = e.annotations
    if (a?.label && a.label.toLowerCase().includes(q)) return true
    if (a?.note && a.note.toLowerCase().includes(q)) return true
    return false
  })
}

// --- private recall grouping (spec §4) -------------------------------------------------------

/** Generate a fresh `groupId` and stamp it onto `annotations.groupId` of every entry whose
 *  `pubkey ∈ ids` (creating the `annotations` object if absent, preserving any existing fields).
 *  MUTATES `entries` IN PLACE and returns the new groupId. */
export function linkForRecall(entries: KindredEntry[], ids: string[]): string {
  const groupId = bytesToHex(randomBytes(8))
  const wanted = new Set(ids.map((i) => i.toLowerCase()))
  for (const e of entries) {
    if (wanted.has(e.pubkey.toLowerCase())) {
      const next: PrivateAnnotations = { ...(e.annotations ?? {}), groupId }
      e.annotations = next
    }
  }
  return groupId
}

/** Clear the matching entry's `annotations.groupId` (leaving its other annotation fields intact).
 *  MUTATES `entries` IN PLACE. No-op if the pubkey isn't present or had no group. */
export function unlink(entries: KindredEntry[], pubkey: string): void {
  const needle = pubkey.toLowerCase()
  for (const e of entries) {
    if (e.pubkey.toLowerCase() === needle && e.annotations && 'groupId' in e.annotations) {
      const { groupId: _drop, ...rest } = e.annotations
      e.annotations = rest
    }
  }
}

// --- wire form + canonical serialization (spec §4, §12.1) ------------------------------------

/** Shallow copy with `annotations` structurally removed. Typed `WireEntry`. */
export function toWire(e: KindredEntry): WireEntry {
  const { annotations: _drop, ...wire } = e
  return wire
}

/** Recursively sort object keys so two devices serialise identical bytes (cross-device sync,
 *  §12.1). Only emits keys that are present (an absent `annotations` never appears). Arrays keep
 *  order (element order is meaningful); plain objects get lexicographically-sorted keys. */
function stableSort(value: unknown): unknown {
  if (Array.isArray(value)) return value.map(stableSort)
  if (value !== null && typeof value === 'object') {
    const obj = value as Record<string, unknown>
    const out: Record<string, unknown> = {}
    for (const k of Object.keys(obj).sort()) {
      // Drop `undefined` so absent optionals never materialise as keys (byte-stability).
      if (obj[k] !== undefined) out[k] = stableSort(obj[k])
    }
    return out
  }
  return value
}

/** Canonical, byte-stable JSON of `toWire(e)` with recursively-sorted keys. The output NEVER
 *  contains an `annotations` key — `toWire` strips it AND `stableSort` only emits present keys. */
export function serializeEntry(e: KindredEntry): string {
  return JSON.stringify(stableSort(toWire(e)))
}

/** Parse untrusted wire JSON into a typed `KindredEntry`, running full field guards (signet-app
 *  untrusted-input discipline). Does NOT restore annotations — wire form never carried them. */
export function parseEntry(s: string): KindredEntry {
  let raw: unknown
  try {
    raw = JSON.parse(s)
  } catch {
    throw new Error('parseEntry: not valid JSON')
  }
  return validateEntryShape(raw, false)
}

// Re-exported so backup.ts can import a single union narrowing without a cycle through model.
export type { KinEntry, KithEntry, KenEntry }

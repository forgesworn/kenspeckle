// kenspeckle — `.` surface local relationship operations (spec §4, §12.1).
//
// Pure functions over plain `KindredEntry` data. No storage, no UI, no graph traversal.
//
// TWO privacy invariants, not one:
//   • `PrivateAnnotations` are LOCAL-ONLY (spec §4). They are searchable in-memory
//     (`searchEntries`) but MUST NEVER be serialised onto any wire or sync form.
//   • `sharedSecret` (the ECDH bond/kin secret) MUST NEVER be published (README Security,
//     types.ts `MutualEntry`) — but it DOES need to travel between the user's OWN devices, or a
//     restored kin/kith contact is useless there. These are different destinations with different
//     trust boundaries, so they get different functions (H4 audit finding — the previous
//     `toWire`/`WireEntry` excluded only `annotations`, so code trusting the "wire-safe" name could
//     leak the secret to a relay/contact-sync event):
//     - `toWire` / `serializeEntry` / `parseEntry` — TRUE wire-safe: strip BOTH `annotations` AND
//       `sharedSecret`. Safe to hand to any third party. A kin/kith `WireEntry` therefore cannot be
//       round-tripped back into a functioning entry via `parseEntry` (it is missing a field
//       `validateEntryShape` requires) — that is intentional, not a bug: the secret's absence means
//       there is nothing to reconstruct.
//     - `toSyncForm` / `serializeEntryForSync` — KEEPS `sharedSecret` (still strips `annotations`).
//       For the ONE legitimate case that needs the secret to travel: syncing a roster across the
//       user's own devices over an already-private/authenticated transport. NEVER publish this
//       output, and never hand it to anything that isn't another one of the user's own devices.
//       `parseEntry` reconstructs this form (it requires `sharedSecret` for kin/kith either way).
//
// The encrypted self-backup (`backup.ts`) bypasses this module entirely — it JSON-serialises raw
// entries (including annotations AND sharedSecret) straight into its AES-sealed blob (§6.7), so no
// separate "backup" wire function is needed here.

import { randomBytes } from '@noble/ciphers/utils.js'
import { bytesToHex } from '@noble/hashes/utils.js'
import type {
  KindredEntry,
  KinEntry,
  KithEntry,
  KenEntry,
  PrivateAnnotations,
  WireEntry,
  SyncEntry,
  DistributiveOmit,
} from './types.js'
import { validateEntryShape } from './validate.js'

// --- persona scoping (spec §4) ---------------------------------------------------------------

/** Re-attach a persona pubkey as the entry owner. The input omits `ownerPubkey`; we stamp it on
 *  and return the value typed as the correct `KindredEntry` union member (tier preserved). */
export function scopeToPersona(
  entry: DistributiveOmit<KindredEntry, 'ownerPubkey'>,
  personaPubkeyHex: string,
): KindredEntry {
  // The spread re-introduces the only missing discriminant-independent field. `entry` is a
  // genuinely DISTRIBUTED `Omit` over the union (see `DistributiveOmit` in types.ts — a bare
  // `Omit<Union, K>` is NOT distributive and silently drops tier-specific fields; M7 audit finding),
  // so `{...entry, ownerPubkey}` is directly assignable back to the union with no cast.
  return { ...entry, ownerPubkey: personaPubkeyHex }
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

/** Shallow copy with `annotations` AND `sharedSecret` structurally removed. Typed `WireEntry`.
 *  Safe to hand to any third party (H4 audit finding — see the module note above). A `KenEntry` has
 *  no `sharedSecret` to begin with, so `delete` on that tier is a no-op. */
export function toWire(e: KindredEntry): WireEntry {
  const { annotations: _drop, ...rest } = e
  const wire = rest as Record<string, unknown>
  delete wire.sharedSecret
  return wire as unknown as WireEntry
}

/** Shallow copy with only `annotations` structurally removed — `sharedSecret` is PRESERVED. Typed
 *  `SyncEntry`. MUST only be transmitted over a channel already private to the user's own devices
 *  (e.g. an encrypted device-sync transport). NEVER publish this output, and never hand it to
 *  anything other than another one of the user's own devices — see the module note above. */
export function toSyncForm(e: KindredEntry): SyncEntry {
  const { annotations: _drop, ...sync } = e
  return sync
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
 *  contains an `annotations` OR a `sharedSecret` key — `toWire` strips both AND `stableSort` only
 *  emits present keys. Safe to hand to any third party. For kin/kith, this output is deliberately
 *  NOT a full round-trip: `parseEntry` requires `sharedSecret` for those tiers, so re-parsing a
 *  wire-form kin/kith throws (there is nothing to reconstruct without the secret) — see
 *  `serializeEntryForSync` for the form that does round-trip. */
export function serializeEntry(e: KindredEntry): string {
  return JSON.stringify(stableSort(toWire(e)))
}

/** Canonical, byte-stable JSON of `toSyncForm(e)` with recursively-sorted keys — KEEPS
 *  `sharedSecret`. The output NEVER contains an `annotations` key. MUST only be transmitted over a
 *  channel already private to the user's own devices; `parseEntry` reconstructs this form (it
 *  requires `sharedSecret` for kin/kith regardless of which serializer produced its input). */
export function serializeEntryForSync(e: KindredEntry): string {
  return JSON.stringify(stableSort(toSyncForm(e)))
}

/** Parse untrusted JSON into a typed `KindredEntry`, running full field guards (signet-app
 *  untrusted-input discipline). Does NOT restore annotations — neither serialised form carries
 *  them. Reconstructs `serializeEntryForSync`'s output; a kin/kith `serializeEntry` (true wire form)
 *  input throws here, because `sharedSecret` is required for those tiers and the wire form omits it
 *  by design (see the module note above). */
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

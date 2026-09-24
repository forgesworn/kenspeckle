// kenspeckle (main export) — relationship model types.
// Source of truth: signet-plans/docs/plans/2026-06-02-kenspeckle-primitive-spec.md §3.2.

import type { EventTemplate, Event as NostrEvent, Filter as NostrFilter } from 'nostr-tools'

/** Canonical tier order — closest → furthest: kin (family), kith (mutually verified), ken (one-way recognised). */
export type KindredTier = 'kin' | 'kith' | 'ken'

/** Annotations that MUST NEVER reach any wire/serialise function. Structurally separate
 *  so "never published" is enforced by the type system, not a code comment. */
export interface PrivateAnnotations {
  /** Private grouping: link several pubkeys you believe are one human, for YOUR recall only. */
  groupId?: string
  label?: string
  note?: string
  blocked?: boolean
}

export interface KindredEntryBase {
  pubkey: string                 // their pubkey (hex, 64)
  ownerPubkey: string            // ONE of MY persona pubkeys (hex) — mandatory, anti-correlation
  tier: KindredTier
  displayName?: string           // optional: a ken from a bare pubkey may have no name
  addedAt: number                // unix seconds
  /** Local-only annotations. Never serialised by any `build*` / `serialize*` function (§4, §7). */
  annotations?: PrivateAnnotations
}

/** Shared base for the two mutual tiers (collapses the v1 KinEntry/KithEntry duplication). */
export interface MutualEntry extends KindredEntryBase {
  sharedSecret: string           // ECDH secret (hex). Encrypted at rest by the consumer. NEVER published.
  verifiedAt: number
}

export interface KinEntry extends MutualEntry {
  tier: 'kin'
  relationship: 'parent' | 'child' | 'sibling' | 'grandparent' | 'partner' | 'guardian' | 'dependant' | 'other'
}

export interface KithEntry extends MutualEntry {
  tier: 'kith'
  bondAssertion?: BondAssertion  // optional, consensual, co-signed (§5.5)
}

export interface KenEntry extends KindredEntryBase {
  tier: 'ken'
  provenance: KenProvenance
  /** ADDITIONAL independent channels that agree this key belongs to this person.
   *
   *  `provenance` above remains the REQUIRED, SINGULAR primary — every pre-existing reader keeps
   *  working untouched. This list is purely additive: it lets "verified in person AND matches their
   *  domain" be expressed instead of silently discarding all but one source.
   *
   *  WHY this matters: as appearance-based identity (name, face, voice, writing) becomes cheap to
   *  forge, the durable defence is not a better single channel — it is SEVERAL INDEPENDENT channels
   *  agreeing, because that is what survives any one channel being compromised. Reuses
   *  `KenProvenance` verbatim, so no new `source` values are introduced (see validate.ts). */
  corroborations?: KenProvenance[]
  nip05?: string
  lastResolvedAt?: number
  /** Current pinned key is `pubkey`. History preserves audit + lets attributeSignature reject old keys. */
  previousPubkeys?: string[]
  rotation?: KenRotation
  /** Set when the figure announced key compromise with no successor — pin is dead, attribution must fail. */
  revoked?: boolean
}

export interface KenProvenance {
  source: 'nip05' | 'dns' | 'web' | 'social-channel' | 'in-person' | 'manual'
  locator: string
  confirmedAt: number
}

/** RESERVED locator prefix: a provenance whose `locator` starts with this was CLAIMED by a
 *  companion app and relayed, not confirmed first-hand. `landReturnedKen` is the only thing in
 *  kenspeckle that mints one, and no first-party flow may mint a locator in this namespace — that
 *  reservation is what lets `summarizeKenProvenance` report how much of a ken's apparent
 *  corroboration is merely relayed claim (spec §6.5, companion rail design §10.3). */
export const COMPANION_LOCATOR_PREFIX = 'companion:'

export interface KenRotation {
  newPubkey: string
  observedAt: number
  via: 'nip05' | 'announcement' | 'manual'
  /** old-key-signed proof, when available */
  announcementEventId?: string
  accepted: boolean
  /** Set when `newPubkey` is already in `previousPubkeys` — NIP-05 (or another `via`) is proposing a
   *  ROLLBACK to a key that was rotated away from, not a forward rotation. This is the exact shape of
   *  a compromised-domain replay (the domain operator re-serves an old, possibly-compromised key).
   *  `resolveKen` sets this; `acceptKenRotation` refuses to accept it unless the caller passes
   *  `{ allowRevert: true }` (H3 audit finding). */
  rollback?: boolean
}

/** Optional, consensual, co-signed bond assertion record (§5.5). Defined in ./bond at runtime;
 *  the shape lives here so KithEntry can reference it without a cycle. */
export interface BondAssertion {
  mineId: string
  theirsId?: string
  relay: string
  createdAt: number
}

export type KindredEntry = KinEntry | KithEntry | KenEntry

// --- K-1 additions (plan §K-1 Step 2) ---

// Canonical nostr event/filter types — kenspeckle re-exports these aliases so consumers have ONE event type.
export type { EventTemplate, NostrEvent, NostrFilter }

/** Distributive `Omit`: applies `Omit` to EACH member of a union separately, instead of collapsing
 *  the union first. A bare `Omit<Union, K>` is NOT distributive — TS resolves `keyof Union` to the
 *  INTERSECTION of each member's keys before omitting, so any field that isn't common to every arm
 *  (e.g. `sharedSecret` on `KinEntry`/`KithEntry` but not `KenEntry`, or `provenance`/`relationship`)
 *  silently vanishes from the result type, and narrowing on `tier` can no longer see it (H4/M7 audit
 *  finding). Distributing over `T extends unknown` forces TS to apply `Omit` to each arm before
 *  re-uniting them, so tier-specific fields stay visible after a `tier` narrow. */
export type DistributiveOmit<T, K extends PropertyKey> = T extends unknown ? Omit<T, K> : never

/** Wire-safe view: `PrivateAnnotations` AND `sharedSecret` structurally removed. Annotations are
 *  never serialised (spec §4). `sharedSecret` is the ECDH bond/kin secret and must NEVER be
 *  published (README Security, this file's `MutualEntry` doc) — `toWire`/`serializeEntry` strip it
 *  (H4 audit finding: the previous `WireEntry` only excluded `annotations`, so code following the
 *  "wire-safe" name could leak the secret). For the ONE legitimate case that needs the secret to
 *  travel — syncing a roster across the user's OWN devices over an already-private/authenticated
 *  channel — use `SyncEntry` / `toSyncForm` / `serializeEntryForSync` instead, never this. */
export type WireEntry = DistributiveOmit<KindredEntry, 'annotations' | 'sharedSecret'>

/** Sync-safe view: only `PrivateAnnotations` removed (the pre-H4 `WireEntry` shape). `sharedSecret`
 *  IS present — this form MUST only travel over a channel already private to the user's own devices
 *  (e.g. an encrypted device-sync transport), never to a relay, a contact, or any third party. See
 *  `toSyncForm` / `serializeEntryForSync` in `./model`. */
export type SyncEntry = DistributiveOmit<KindredEntry, 'annotations'>

// Compile-time invariants. These live in a COMPILED source file, not a *.test.ts: the house tsconfig
// excludes `**/*.test.ts`, and vitest transpiles tests with esbuild (no type-checking), so a
// `@ts-expect-error` placed in a test would be inert — a false green. Asserting them here makes
// `npm run typecheck` and `npm run build` the real gate, and they emit no runtime JS.
type _Assert<T extends true> = T

// `annotations` is common to every union arm (declared on `KindredEntryBase`), so a bare
// `keyof WireEntry` check is sufficient: if `WireEntry` ever re-admits `annotations`,
// `_WireExcludesAnnotations` resolves to `false` and the `extends true` constraint below fails
// (TS2344).
type _WireExcludesAnnotations = 'annotations' extends keyof WireEntry ? false : true
type _WireAnnotationsExclusionCheck = _Assert<_WireExcludesAnnotations>

// `sharedSecret` is declared only on `MutualEntry` (kin/kith), NOT on `KenEntry` — so it was NEVER
// part of `keyof (KinEntry | KithEntry | KenEntry)` in the first place (`keyof` of a union is the
// INTERSECTION of each member's keys). A bare `keyof WireEntry` check would therefore pass trivially
// even if `sharedSecret` leaked through on the kin/kith arms — exactly the M7 unsoundness this file
// now fixes. So this checks the MUTUAL arms directly via `Extract`.
type _KithWireExcludesSharedSecret = 'sharedSecret' extends keyof Extract<WireEntry, { tier: 'kith' }>
  ? false
  : true
type _KithWireSharedSecretExclusionCheck = _Assert<_KithWireExcludesSharedSecret>
type _KinWireExcludesSharedSecret = 'sharedSecret' extends keyof Extract<WireEntry, { tier: 'kin' }>
  ? false
  : true
type _KinWireSharedSecretExclusionCheck = _Assert<_KinWireExcludesSharedSecret>

// Distributivity regression test (the actual M7 bug): after narrowing `WireEntry` to one tier, the
// tier-specific fields that a non-distributive `Omit` would have dropped MUST still be visible.
type _KithWireHasVerifiedAt = 'verifiedAt' extends keyof Extract<WireEntry, { tier: 'kith' }>
  ? true
  : false
type _KithWireVerifiedAtCheck = _Assert<_KithWireHasVerifiedAt>
type _KenWireHasProvenance = 'provenance' extends keyof Extract<WireEntry, { tier: 'ken' }>
  ? true
  : false
type _KenWireProvenanceCheck = _Assert<_KenWireHasProvenance>
type _KinWireHasRelationship = 'relationship' extends keyof Extract<WireEntry, { tier: 'kin' }>
  ? true
  : false
type _KinWireRelationshipCheck = _Assert<_KinWireHasRelationship>

// `SyncEntry` keeps `sharedSecret` on the mutual arms (only `annotations` is stripped).
type _KithSyncHasSharedSecret = 'sharedSecret' extends keyof Extract<SyncEntry, { tier: 'kith' }>
  ? true
  : false
type _KithSyncSharedSecretCheck = _Assert<_KithSyncHasSharedSecret>
type _SyncExcludesAnnotations = 'annotations' extends keyof SyncEntry ? false : true
type _SyncAnnotationsExclusionCheck = _Assert<_SyncExcludesAnnotations>

/** Type predicate: can this entry run the spoken-token ceremony? (kin/kith carry a shared secret; ken does not.)
 *
 *  Spec §3.2 writes this as `e is MutualEntry`, but a bare `MutualEntry` is NOT assignable to the
 *  `KindredEntry` union (its `tier: KindredTier` is wider than the `'kin'`/`'kith'` literals on the
 *  union arms — TS2677). The type-sound narrowing target that preserves the same semantic is the
 *  union's two mutual arms `KinEntry | KithEntry`, both of which extend `MutualEntry` — so callers
 *  still get `.sharedSecret`/`.verifiedAt` and an assignment to `MutualEntry` holds. Raised against
 *  the spec; resolved here without changing the predicate's name or meaning. */
export function hasSharedSecret(e: KindredEntry): e is KinEntry | KithEntry {
  return 'sharedSecret' in e
}

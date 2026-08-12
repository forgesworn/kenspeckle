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

/** Wire-safe view: PrivateAnnotations structurally removed (spec §4 — never serialised). */
export type WireEntry = Omit<KindredEntry, 'annotations'>

// Compile-time invariant (spec §4 — annotations never on a wire). This lives in a COMPILED source
// file, not a *.test.ts: the house tsconfig excludes `**/*.test.ts`, and vitest transpiles tests
// with esbuild (no type-checking), so a `@ts-expect-error` placed in a test would be inert — a false
// green. Asserting it here makes `npm run typecheck` and `npm run build` the real gate, and emits no
// runtime JS. If WireEntry ever re-admits `annotations`, `_WireExcludesAnnotations` resolves to
// `false`, `_Assert<false>` violates its `extends true` constraint, and the build fails (TS2344).
type _Assert<T extends true> = T
type _WireExcludesAnnotations = 'annotations' extends keyof WireEntry ? false : true
// Evaluated at its declaration site (no export needed → stays out of the public .d.ts surface):
// if the conditional above resolves to `false`, `_Assert<false>` breaks its `extends true` constraint.
type _WireAnnotationsExclusionCheck = _Assert<_WireExcludesAnnotations>

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

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
//
// ── L9 AUDIT FINDING — "kith" IS NOT PROOF A BOND HAPPENED ──────────────────────────────────────
// This module can only check SHAPE, never PROVENANCE: `validateEntryShape` accepts any
// `tier:'kith'` object carrying a syntactically-valid 64-hex `sharedSecret` and `verifiedAt` — it
// has no way to confirm that secret actually came from a real `deriveBondSecret` ceremony between
// two consenting parties. `bondAssertion` is OPTIONAL METADATA (a co-signed record, when present),
// never REQUIRED, so its absence proves nothing either way.
// CONSEQUENCE: an unauthenticated sync/import channel — anything that can hand `parseEntry` or
// `importEntries` a crafted object — can escalate a mere `ken` (one-way recognition, no secret) into
// a `kith` (implies MUTUAL, out-of-band-verified trust) by fabricating a random 64-hex string as
// `sharedSecret`. kenspeckle has no storage and cannot itself authenticate a sync source, so THE
// CONSUMER MUST authenticate/encrypt whatever channel feeds `parseEntry`/`importEntries` — this
// module's validation is a SHAPE gate, not a trust boundary. (A structural `promoteKenToKith` /
// merge helper that makes escalation possible only through a real ceremony artefact is tracked as a
// follow-up, not implemented here.)

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

// --- NIP-05 strict validation (M1 audit finding) ----------------------------------------------
//
// `resolveNip05` (./ken) interpolates the `domain` half of a `nip05` field DIRECTLY into a fetch
// URL. A permissive shape check (just "one `@`, allowed local chars") lets a domain half carry a
// port, userinfo, a path/query/fragment, or a bare IP literal — turning `resolveKen` into an
// arbitrary-URL fetch for whoever can get a `nip05` field into an entry (sync, a backup file, a
// future rail). This is the SINGLE source of truth for the strict shape; every entry point that can
// reach `resolveNip05` (`pinKen`, `pinKenFromNip05`, `resolveKen`, and `resolveNip05` itself as the
// last-line choke point) validates through `validateNip05`. Parse/import only type-check `nip05`, so
// a value 0.1.x stored still restores; `resolveKen` treats one that fails here as unresolvable.
const NIP05_LOCAL = /^[a-z0-9\-_.]+$/i
// RFC-1035-shaped DNS label: alnum, optional interior hyphens, no leading/trailing hyphen.
const DOMAIN_LABEL = '[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?'
// At least two labels (rejects a bare single-label host like `localhost` as a side effect).
const DOMAIN_RE = new RegExp(`^${DOMAIN_LABEL}(?:\\.${DOMAIN_LABEL})+$`, 'i')
// The last label (the TLD) must be letters only (2–63) or a punycode `xn--` label. This is what
// rejects IPv4 in EVERY spelling the WHATWG URL parser accepts — dotted-quad, the shorthand forms
// (`127.1`, `10.1`, `192.168.1`), octal (`0177.0.0.1`) and hex (`0x7f.1`) — since the URL parser
// treats a host whose last label is numeric as an IPv4 address and would otherwise turn
// `x@127.1` into a fetch of 127.0.0.1.
const TLD_RE = /^(?:[a-z]{2,63}|xn--[a-z0-9-]{1,59})$/i

/**
 * Validate a strict NIP-05 `local@domain` shape and return it unchanged.
 *
 * Exactly one `@`; the local part matches NIP-05's allowed characters; the domain is DNS-hostname
 * shaped ONLY — at least two labels, no port, no userinfo, no path/query/fragment, and a last label
 * that is alphabetic (2–63 letters) or punycode (`xn--…`). That rules out an IPv4 literal in any
 * form, including shorthand such as `127.1` or `0x7f.1` (a NIP-05 domain names a host, not a
 * network endpoint); an IPv6 literal is already rejected by the charset — `[`/`]`/`:` are not
 * DNS-label characters.
 *
 * @throws with `field` named in the message, for a non-string or malformed value.
 */
export function validateNip05(v: unknown, field = 'nip05'): string {
  if (typeof v !== 'string') {
    throw new Error(`kenspeckle: ${field} must be a string`)
  }
  const at = v.indexOf('@')
  if (at <= 0 || at !== v.lastIndexOf('@') || at === v.length - 1) {
    throw new Error(`kenspeckle: ${field} must be of the form local@domain`)
  }
  const local = v.slice(0, at)
  const domain = v.slice(at + 1)
  if (!NIP05_LOCAL.test(local)) {
    throw new Error(`kenspeckle: ${field} local part is invalid`)
  }
  if (!DOMAIN_RE.test(domain) || !TLD_RE.test(domain.slice(domain.lastIndexOf('.') + 1))) {
    throw new Error(
      `kenspeckle: ${field} domain must be a plain hostname (no port, credentials, path, or IP literal)`,
    )
  }
  return v
}

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

// --- length caps (L8 audit finding) -------------------------------------------------------------
//
// `displayName` and `provenance.locator` had no upper bound. The caps are enforced on the paths
// that CREATE or MUTATE an entry (`pinKen`/`addCorroboration` in ./ken, `landReturnedKen` in
// ./companion-rail), NOT on parse/import: an entry 0.1.x wrote with a longer string must still
// restore, because `importEntries` is all-or-nothing and one over-length field would lose the whole
// backup. Every cap is measured in Unicode CODE POINTS — one unit everywhere — so a builder that
// slices by code point can never mint a value a UTF-16 `.length` check would call over-length.
export const MAX_DISPLAY_NAME_LEN = 256
export const MAX_LOCATOR_LEN = 1024

/** Length of `s` in Unicode code points (a surrogate pair counts once). */
export function codePointLength(s: string): number {
  let n = 0
  for (const _ of s) n++
  return n
}

/**
 * Enforce `MAX_LOCATOR_LEN` (code points) on an already-`validateProvenance`d provenance and return
 * it unchanged.
 *
 * Deliberately NOT folded into `validateProvenance` itself: `validateProvenance` is also the
 * canonical structural check `./companion-rail`'s `landReturnedKen` runs on a RAW claimed locator
 * BEFORE it truncates that locator to `RETURN_LOCATOR_MAX` (512) and namespaces it under
 * `companion:<appName>:`. Capping length inside `validateProvenance` would reject a legitimately
 * over-length raw claim before that module ever got to truncate it. This wrapper is applied only on
 * creation paths (`pinKen`/`addCorroboration` in ./ken, the final locators `landReturnedKen` emits),
 * where the locator is final and nothing downstream is going to shorten it.
 */
export function capLocator(p: KenProvenance): KenProvenance {
  if (codePointLength(p.locator) > MAX_LOCATOR_LEN) {
    throw new Error(`kenspeckle ken: provenance.locator exceeds ${MAX_LOCATOR_LEN} code points`)
  }
  return p
}

/** Enforce `MAX_DISPLAY_NAME_LEN` (code points) on a creation path and return the value unchanged. */
export function capDisplayName<T extends string | undefined>(v: T): T {
  if (v !== undefined && (typeof v !== 'string' || codePointLength(v) > MAX_DISPLAY_NAME_LEN)) {
    throw new Error(`kenspeckle: displayName must be a string of at most ${MAX_DISPLAY_NAME_LEN} code points`)
  }
  return v
}

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
  // NOTE: no upper-bound length check here — see `capLocator`'s doc comment for why the cap is
  // applied by CALLERS (this function is also `./companion-rail`'s pre-truncation structural check).
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
  if (v.rollback !== undefined) {
    if (typeof v.rollback !== 'boolean') {
      throw new Error('kenspeckle ken: rotation.rollback must be a boolean')
    }
    out.rollback = v.rollback
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
  // L8 audit finding: a self-referential entry (recognising your OWN persona pubkey as a contact)
  // is never a valid relationship record and was previously silently accepted.
  if (pubkey === ownerPubkey) {
    throw new Error('kenspeckle entry: pubkey must not equal ownerPubkey')
  }
  const addedAt = reqFiniteNumber(raw, 'addedAt')
  // No length cap here — see "length caps" above: caps apply on creation paths, not parse/import.
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
    // bondAssertion is optional metadata; preserve it shallowly if structurally valid, and DROP it
    // (keeping the entry) if it is malformed — the 0.1.x behaviour, kept so a backup 0.1.x wrote
    // still restores. Dropping is safe: `bondAssertion` is never required and its absence proves
    // nothing (see the L9 note at the top of this file). A non-string `theirsId` is dropped on its
    // own, also as 0.1.x did.
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
  // No locator length cap on parse — see "length caps" above.
  const provenance = validateProvenance(raw.provenance)
  const entry: KenEntry = { tier: 'ken', pubkey, ownerPubkey, addedAt, provenance }
  if (displayName !== undefined) entry.displayName = displayName
  if (annotations !== undefined) entry.annotations = annotations
  // `nip05` is only type-checked here, NOT strictly validated: 0.1.x accepted permissive values
  // (e.g. `x@localhost`) and an entry carrying one must still restore. The SSRF guard (M1 audit
  // finding) lives where the value is USED: `resolveKen` treats a nip05 that fails `validateNip05`
  // as unresolvable and never fetches, and `resolveNip05` re-validates as the last-line choke point.
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
    // Lowercase each element (same equality-safety reason as reqHex64), then NORMALISE: drop the
    // current pin and de-duplicate (first occurrence wins, so audit order is kept). H3 invariant:
    // the CURRENT pin must never also sit in its own rotation history, or `attributeSignature`
    // would reject the legitimate current key as `'rotated-away-key'` (that check runs before the
    // current-pin check). 0.1.x's double-accept bug (H2) wrote exactly that state, so parse
    // repairs it rather than rejecting the entry and, with it, the whole backup.
    const previousPubkeys: string[] = []
    for (const p of raw.previousPubkeys as string[]) {
      const key = p.toLowerCase()
      if (key !== pubkey && !previousPubkeys.includes(key)) previousPubkeys.push(key)
    }
    entry.previousPubkeys = previousPubkeys
  }
  if (raw.rotation !== undefined) {
    entry.rotation = validateRotation(raw.rotation)
    // L8 audit finding: a degenerate self-rotation (a PENDING proposal of the CURRENT pin as its own
    // successor) is rejected. An ACCEPTED rotation is the opposite case: `acceptKenRotation` sets
    // `pubkey = rotation.newPubkey` and keeps the record with `accepted: true`, so equality there is
    // the normal post-accept state and must round-trip. The double-accept guard in
    // `acceptKenRotation` (H2) still refuses to accept it again.
    if (!entry.rotation.accepted && entry.rotation.newPubkey === pubkey) {
      throw new Error('kenspeckle ken: rotation.newPubkey must not equal the current pubkey')
    }
  }
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
    entry.corroborations = raw.corroborations.map((c) => validateProvenance(c))
  }
  if (raw.revoked !== undefined) {
    if (typeof raw.revoked !== 'boolean') throw new Error('kenspeckle ken: revoked must be a boolean')
    entry.revoked = raw.revoked
  }
  return entry
}

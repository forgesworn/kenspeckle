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
// reach `resolveNip05` (parse, `pinKen`, `pinKenFromNip05`, and `resolveNip05` itself as the
// last-line choke point) validates through `validateNip05`.
const NIP05_LOCAL = /^[a-z0-9\-_.]+$/i
// RFC-1035-shaped DNS label: alnum, optional interior hyphens, no leading/trailing hyphen.
const DOMAIN_LABEL = '[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?'
// At least two labels (rejects a bare single-label host like `localhost` as a side effect).
const DOMAIN_RE = new RegExp(`^${DOMAIN_LABEL}(?:\\.${DOMAIN_LABEL})+$`, 'i')
const IPV4_LITERAL = /^\d{1,3}(?:\.\d{1,3}){3}$/

/**
 * Validate a strict NIP-05 `local@domain` shape and return it unchanged.
 *
 * Exactly one `@`; the local part matches NIP-05's allowed characters; the domain is DNS-hostname
 * shaped ONLY — no port, no userinfo, no path/query/fragment, and not a bare IPv4 literal (a NIP-05
 * domain names a host, not a network endpoint; an IPv6 literal is already rejected by the charset —
 * `[`/`]`/`:` are not DNS-label characters).
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
  if (!DOMAIN_RE.test(domain) || IPV4_LITERAL.test(domain)) {
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
// Only `corroborations` had an upper bound; `displayName`, `provenance.locator`, and
// `annotations.note` did not, despite being attacker/disk-controlled strings on the SAME untrusted
// input path. An unbounded string field on a restored backup or a synced entry is the same
// memory-amplification surface the `MAX_CORROBORATIONS` cap exists to close.
const MAX_DISPLAY_NAME_LEN = 256
const MAX_LOCATOR_LEN = 1024
const MAX_NOTE_LEN = 2_000

/**
 * Enforce `MAX_LOCATOR_LEN` on an already-`validateProvenance`d provenance and return it unchanged.
 *
 * Deliberately NOT folded into `validateProvenance` itself: `validateProvenance` is also the
 * canonical structural check `./companion-rail`'s `landReturnedKen` runs on a RAW claimed locator
 * BEFORE it truncates that locator to `RETURN_LOCATOR_MAX` (512) and namespaces it under
 * `companion:<appName>:`. Capping length inside `validateProvenance` would reject a legitimately
 * over-length raw claim before that module ever got to truncate it. This wrapper is applied only at
 * kenspeckle's OWN entry/parse points (`validateEntryShape`, `pinKen`/`addCorroboration` in ./ken),
 * where the locator is already final and nothing downstream is going to shorten it.
 */
export function capLocator(p: KenProvenance): KenProvenance {
  if (p.locator.length > MAX_LOCATOR_LEN) {
    throw new Error(`kenspeckle ken: provenance.locator exceeds ${MAX_LOCATOR_LEN} chars`)
  }
  return p
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

function optString(o: Record<string, unknown>, field: string, maxLen?: number): string | undefined {
  const v = o[field]
  if (v === undefined) return undefined
  if (typeof v !== 'string') throw new Error(`kenspeckle entry: ${field} must be a string`)
  if (maxLen !== undefined && v.length > maxLen) {
    throw new Error(`kenspeckle entry: ${field} exceeds ${maxLen} chars`)
  }
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
    if (v.note.length > MAX_NOTE_LEN) {
      throw new Error(`kenspeckle entry: annotations.note exceeds ${MAX_NOTE_LEN} chars`)
    }
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
  const displayName = optString(raw, 'displayName', MAX_DISPLAY_NAME_LEN)

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
    // bondAssertion is optional metadata; preserve it shallowly if structurally present. A PRESENT
    // but malformed `bondAssertion` now THROWS rather than being silently dropped (L8 audit finding
    // — this previously behaved differently from every other malformed-evidence case in this file,
    // e.g. `corroborations`, which throws on the first bad element rather than discarding it).
    if (raw.bondAssertion !== undefined) {
      if (!isRecord(raw.bondAssertion)) {
        throw new Error('kenspeckle kith: bondAssertion must be an object')
      }
      const ba = raw.bondAssertion
      if (typeof ba.mineId !== 'string') {
        throw new Error('kenspeckle kith: bondAssertion.mineId must be a string')
      }
      if (typeof ba.relay !== 'string') {
        throw new Error('kenspeckle kith: bondAssertion.relay must be a string')
      }
      if (typeof ba.createdAt !== 'number' || !Number.isFinite(ba.createdAt)) {
        throw new Error('kenspeckle kith: bondAssertion.createdAt must be a finite number')
      }
      if (ba.theirsId !== undefined && typeof ba.theirsId !== 'string') {
        throw new Error('kenspeckle kith: bondAssertion.theirsId must be a string')
      }
      entry.bondAssertion = {
        mineId: ba.mineId,
        relay: ba.relay,
        createdAt: ba.createdAt,
        ...(ba.theirsId !== undefined ? { theirsId: ba.theirsId } : {}),
      }
    }
    return entry
  }

  // tier === 'ken'
  const provenance = capLocator(validateProvenance(raw.provenance))
  const entry: KenEntry = { tier: 'ken', pubkey, ownerPubkey, addedAt, provenance }
  if (displayName !== undefined) entry.displayName = displayName
  if (annotations !== undefined) entry.annotations = annotations
  // Strict NIP-05 shape (M1 audit finding): `resolveKen`/`resolveNip05` build a fetch URL straight
  // from this field, so an untrusted/imported entry must not be able to smuggle a port, userinfo, a
  // path/query/fragment, or an IP literal into it.
  if (raw.nip05 !== undefined) entry.nip05 = validateNip05(raw.nip05, 'nip05')
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
    // H3 invariant: the CURRENT pin must never also sit in its own rotation history. If it did,
    // `attributeSignature` would reject the legitimate current key as `'rotated-away-key'` (that
    // check runs before the current-pin check) — the exact self-contradiction H2/H3 close off.
    if (entry.previousPubkeys.includes(pubkey)) {
      throw new Error('kenspeckle ken: pubkey must not appear in previousPubkeys')
    }
  }
  if (raw.rotation !== undefined) {
    entry.rotation = validateRotation(raw.rotation)
    // L8 audit finding: a degenerate self-rotation (proposing the CURRENT pin as its own successor)
    // was previously accepted. `acceptKenRotation` also guards this at accept-time (H2); this closes
    // it at parse-time for a stored/imported entry too.
    if (entry.rotation.newPubkey === pubkey) {
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
    entry.corroborations = raw.corroborations.map((c) => capLocator(validateProvenance(c)))
  }
  if (raw.revoked !== undefined) {
    if (typeof raw.revoked !== 'boolean') throw new Error('kenspeckle ken: revoked must be a boolean')
    entry.revoked = raw.revoked
  }
  return entry
}

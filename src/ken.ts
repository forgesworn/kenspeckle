// kindred (`./ken` subpath) — the ONE-WAY recognition trust-store (spec §6.1–§6.4).
//
// `ken` is recognising a public key you did NOT bond with: a public figure, an organisation, a
// NIP-05 handle. There is no shared secret and no mutual ceremony — recognition is one-directional.
// This file gives a consumer four capabilities over a pinned key:
//
//   1. PIN it (with provenance: how you came to trust this key) — `pinKen` / `pinKenFromNip05`.
//   2. Prove LIVE control of it — `buildKeyControlChallenge` + `verifyKeyControl`. This is the
//      impersonation-resistance primitive: a FRESH random nonce the claimant must sign means a
//      replayed old signature can never satisfy it.
//   3. ATTRIBUTE a (possibly old) signed artifact to the pin — `attributeSignature`. This binds an
//      artifact to the CURRENT pin only and is — by construction — REPLAYABLE (anyone can re-present
//      a genuinely-signed old event). That replayability is exactly WHY `verifyKeyControl` exists:
//      attribution answers "did the current pin sign this artifact?"; key-control answers "is the
//      party in front of me, right now, in control of the pinned key?".
//   4. ROTATE / REVOKE safely — `resolveKen` (propose-not-flip), `acceptKenRotation` (explicit move),
//      `revokeKen` (fail-closed), `dropKen` (consumer deletes the record).
//
// This is a STANDALONE subpath entry (`import { ... } from 'kindred/ken'`); it is deliberately NOT
// re-exported from the `.` barrel.
//
// ── NIP-05 HONESTY (security model — also stated in SECURITY.md) ──────────────────────────────────
// NIP-05 is a DNS + TLS + HTTP "trust on first use" (TOFU) anchor. It proves only that whoever
// controls `https://<domain>/.well-known/nostr.json` *says* a name maps to a key. It is NOT a
// cryptographic key-CONTINUITY anchor: the domain operator (or anyone who later compromises DNS/TLS
// or the web host) can silently swap the published key. Therefore:
//   • `pinKenFromNip05` REFUSES to pin unless the name resolves to a syntactically-valid key
//     (a refuse-on-mismatch TOFU pin — you decide to trust the first observation).
//   • `resolveKen` treats a later key CHANGE as an UNTRUSTED signal: it PROPOSES a rotation and
//     NEVER auto-flips `pubkey`. Accepting it is an explicit, user-confirmed act (`acceptKenRotation`).
//   • For high-value ken, prefer an OLD-KEY-SIGNED rotation announcement over a bare NIP-05 change
//     (record its id in `KenRotation.announcementEventId`), and always require user confirmation.
//
// All hex is lowercase-normalized at the boundary. No console output anywhere.

import { bytesToHex, randomBytes } from '@noble/hashes/utils.js'
import { verifyEvent } from 'nostr-tools/pure'
import type { NostrEvent, KenEntry, KenProvenance, KenRotation } from './types.js'

/** Exactly 64 hex chars (case-insensitive; callers lowercase on the way out). */
const HEX64 = /^[0-9a-f]{64}$/i

/** Basic NIP-05 `local@domain` shape. Deliberately permissive on the allowed characters (NIP-05
 *  itself only constrains the local part to `[a-z0-9-_.]` case-insensitively); the load-bearing
 *  guard is that BOTH sides are non-empty and there is exactly one `@`. */
const NIP05 = /^[a-z0-9\-_.]+@[a-z0-9\-_.]+$/i

/** Current unix time in whole seconds (the kindred timestamp convention). */
function nowSec(): number {
  return Math.floor(Date.now() / 1000)
}

/** Validate a 64-hex pubkey field and return it lowercase-normalized. */
function normHex64(value: string, field: string): string {
  if (typeof value !== 'string' || !HEX64.test(value)) {
    throw new Error(`ken: ${field} must be 64 hex chars`)
  }
  return value.toLowerCase()
}

/**
 * Pin a public key as a `ken` (one-way recognition) entry.
 *
 * Validates `pubkeyHex` and `ownerPubkeyHex` (each 64-hex; lowercase-normalized). `ownerPubkeyHex`
 * is ONE of MY persona pubkeys — mandatory, for the anti-correlation scoping invariant shared by the
 * whole model (a ken is recorded under a specific persona of mine, never globally). There is NO
 * shared secret — recognition is one-directional.
 *
 * @returns A fresh `KenEntry` with `tier:'ken'`, integer `addedAt`, the supplied provenance, and the
 *          optional `displayName` / `nip05` when present.
 */
export function pinKen(p: {
  pubkeyHex: string
  ownerPubkeyHex: string
  displayName?: string
  provenance: KenProvenance
  nip05?: string
}): KenEntry {
  const pubkey = normHex64(p.pubkeyHex, 'pubkeyHex')
  const ownerPubkey = normHex64(p.ownerPubkeyHex, 'ownerPubkeyHex')

  const entry: KenEntry = {
    tier: 'ken',
    pubkey,
    ownerPubkey,
    addedAt: nowSec(),
    provenance: p.provenance,
  }
  if (p.displayName !== undefined) entry.displayName = p.displayName
  if (p.nip05 !== undefined) entry.nip05 = p.nip05
  return entry
}

/**
 * Resolve a NIP-05 identifier to a single key over HTTPS, with full untrusted-input hardening.
 *
 * Shared by `pinKenFromNip05` and `resolveKen`. Fetches `https://<domain>/.well-known/nostr.json
 * ?name=<local>` (HTTPS ONLY — there is no http path; the locator is constructed, never reflected
 * from input). The response body is attacker-influenced (the domain operator controls it), so it is
 * parsed with a runtime type guard: the body must be an object, `body.names` must be an object, and
 * `body.names[local]` must be a 64-hex string. Anything else THROWS (we refuse to guess).
 *
 * @param nip05 - `local@domain` (validated by the caller before this runs).
 * @param fetch - injected `fetch` (the global, or a test double) — keeps this unit pure/testable.
 * @returns the resolved pubkey, lowercase-normalized.
 * @throws if the HTTP response is not ok, the JSON is malformed, or the name is absent / not 64-hex.
 */
async function resolveNip05(nip05: string, fetch: typeof globalThis.fetch): Promise<string> {
  const atIndex = nip05.indexOf('@')
  const local = nip05.slice(0, atIndex)
  const domain = nip05.slice(atIndex + 1)

  // HTTPS only. The URL is constructed from validated parts, so there is no scheme-injection surface.
  const url = `https://${domain}/.well-known/nostr.json?name=${encodeURIComponent(local)}`

  const res = await fetch(url)
  if (!res.ok) {
    throw new Error(`ken: nip05 lookup failed (HTTP ${res.status})`)
  }

  // Untrusted body — JSON.parse-equivalent surface. Guard every step before trusting it.
  const body: unknown = await res.json()
  if (body === null || typeof body !== 'object') {
    throw new Error('ken: nip05 response is not an object')
  }
  const names: unknown = (body as Record<string, unknown>).names
  if (names === null || typeof names !== 'object') {
    throw new Error('ken: nip05 response missing a names object')
  }
  const resolved: unknown = (names as Record<string, unknown>)[local]
  if (typeof resolved !== 'string' || !HEX64.test(resolved)) {
    // Refuse to pin/propose on a missing or malformed name — this is the TOFU refuse-on-mismatch.
    throw new Error(`ken: nip05 name "${local}" did not resolve to a 64-hex pubkey`)
  }
  return resolved.toLowerCase()
}

/**
 * Pin a `ken` from a NIP-05 identifier — a TOFU (trust-on-first-use) pin.
 *
 * Validates the `local@domain` shape, resolves it over HTTPS (see `resolveNip05`), and REFUSES to pin
 * (throws) if the name is absent or not 64-hex. On success, records `provenance.source:'nip05'` with
 * the identifier as the locator and `confirmedAt = now`. See the NIP-05 HONESTY note at the top of
 * this file: this is a DNS/TLS/HTTP anchor, not a key-continuity guarantee.
 *
 * @throws on malformed nip05, non-ok HTTP, malformed JSON, or an unresolved/invalid name.
 */
export async function pinKenFromNip05(
  nip05: string,
  ownerPubkeyHex: string,
  fetch: typeof globalThis.fetch,
): Promise<KenEntry> {
  if (typeof nip05 !== 'string' || !NIP05.test(nip05)) {
    throw new Error('ken: nip05 must be of the form local@domain')
  }
  const resolved = await resolveNip05(nip05, fetch)
  return pinKen({
    pubkeyHex: resolved,
    ownerPubkeyHex,
    nip05,
    provenance: { source: 'nip05', locator: nip05, confirmedAt: nowSec() },
  })
}

/**
 * Build a fresh key-control challenge: a 32-byte random nonce (hex) plus the issue time.
 *
 * Freshness is the whole point — the nonce is the replay defence. The claimant proves LIVE control
 * by signing an event whose `content` is exactly this nonce (see `verifyKeyControl`).
 *
 * @returns `{ nonce: 64-hex (32 random bytes), createdAt: unix seconds }`.
 */
export function buildKeyControlChallenge(): { nonce: string; createdAt: number } {
  return { nonce: bytesToHex(randomBytes(32)), createdAt: nowSec() }
}

/**
 * Verify LIVE control of the pinned key against a fresh challenge nonce. FAIL-CLOSED.
 *
 * **Nonce-binding convention:** the claimant signs a nostr event whose `content` is EXACTLY the
 * challenge nonce. (The consumer builds the event that way; any kind works — only `content` and the
 * signature/pubkey are inspected here.) Because the nonce is freshly random per challenge, a replayed
 * old signature can never satisfy this — that is what makes recognition impersonation-resistant
 * *live*, in contrast to `attributeSignature`, which is replayable by design.
 *
 * Checks, in this exact order (each short-circuits, fail-closed):
 *   1. `revoked`                  → `{ proven:false, reason:'revoked' }` (a dead pin proves nothing).
 *   2. pubkey is the CURRENT pin  → else `'pubkey-not-current-pin'` (a `previousPubkeys` key is NOT
 *                                   accepted — live control must be of the key in force NOW).
 *   3. `content === nonce`        → else `'nonce-mismatch'` (binds the proof to THIS challenge).
 *   4. `verifyEvent` (sig + id)   → else `'bad-signature'`.
 *   5. otherwise                  → `{ proven:true }`.
 */
export function verifyKeyControl(
  entry: KenEntry,
  nonce: string,
  signedEvent: NostrEvent,
): { proven: boolean; reason?: string } {
  if (entry.revoked) return { proven: false, reason: 'revoked' }
  if (signedEvent.pubkey !== entry.pubkey) return { proven: false, reason: 'pubkey-not-current-pin' }
  if (signedEvent.content !== nonce) return { proven: false, reason: 'nonce-mismatch' }
  if (!verifyEvent(signedEvent)) return { proven: false, reason: 'bad-signature' }
  return { proven: true }
}

/**
 * Attribute a (possibly OLD) signed artifact to the CURRENT pin. FAIL-CLOSED.
 *
 * Answers "did the key I currently recognise sign this event?". This is REPLAYABLE: a genuinely-old
 * signature still verifies, and anyone can re-present it — there is no freshness here. That is the
 * deliberate division of labour with `verifyKeyControl` (which proves *live* control via a fresh
 * nonce). Use attribution to credit an artifact; use key-control to authenticate a live party.
 *
 * Checks, in this exact order (each short-circuits, fail-closed):
 *   1. `revoked`                          → `{ genuine:false, reason:'revoked' }`.
 *   2. pubkey ∈ `previousPubkeys`         → `'rotated-away-key'` (explicitly distinguished from a
 *                                           random mismatch: this key WAS the pin but was rotated out).
 *   3. pubkey === current pin             → else `'pubkey-mismatch'`.
 *   4. `verifyEvent` (sig + id)           → else `'bad-signature'`.
 *   5. otherwise                          → `{ genuine:true }`.
 */
export function attributeSignature(
  entry: KenEntry,
  event: NostrEvent,
): { genuine: boolean; reason?: string } {
  if (entry.revoked) return { genuine: false, reason: 'revoked' }
  if (entry.previousPubkeys?.includes(event.pubkey)) {
    return { genuine: false, reason: 'rotated-away-key' }
  }
  if (event.pubkey !== entry.pubkey) return { genuine: false, reason: 'pubkey-mismatch' }
  if (!verifyEvent(event)) return { genuine: false, reason: 'bad-signature' }
  return { genuine: true }
}

/**
 * Re-resolve the entry's NIP-05 and PROPOSE (never auto-flip) a rotation if the key changed.
 *
 * If the entry has no `nip05`, returns it UNCHANGED (same reference — no network call). Otherwise
 * resolves over HTTPS and:
 *   • resolved === current pin  → `{ ...entry, lastResolvedAt: now }` (records the successful check;
 *     any pre-existing unaccepted `rotation` is LEFT as-is — we don't silently retract a proposal the
 *     user hasn't acted on; clearing it is the consumer's explicit choice).
 *   • resolved !== current pin  → `{ ...entry, lastResolvedAt: now, rotation: { newPubkey: resolved,
 *     observedAt: now, via:'nip05', accepted:false } }`. **`pubkey` is NOT touched.** A NIP-05 key
 *     change is an UNTRUSTED signal (see the NIP-05 HONESTY note); accepting it is an explicit act
 *     via `acceptKenRotation`.
 *
 * @throws (propagated from `resolveNip05`) on non-ok HTTP, malformed JSON, or an unresolved name —
 *         a resolution FAILURE must not silently look like "no change".
 */
export async function resolveKen(
  entry: KenEntry,
  fetch: typeof globalThis.fetch,
): Promise<KenEntry> {
  if (entry.nip05 === undefined) return entry
  const resolved = await resolveNip05(entry.nip05, fetch)
  const at = nowSec()
  if (resolved === entry.pubkey) {
    return { ...entry, lastResolvedAt: at }
  }
  return {
    ...entry,
    lastResolvedAt: at,
    rotation: { newPubkey: resolved, observedAt: at, via: 'nip05', accepted: false },
  }
}

/**
 * Accept a pending rotation: move the current pin into history and adopt the proposed key.
 *
 * Requires `entry.rotation` to be present (throws otherwise — there is nothing to accept). The
 * current `pubkey` is APPENDED to `previousPubkeys` (preserving multi-rotation audit order), `pubkey`
 * is set to `rotation.newPubkey`, and `rotation.accepted` is set to `true`. There is NO dual-accept /
 * grace window: the moment this runs, `attributeSignature` rejects the old key (now in
 * `previousPubkeys`) as `'rotated-away-key'`, and `verifyKeyControl` will only prove the new pin.
 *
 * This is intentionally a separate, explicit step from `resolveKen` (which only proposes): adopting a
 * new key for a recognised public figure is a security-relevant decision the user must confirm.
 */
export function acceptKenRotation(entry: KenEntry): KenEntry {
  if (!entry.rotation) {
    throw new Error('ken: no pending rotation to accept')
  }
  const previousPubkeys = [...(entry.previousPubkeys ?? []), entry.pubkey]
  return {
    ...entry,
    pubkey: entry.rotation.newPubkey,
    previousPubkeys,
    rotation: { ...entry.rotation, accepted: true },
  }
}

/**
 * Revoke the pin: the figure announced key compromise with NO successor.
 *
 * Sets `revoked:true`. Thereafter `attributeSignature` and `verifyKeyControl` BOTH fail closed
 * (`reason:'revoked'`, checked first) — a compromised key with no rotation target must authenticate
 * nothing and attribute nothing. (A compromise WITH a successor is a rotation, not a revoke.)
 */
export function revokeKen(entry: KenEntry): KenEntry {
  return { ...entry, revoked: true }
}

/**
 * Mark intent to drop a ken. This is a NO-OP: kindred does not own the consumer's storage, so the
 * actual removal of the local record is the CONSUMER'S responsibility (delete it from your store).
 * Returns `void`; kept in the API as an explicit, documented seam so "drop a ken" has a named home
 * and a place to grow (e.g. emitting an audit hook) without changing the call site later.
 */
export function dropKen(_entry: KenEntry): void {
  // Intentionally empty — see doc comment. The consumer removes the record from its own storage.
}

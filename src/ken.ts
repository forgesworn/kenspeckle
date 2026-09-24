// kenspeckle (`./ken` subpath) — the ONE-WAY recognition trust-store (spec §6.1–§6.4).
//
// `ken` is recognising a public key you did NOT bond with: a public figure, an organisation, a
// NIP-05 handle. There is no shared secret and no mutual ceremony — recognition is one-directional.
// This file gives a consumer four capabilities over a pinned key:
//
//   1. PIN it (with provenance: how you came to trust this key) — `pinKen` / `pinKenFromNip05`.
//   2. Prove LIVE control of it — `buildKeyControlChallenge` + `verifyKeyControl`. This is the
//      impersonation-resistance primitive: a FRESH random nonce the claimant must sign means a
//      replayed old signature can never satisfy it. `verifyKeyControl` ENFORCES that the nonce is the
//      full 64-hex random shape `buildKeyControlChallenge` emits (rejecting `''`/weak nonces with
//      `reason:'bad-nonce'`) — without that gate an empty nonce would be satisfied by a replayed
//      empty-content event, so the strength check is what makes the "never" claim true.
//   3. ATTRIBUTE a (possibly old) signed artifact to the pin — `attributeSignature`. This binds an
//      artifact to the CURRENT pin only and is — by construction — REPLAYABLE (anyone can re-present
//      a genuinely-signed old event). That replayability is exactly WHY `verifyKeyControl` exists:
//      attribution answers "did the current pin sign this artifact?"; key-control answers "is the
//      party in front of me, right now, in control of the pinned key?".
//   4. ROTATE / REVOKE safely — `resolveKen` (propose-not-flip), `acceptKenRotation` (explicit move),
//      `revokeKen` (fail-closed), `dropKen` (consumer deletes the record).
//
// This is a STANDALONE subpath entry (`import { ... } from '@forgesworn/kenspeckle/ken'`); it is deliberately NOT
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
import { COMPANION_LOCATOR_PREFIX } from './types.js'
import type { NostrEvent, KenEntry, KenProvenance } from './types.js'
import { validateNip05, validateProvenance, capLocator, capDisplayName, MAX_CORROBORATIONS } from './validate.js'

/** Exactly 64 hex chars (case-insensitive; callers lowercase on the way out). */
const HEX64 = /^[0-9a-f]{64}$/i

/** Exactly 64 LOWERCASE hex chars — the EXACT shape `buildKeyControlChallenge` emits (32 random
 *  bytes via `bytesToHex`, which is lowercase). `verifyKeyControl` requires the challenge nonce to
 *  match this so a weak/empty nonce (e.g. `''`) cannot be satisfied by a replayed empty-content
 *  event. Deliberately case-SENSITIVE (no `i` flag): nothing we issue is uppercase, so accepting
 *  uppercase would only widen the surface for no benefit. */
const CHALLENGE_NONCE = /^[0-9a-f]{64}$/

/** Current unix time in whole seconds (the kenspeckle timestamp convention). */
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
 * Validate a provenance for a FIRST-PARTY creation path (`pinKen` / `addCorroboration`) and reject
 * the RESERVED `companion:` locator prefix (M5 audit finding). `COMPANION_LOCATOR_PREFIX` is
 * reserved for `landReturnedKen` (./companion-rail) to mark a RELAYED claim, not a first-hand
 * confirmation; a first-party call minting one would let a companion-app claim masquerade as
 * something the user directly confirmed — the opposite of what the reservation means to guarantee.
 */
function validateFirstPartyProvenance(v: KenProvenance): KenProvenance {
  const validated = capLocator(validateProvenance(v))
  if (validated.locator.startsWith(COMPANION_LOCATOR_PREFIX)) {
    throw new Error(
      `ken: provenance.locator must not use the reserved "${COMPANION_LOCATOR_PREFIX}" prefix`,
    )
  }
  return validated
}

/**
 * Pin a public key as a `ken` (one-way recognition) entry.
 *
 * Validates `pubkeyHex` and `ownerPubkeyHex` (each 64-hex; lowercase-normalized). `ownerPubkeyHex`
 * is ONE of MY persona pubkeys — mandatory, for the anti-correlation scoping invariant shared by the
 * whole model (a ken is recorded under a specific persona of mine, never globally). There is NO
 * shared secret — recognition is one-directional.
 *
 * Runs the SAME `validateProvenance` + `MAX_CORROBORATIONS` cap + reserved-`companion:`-prefix
 * rejection as `importEntries`/`parseEntry` (M4/M5 audit findings) — a builder must not be able to
 * mint an entry the parser would then refuse (which, for a corroboration cap violation, meant a
 * roster that exported fine could not be restored, losing the whole backup). It also enforces the
 * creation-path rules parse does not: the `MAX_DISPLAY_NAME_LEN` / `MAX_LOCATOR_LEN` caps (in code
 * points) and a strict `nip05`, plus the self-entry rejection parse shares.
 *
 * @returns A fresh `KenEntry` with `tier:'ken'`, integer `addedAt`, the supplied provenance, and the
 *          optional `displayName` / `nip05` when present.
 * @throws on `pubkeyHex === ownerPubkeyHex`, a malformed provenance/corroboration, a
 *         `companion:`-prefixed locator, an over-length `displayName` or locator, more than
 *         `MAX_CORROBORATIONS` corroborations, or a malformed `nip05`.
 */
export function pinKen(p: {
  pubkeyHex: string
  ownerPubkeyHex: string
  displayName?: string
  provenance: KenProvenance
  /** OPTIONAL additional independent confirmations (§3.2). Omitting it is exactly the pre-existing
   *  behaviour — the field is only set on the returned entry when supplied and non-empty. */
  corroborations?: KenProvenance[]
  nip05?: string
}): KenEntry {
  const pubkey = normHex64(p.pubkeyHex, 'pubkeyHex')
  const ownerPubkey = normHex64(p.ownerPubkeyHex, 'ownerPubkeyHex')
  // A self-entry (recognising my OWN persona) is never a relationship; parse rejects it too.
  if (pubkey === ownerPubkey) {
    throw new Error('ken: pubkeyHex must not equal ownerPubkeyHex')
  }
  const provenance = validateFirstPartyProvenance(p.provenance)

  const entry: KenEntry = {
    tier: 'ken',
    pubkey,
    ownerPubkey,
    addedAt: nowSec(),
    provenance,
  }
  if (p.displayName !== undefined) entry.displayName = capDisplayName(p.displayName)
  // Only materialise `corroborations` when there is something to record: a caller passing `[]` must
  // not make the new entry serialise differently from one pinned without the argument at all.
  if (p.corroborations !== undefined && p.corroborations.length > 0) {
    if (p.corroborations.length > MAX_CORROBORATIONS) {
      throw new Error(`ken: at most ${MAX_CORROBORATIONS} corroborations`)
    }
    entry.corroborations = p.corroborations.map(validateFirstPartyProvenance)
  }
  if (p.nip05 !== undefined) entry.nip05 = validateNip05(p.nip05, 'nip05')
  return entry
}

/**
 * Record ANOTHER independent channel confirming this key belongs to this person. PURE — returns a
 * new entry; the input is never mutated.
 *
 * The primary `provenance` is NEVER touched. A later confirmation does not replace how you first
 * came to believe the key; it stands alongside it, which is the entire point of corroboration.
 * Appends in observation order (order is meaningful and preserved by `stableSort`, which sorts
 * object keys but leaves array element order alone).
 *
 * Duplicates are NOT de-duplicated: re-checking the same domain a year later is a genuinely new
 * confirmation with a new `confirmedAt`, and collapsing it would destroy the recency evidence.
 *
 * Runs the SAME `validateProvenance` + `MAX_CORROBORATIONS` cap + reserved-`companion:`-prefix
 * rejection as `pinKen`/`importEntries`/`parseEntry` (M4/M5 audit findings).
 *
 * @throws on a malformed provenance, a `companion:`-prefixed locator, or if the result would exceed
 *         `MAX_CORROBORATIONS`.
 */
export function addCorroboration(entry: KenEntry, provenance: KenProvenance): KenEntry {
  const validated = validateFirstPartyProvenance(provenance)
  const corroborations = [...(entry.corroborations ?? []), validated]
  if (corroborations.length > MAX_CORROBORATIONS) {
    throw new Error(`ken: at most ${MAX_CORROBORATIONS} corroborations`)
  }
  return { ...entry, corroborations }
}

/**
 * Describe how much independent agreement stands behind this pin, and how fresh it is.
 *
 * ── WHY THIS RETURNS FACTS AND NOT A SCORE ───────────────────────────────────────────────────────
 * It is tempting to reduce this to a single "trust strength" number. That is deliberately NOT done:
 *   • A scalar invites false precision, and invites being used as an AUTHORIZATION input
 *     (`if (strength > 0.7) allow`) — a security decision this primitive cannot underwrite.
 *   • Weighting channels against each other (is one `in-person` worth two `nip05`?) is CONSUMER
 *     POLICY, not a property of the data. A social-channel confirmation means something very
 *     different to a game client than to a bank.
 *   • Recency "decay" has the same problem: the half-life is a policy choice, not a fact.
 * So this returns only what is literally true of the record, and the consumer applies its own rule.
 *
 * ── HONESTY ABOUT WHAT "INDEPENDENT" MEANS ───────────────────────────────────────────────────────
 * Neither count PROVES independence. `distinctSources` can UNDERSTATE it (two different websites
 * both count as one `web`); `distinctLocators` can OVERSTATE it (one operator can serve two
 * locators, and DNS + the website behind it commonly share a single point of compromise). They are
 * useful signals, not guarantees — same posture as the NIP-05 honesty note above.
 *
 * ── `claimed` — THE COUNT THAT KEEPS THE REST HONEST ──────────────────────────────────────────────
 * A ken landed from a companion app can show six confirmations across six distinct sources while
 * NOTHING was verified first-hand: every entry is a relayed claim, and the primary only means "this
 * arrived via app X". Reporting only the totals would show maximum apparent corroboration for zero
 * verification — a worse failure than having no summary at all. `claimed` counts the records whose
 * locator sits in the RESERVED `companion:` namespace (`COMPANION_LOCATOR_PREFIX`), which only
 * `landReturnedKen` mints and which no first-party flow may use. `confirmations - claimed` is
 * therefore what was actually confirmed first-hand. A consumer that renders corroboration MUST use
 * this, or it will present relayed claims as verification.
 *
 * @returns counts over the primary provenance PLUS every corroboration, `sources` in first-seen
 *          order (primary first), and the newest/oldest `confirmedAt` across all of them. An entry
 *          with no corroborations reports `confirmations: 1` — never zero.
 */
export function summarizeKenProvenance(entry: KenEntry): {
  confirmations: number
  /** How many of `confirmations` are relayed companion CLAIMS rather than first-hand checks. */
  claimed: number
  distinctSources: number
  distinctLocators: number
  sources: KenProvenance['source'][]
  mostRecentAt: number
  oldestAt: number
} {
  const all: KenProvenance[] = [entry.provenance, ...(entry.corroborations ?? [])]

  const sources: KenProvenance['source'][] = []
  for (const p of all) {
    if (!sources.includes(p.source)) sources.push(p.source)
  }
  // Lowercase before counting locators: case-folding can only MERGE two entries into one, never
  // split one into two, so it errs toward reporting LESS independence — the honest direction.
  const locators = new Set(all.map((p) => p.locator.toLowerCase()))

  // Fold rather than `Math.max(...times)`: `corroborations` has no length cap (matching
  // `previousPubkeys`), and spreading a large array into a call blows the argument limit with a
  // RangeError. A restored backup is disk-controlled input, so this must not be a crash surface.
  // Seed from the primary, which is always present — `all` is never empty by construction.
  let mostRecentAt = entry.provenance.confirmedAt
  let oldestAt = entry.provenance.confirmedAt
  for (const p of all) {
    if (p.confirmedAt > mostRecentAt) mostRecentAt = p.confirmedAt
    if (p.confirmedAt < oldestAt) oldestAt = p.confirmedAt
  }

  return {
    confirmations: all.length,
    claimed: all.filter((p) => p.locator.startsWith(COMPANION_LOCATOR_PREFIX)).length,
    distinctSources: sources.length,
    distinctLocators: locators.size,
    sources,
    mostRecentAt,
    oldestAt,
  }
}

/** Bounded wait for the nip05 fetch (L1 audit finding) — a stalled/malicious server must not be
 *  able to hang the caller forever. */
const NIP05_FETCH_TIMEOUT_MS = 10_000
/** Cap on the nip05 response body, checked BEFORE it is handed to `JSON.parse` (L1 audit finding):
 *  a well-known `nostr.json` is a small, bounded document, so an unbounded body is itself a signal
 *  something is wrong, and parsing it would be an unbounded-allocation surface either way. */
const NIP05_MAX_BODY_CHARS = 1_048_576 // 1 MiB of JSON text

/** True when `v` passes `validateNip05` — used where a bad value means "unresolvable", not an error. */
function isStrictNip05(v: string): boolean {
  try {
    validateNip05(v, 'nip05')
    return true
  } catch {
    return false
  }
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
 * THIS IS THE CHOKE POINT (M1 audit finding): `nip05` can reach here from an untrusted/imported
 * entry (`resolveKen` operates on whatever `entry.nip05` was set to, including one that arrived via
 * sync or a restored backup), not only from a caller that already validated it. `validateNip05` is
 * re-run here regardless of whether the caller already checked, so the URL is built ONLY from a
 * strictly-shaped `local`/`domain` — no port, no userinfo, no path/query/fragment, no IP literal.
 *
 * FETCH HARDENING (L1 audit finding): NIP-05 requires fetchers to ignore redirects — the "HTTPS
 * only" guarantee would otherwise depend on wherever a redirect target points, which the domain
 * operator also controls — so `redirect:'error'` makes a redirect a hard failure instead of a
 * silent follow. A bounded `AbortSignal.timeout` prevents a stalled response from hanging the
 * caller. The body is read as text and length-capped BEFORE `JSON.parse`, not handed straight to
 * `res.json()`, so an oversized body is rejected before an unbounded parse/allocation.
 *
 * CASE-FOLDING (L2 audit finding): NIP-05 names are case-insensitive, but servers commonly publish
 * lowercase keys in `names`. Both the query param and the `names` lookup key are lowercased so
 * `Bob@Example.com` matches a server publishing `bob`.
 *
 * @param nip05 - `local@domain`. Re-validated here even though callers also validate.
 * @param fetch - injected `fetch` (the global, or a test double) — keeps this unit pure/testable.
 * @returns the resolved pubkey, lowercase-normalized.
 * @throws if `nip05` is malformed, the HTTP response is not ok / redirected, the body exceeds the
 *         size cap, the JSON is malformed, or the name is absent / not 64-hex.
 */
async function resolveNip05(nip05: string, fetch: typeof globalThis.fetch): Promise<string> {
  validateNip05(nip05, 'nip05')
  const atIndex = nip05.indexOf('@')
  // Lowercase BOTH halves — NIP-05 is case-insensitive end to end (L2).
  const local = nip05.slice(0, atIndex).toLowerCase()
  const domain = nip05.slice(atIndex + 1).toLowerCase()

  // HTTPS only. The URL is constructed from validated parts, so there is no scheme-injection surface.
  const url = `https://${domain}/.well-known/nostr.json?name=${encodeURIComponent(local)}`

  const res = await fetch(url, {
    redirect: 'error',
    signal: AbortSignal.timeout(NIP05_FETCH_TIMEOUT_MS),
  })
  if (!res.ok) {
    throw new Error(`ken: nip05 lookup failed (HTTP ${res.status})`)
  }

  // Read as text and cap BEFORE parsing — an oversized body is rejected before `JSON.parse` ever
  // sees it (L1).
  const text = await res.text()
  if (text.length > NIP05_MAX_BODY_CHARS) {
    throw new Error('ken: nip05 response exceeds the size cap')
  }
  let body: unknown
  try {
    body = JSON.parse(text)
  } catch {
    throw new Error('ken: nip05 response is not valid JSON')
  }
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
  validateNip05(nip05, 'nip05')
  const resolved = await resolveNip05(nip05, fetch)
  return pinKen({
    pubkeyHex: resolved,
    ownerPubkeyHex,
    nip05,
    provenance: { source: 'nip05', locator: nip05, confirmedAt: nowSec() },
  })
}

/**
 * Build a fresh key-control challenge: a 32-byte random nonce (lowercase hex) plus the issue time.
 *
 * Freshness is the whole point — the nonce is the replay defence. The claimant proves LIVE control
 * by signing an event whose `content` is exactly this nonce (see `verifyKeyControl`). The 64-hex
 * shape this emits is ALSO the shape `verifyKeyControl` enforces (`reason:'bad-nonce'` otherwise),
 * so a caller cannot accidentally weaken the challenge to an empty/short string and reopen the
 * replay hole.
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
 * **Known limitation (L4 audit finding) — NOT verifier-bound.** Nothing here ties the proof to a
 * SPECIFIC verifier or context: any party holding a valid `{nonce, signedEvent}` pair can present it
 * to prove control to a DIFFERENT verifier (a phishing verifier B can relay a challenge from real
 * verifier A to the key holder and replay the resulting proof back to A). Closing this fully needs a
 * dedicated event kind carrying verifier/origin/expiry tags — a wire-format change that belongs in
 * PROTOCOL.md (out of this file's scope). As a backward-compatible, OPT-IN partial mitigation,
 * `opts.expectedCreatedAt` + `opts.maxAgeSec` bound `signedEvent.created_at` against the challenge's
 * own `createdAt` (rejecting a proof presented long after the challenge was issued), and
 * `opts.verifierTag` requires a `['verifier', <id>]` tag on the signed event. Both are no-ops when
 * omitted (existing callers are unaffected). Passing them does not by itself defeat a REAL-TIME
 * relay attack (a phishing verifier can still forward tags it was told to include) — only a
 * dedicated, verifier-signed challenge kind closes that fully.
 *
 * **Single-use is the CONSUMER'S responsibility.** This function does not — and cannot, being pure
 * and stateless — track which nonces have already been consumed. A verifier MUST record each
 * `nonce` it accepts (e.g. against `entry.pubkey`) and reject a repeat, or a proof captured once can
 * be replayed against the SAME verifier within the freshness window.
 *
 * Checks, in this exact order (each short-circuits, fail-closed):
 *   1. `revoked`                  → `{ ok:false, reason:'revoked' }` (a dead pin proves nothing).
 *   2. nonce STRENGTH             → else `'bad-nonce'`. The challenge nonce MUST be exactly 64
 *                                   lowercase-hex chars (the 32 random bytes `buildKeyControlChallenge`
 *                                   emits). This is the load-bearing replay defence: WITHOUT it, a
 *                                   weak/empty nonce (e.g. `''`) is satisfied by a replayed GENUINE
 *                                   empty-content event (kind-3 lists, reactions — common on Nostr),
 *                                   because `content === nonce` reduces to `'' === ''`. The guard is
 *                                   what makes "a replayed old signature can never satisfy this" TRUE.
 *   3. pubkey is the CURRENT pin  → else `'pubkey-not-current-pin'` (a `previousPubkeys` key is NOT
 *                                   accepted — live control must be of the key in force NOW).
 *   4. `content === nonce`        → else `'nonce-mismatch'` (binds the proof to THIS challenge).
 *   5. `verifyEvent` (sig + id)   → else `'bad-signature'`.
 *   6. `opts.expectedCreatedAt`   → else `'stale-proof'` (only when supplied; see above).
 *   7. `opts.verifierTag`         → else `'verifier-mismatch'` (only when supplied; see above).
 *   8. otherwise                  → `{ ok:true }`.
 *
 * @returns `{ ok, reason? }` — `ok:true` only when LIVE control is proven; `reason` names the failure.
 */
export function verifyKeyControl(
  entry: KenEntry,
  nonce: string,
  signedEvent: NostrEvent,
  opts?: { expectedCreatedAt?: number; maxAgeSec?: number; verifierTag?: string },
): { ok: boolean; reason?: string } {
  if (entry.revoked) return { ok: false, reason: 'revoked' }
  // Nonce-strength gate (fail-closed, checked EARLY): a challenge that is not the full 64-hex random
  // shape is rejected before we ever trust `content === nonce`. This closes the empty/weak-nonce
  // replay hole and is what makes the impersonation-resistance claim honest.
  if (typeof nonce !== 'string' || !CHALLENGE_NONCE.test(nonce)) {
    return { ok: false, reason: 'bad-nonce' }
  }
  if (signedEvent.pubkey !== entry.pubkey) return { ok: false, reason: 'pubkey-not-current-pin' }
  if (signedEvent.content !== nonce) return { ok: false, reason: 'nonce-mismatch' }
  if (!verifyEvent(signedEvent)) return { ok: false, reason: 'bad-signature' }
  if (opts?.expectedCreatedAt !== undefined) {
    const maxAge = opts.maxAgeSec ?? 300
    const age = signedEvent.created_at - opts.expectedCreatedAt
    if (age < 0 || age > maxAge) return { ok: false, reason: 'stale-proof' }
  }
  if (opts?.verifierTag !== undefined) {
    const has = signedEvent.tags.some((t) => t[0] === 'verifier' && t[1] === opts.verifierTag)
    if (!has) return { ok: false, reason: 'verifier-mismatch' }
  }
  return { ok: true }
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
 *   1. `revoked`                          → `{ ok:false, reason:'revoked' }`.
 *   2. pubkey ∈ `previousPubkeys`         → `'rotated-away-key'` (explicitly distinguished from a
 *                                           random mismatch: this key WAS the pin but was rotated out).
 *   3. pubkey === current pin             → else `'pubkey-mismatch'`.
 *   4. `verifyEvent` (sig + id)           → else `'bad-signature'`.
 *   5. otherwise                          → `{ ok:true }`.
 *
 * @returns `{ ok, reason? }` — `ok:true` only when the CURRENT pin genuinely signed `event`; `reason`
 *          names the failure. (Replayable by design — `ok:true` does NOT prove live control.)
 */
export function attributeSignature(
  entry: KenEntry,
  event: NostrEvent,
): { ok: boolean; reason?: string } {
  if (entry.revoked) return { ok: false, reason: 'revoked' }
  if (entry.previousPubkeys?.includes(event.pubkey)) {
    return { ok: false, reason: 'rotated-away-key' }
  }
  if (event.pubkey !== entry.pubkey) return { ok: false, reason: 'pubkey-mismatch' }
  if (!verifyEvent(event)) return { ok: false, reason: 'bad-signature' }
  return { ok: true }
}

/**
 * Re-resolve the entry's NIP-05 and PROPOSE (never auto-flip) a rotation if the key changed.
 *
 * If the entry has no `nip05`, or its stored `nip05` fails `validateNip05` (an unresolvable value
 * 0.1.x accepted, e.g. `x@localhost`), returns it UNCHANGED (same reference — no network call). If the entry
 * is `revoked`, ALSO returns it UNCHANGED (same reference — no network call): a revoked pin is dead
 * (`attributeSignature`/`verifyKeyControl` both fail closed on it regardless), so proposing a
 * rotation for it is nonsensical and would only invite an `acceptKenRotation` that resurrects a
 * revoked pin under a new key without an explicit un-revoke decision (L3 audit finding). Otherwise
 * resolves over HTTPS and:
 *   • resolved === current pin        → `{ ...entry, lastResolvedAt: now }` (records the successful
 *     check; any pre-existing unaccepted `rotation` is LEFT as-is — we don't silently retract a
 *     proposal the user hasn't acted on; clearing it is the consumer's explicit choice).
 *   • resolved ∈ `previousPubkeys`    → PROPOSED with `rotation.rollback: true` (H3 audit finding).
 *     This is the exact shape of a compromised-domain replay: the NIP-05 operator re-serves a key
 *     that was already rotated away from. Flagging it (instead of proposing an ordinary rotation)
 *     lets `acceptKenRotation` refuse it by default.
 *   • resolved !== current pin, not previously rotated away → PROPOSED as an ordinary rotation
 *     (`rotation.rollback` absent). `pubkey` is NOT touched in either proposal case. A NIP-05 key
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
  if (entry.revoked) return entry
  // A stored nip05 that fails the strict shape (parse/import keep values 0.1.x accepted, e.g.
  // `x@localhost`) is unresolvable: treated like "no nip05", and NEVER fetched (M1 SSRF guard).
  if (!isStrictNip05(entry.nip05)) return entry
  const resolved = await resolveNip05(entry.nip05, fetch)
  const at = nowSec()
  if (resolved === entry.pubkey) {
    return { ...entry, lastResolvedAt: at }
  }
  const rollback = entry.previousPubkeys?.includes(resolved) ?? false
  return {
    ...entry,
    lastResolvedAt: at,
    rotation: {
      newPubkey: resolved,
      observedAt: at,
      via: 'nip05',
      accepted: false,
      ...(rollback ? { rollback: true } : {}),
    },
  }
}

/**
 * Accept a pending rotation: move the current pin into history and adopt the proposed key.
 *
 * Requires `entry.rotation` to be present (throws otherwise — there is nothing to accept). The
 * current `pubkey` is APPENDED to `previousPubkeys` (preserving multi-rotation audit order; any
 * PRIOR occurrence of the new pubkey there is filtered out first — see the rollback note below),
 * `pubkey` is set to `rotation.newPubkey`, and `rotation.accepted` is set to `true`. There is NO
 * dual-accept / grace window: the moment this runs, `attributeSignature` rejects the old key (now in
 * `previousPubkeys`) as `'rotated-away-key'`, and `verifyKeyControl` will only prove the new pin.
 *
 * This is intentionally a separate, explicit step from `resolveKen` (which only proposes): adopting a
 * new key for a recognised public figure is a security-relevant decision the user must confirm.
 *
 * FAIL-CLOSED GUARDS (H2/H3 audit findings, and the revoked guard below):
 *   • `entry.revoked === true`             → throws, CHECKED FIRST — mirrors `attributeSignature` /
 *     `verifyKeyControl`, which both check `revoked` before anything else. A revoked pin announces a
 *     compromise with no successor (see `revokeKen`); silently moving it to a NEW pubkey — even one
 *     `resolveKen` proposed BEFORE the revoke — would resurrect a dead pin under a key nobody
 *     explicitly re-confirmed. Un-revoking is a separate, explicit decision this function does not
 *     make on the caller's behalf.
 *   • `rotation.accepted === true`         → throws. Without this, calling accept a SECOND time on
 *     an entry whose accepted rotation `resolveKen` deliberately left in place (see its doc comment)
 *     would append the now-CURRENT pubkey into `previousPubkeys` again, and `attributeSignature`
 *     would then reject the legitimate current key as `'rotated-away-key'`. This makes the function
 *     idempotency-safe: the current pubkey can never be added to `previousPubkeys` twice.
 *   • `rotation.newPubkey === entry.pubkey` → throws (a degenerate self-rotation).
 *   • `rotation.rollback === true`          → throws UNLESS `opts.allowRevert` is `true`. A rollback
 *     proposal targets a key already in `previousPubkeys` — the compromised-domain-replay shape — so
 *     accepting it requires an explicit, informed override rather than the ordinary accept path.
 *   • `rotation.newPubkey` is re-validated as 64-hex here (defense-in-depth for a hand-built entry
 *     that bypassed `validateEntryShape`).
 *
 * @throws per the guards above, or `ken: rotation.newPubkey must be 64 hex chars` for a malformed
 *         `newPubkey`.
 */
export function acceptKenRotation(entry: KenEntry, opts?: { allowRevert?: boolean }): KenEntry {
  // Checked FIRST, mirroring attributeSignature/verifyKeyControl: a revoked pin proves nothing and
  // adopts nothing — see the FAIL-CLOSED GUARDS note above.
  if (entry.revoked) {
    throw new Error('ken: cannot accept a rotation on a revoked entry')
  }
  if (!entry.rotation) {
    throw new Error('ken: no pending rotation to accept')
  }
  if (entry.rotation.accepted) {
    throw new Error('ken: rotation has already been accepted')
  }
  if (entry.rotation.rollback && !opts?.allowRevert) {
    throw new Error(
      'ken: rotation targets a key already in previousPubkeys (rollback) — pass { allowRevert: true } to confirm',
    )
  }
  const newPubkey = normHex64(entry.rotation.newPubkey, 'rotation.newPubkey')
  if (newPubkey === entry.pubkey) {
    throw new Error('ken: rotation.newPubkey equals the current pin')
  }
  // Filter out `newPubkey` before appending the current pin: for a rollback accept, `newPubkey` is
  // ALREADY in `previousPubkeys`, and leaving it there while also setting it as the current `pubkey`
  // would make `attributeSignature` reject the legitimate current key (it checks `previousPubkeys`
  // before the current-pin match) — the exact self-contradiction this fix closes.
  const previousPubkeys = [
    ...(entry.previousPubkeys ?? []).filter((p) => p !== newPubkey),
    entry.pubkey,
  ]
  return {
    ...entry,
    pubkey: newPubkey,
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
 * Mark intent to drop a ken. This is a NO-OP: kenspeckle does not own the consumer's storage, so the
 * actual removal of the local record is the CONSUMER'S responsibility (delete it from your store).
 * Returns `void`; kept in the API as an explicit, documented seam so "drop a ken" has a named home
 * and a place to grow (e.g. emitting an audit hook) without changing the call site later.
 */
export function dropKen(_entry: KenEntry): void {
  // Intentionally empty — see doc comment. The consumer removes the record from its own storage.
}

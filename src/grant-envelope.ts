// Companion data rail — the wire envelope shared by signet-app (sharer) and an
// owner-controlled companion app (consumer). See PROTOCOL.md.
import type { KindredEntry, KinEntry } from './types.js'

/** Secret-stripped "read & pick" view of a contact. Structurally omits
 *  sharedSecret / annotations / bond / provenance — a compromised companion
 *  app can never impersonate a bond, because the type has no secret field. */
export interface GrantContactView {
  pubkey: string
  ownerPubkey: string
  tier: 'kin' | 'kith' | 'ken'
  displayName?: string
  addedAt: number
  relationship?: KinEntry['relationship']
  nip05?: string
}

export function toGrantView(e: KindredEntry): GrantContactView {
  const base: GrantContactView = {
    pubkey: e.pubkey,
    ownerPubkey: e.ownerPubkey,
    tier: e.tier,
    addedAt: e.addedAt,
  }
  if (e.displayName !== undefined) base.displayName = e.displayName
  if (e.tier === 'kin') base.relationship = e.relationship
  if (e.tier === 'ken' && e.nip05) base.nip05 = e.nip05
  return base
}

const TIERS = ['kin', 'kith', 'ken'] as const
const HEX64 = /^[0-9a-f]{64}$/
const KIN_RELS = ['parent', 'child', 'sibling', 'grandparent', 'partner', 'guardian', 'dependant', 'other']

/** Most contacts one envelope carries. Parse keeps the first this-many; build throws past it. */
export const GRANT_CONTACTS_CAP = 5000

// Same display-boundary class as Signet (and the companion rail's forward sanitiser).
// eslint-disable-next-line no-control-regex
const DISPLAY_UNSAFE = /[\x00-\x1f\x7f-\x9f\u200b-\u200f\u2028-\u202e\u2066-\u2069]/g

/** Sanitise display text at the trust boundary: strip control/bidi → trim → slice to `max` CODE
 *  POINTS (a UTF-16 slice could split a surrogate pair). Undefined when nothing survives. Internal:
 *  shared with ./companion-rail, not re-exported from the barrel. */
export function cleanDisplayText(value: unknown, max: number): string | undefined {
  if (typeof value !== 'string') return undefined
  const out = Array.from(value.replace(DISPLAY_UNSAFE, '').trim()).slice(0, max).join('')
  return out.length > 0 ? out : undefined
}

/** A non-negative safe integer (unix seconds). `JSON.parse('1e400')` is `Infinity`, which would
 *  otherwise freeze a monotonic reducer for good. */
function isUnixSeconds(value: unknown): value is number {
  return typeof value === 'number' && Number.isSafeInteger(value) && value >= 0
}

export interface GrantScope {
  tiers: Array<'kin' | 'kith' | 'ken'>
  personas: 'all' | string[]
}

export interface GrantEnvelope {
  v: 1
  scope: GrantScope
  contacts: GrantContactView[]
  publishedAt: number
  revoked?: true
}

/**
 * Build the JSON plaintext of a grant snapshot (or, with `{ revoked: true }`, the tombstone).
 *
 * Serialises an explicit PROJECTION of the scope and of each view — never the caller's objects, so a
 * non-literal argument carrying extra fields cannot put them on the wire — then round-trips through
 * the parser and throws unless every contact survives byte-identically (a contact outside `scope`, a
 * bad key, an unsafe display name … would otherwise be dropped silently on the far side).
 *
 * @throws If `publishedAt` is not a non-negative safe integer, the scope is invalid, there are more
 *         than `GRANT_CONTACTS_CAP` contacts, or any contact would not survive the parser.
 */
export function buildGrantEnvelope(
  scope: GrantScope,
  views: GrantContactView[],
  publishedAt: number,
  opts?: { revoked?: true },
): string {
  if (!isUnixSeconds(publishedAt)) throw new TypeError('grant envelope: publishedAt must be a non-negative safe integer')
  const projectedScope = parseScope(scope)
  if (!projectedScope) throw new TypeError('grant envelope: invalid scope')
  if (!Array.isArray(views)) throw new TypeError('grant envelope: contacts must be an array')
  if (views.length > GRANT_CONTACTS_CAP) {
    throw new TypeError(`grant envelope: at most ${GRANT_CONTACTS_CAP} contacts per envelope`)
  }
  const contacts = views.map(projectView)
  const env: GrantEnvelope = { v: 1, scope: projectedScope, contacts, publishedAt }
  if (opts?.revoked) env.revoked = true
  const json = JSON.stringify(env)
  const reparsed = parseGrantEnvelope(json)
  if (!reparsed || JSON.stringify(reparsed.contacts) !== JSON.stringify(contacts)) {
    throw new TypeError('grant envelope: a contact would not survive the wire intact')
  }
  return json
}

/** Copy exactly the declared `GrantContactView` fields (see `buildGrantEnvelope`), applying the same
 *  normalisation the parser does (hex lowercased, display text sanitised) so that only a structurally
 *  bad or out-of-scope contact makes the build throw — never a stray space in a name. */
function projectView(v: GrantContactView): GrantContactView {
  const out: GrantContactView = {
    pubkey: typeof v.pubkey === 'string' ? v.pubkey.toLowerCase() : v.pubkey,
    ownerPubkey: typeof v.ownerPubkey === 'string' ? v.ownerPubkey.toLowerCase() : v.ownerPubkey,
    tier: v.tier,
    addedAt: v.addedAt,
  }
  const displayName = cleanDisplayText(v.displayName, 200)
  if (displayName !== undefined) out.displayName = displayName
  if (v.relationship !== undefined) out.relationship = v.relationship
  const nip05 = cleanDisplayText(v.nip05, 200)
  if (nip05 !== undefined) out.nip05 = nip05
  return out
}

/** Validate a scope and return a fresh projection (declared keys only, hex lowercased), or null. */
function parseScope(s: unknown): GrantScope | null {
  if (typeof s !== 'object' || s === null) return null
  const o = s as Record<string, unknown>
  if (!Array.isArray(o.tiers) || o.tiers.some(t => !TIERS.includes(t as never))) return null
  const tiers = [...o.tiers] as GrantScope['tiers']
  if (o.personas === 'all') return { tiers, personas: 'all' }
  if (!Array.isArray(o.personas)) return null
  const personas: string[] = []
  for (const p of o.personas) {
    if (typeof p !== 'string' || !HEX64.test(p.toLowerCase())) return null
    personas.push(p.toLowerCase())
  }
  return { tiers, personas }
}

function parseView(item: unknown): GrantContactView | null {
  if (typeof item !== 'object' || item === null) return null
  const c = item as Record<string, unknown>
  // Hex is case-normalised (as every other kenspeckle parser does), not silently dropped.
  const pubkey = typeof c.pubkey === 'string' ? c.pubkey.toLowerCase() : ''
  const ownerPubkey = typeof c.ownerPubkey === 'string' ? c.ownerPubkey.toLowerCase() : ''
  if (!HEX64.test(pubkey) || !HEX64.test(ownerPubkey)) return null
  if (!TIERS.includes(c.tier as never)) return null
  if (!isUnixSeconds(c.addedAt)) return null
  const view: GrantContactView = {
    pubkey, ownerPubkey,
    tier: c.tier as GrantContactView['tier'], addedAt: c.addedAt,
  }
  const displayName = cleanDisplayText(c.displayName, 200)
  if (displayName !== undefined) view.displayName = displayName
  if (c.tier === 'kin' && typeof c.relationship === 'string' && KIN_RELS.includes(c.relationship)) {
    view.relationship = c.relationship as GrantContactView['relationship']
  }
  if (c.tier === 'ken') {
    const nip05 = cleanDisplayText(c.nip05, 200)
    if (nip05 !== undefined) view.nip05 = nip05
  }
  return view
}

/** True if a contact lies inside the scope the envelope itself declares. */
function inScope(view: GrantContactView, scope: GrantScope): boolean {
  if (!scope.tiers.includes(view.tier)) return false
  return scope.personas === 'all' || scope.personas.includes(view.ownerPubkey)
}

/**
 * Parse a decrypted grant envelope. A structurally bad envelope — including a `publishedAt` that is not
 * a non-negative safe integer (`1e400` parses as `Infinity`) — is null. Individually invalid contacts,
 * and contacts outside the envelope's own `scope` (wrong tier, or an owner persona not listed), are
 * dropped. At most `GRANT_CONTACTS_CAP` contacts are read. The returned `scope` is a projection
 * (unknown keys dropped); display text is control/bidi-stripped.
 */
export function parseGrantEnvelope(json: string): GrantEnvelope | null {
  let raw: unknown
  try { raw = JSON.parse(json) } catch { return null }
  if (typeof raw !== 'object' || raw === null) return null
  const p = raw as Record<string, unknown>
  if (p.v !== 1) return null
  const scope = parseScope(p.scope)
  if (!scope) return null
  if (!isUnixSeconds(p.publishedAt)) return null
  if (!Array.isArray(p.contacts)) return null
  const contacts: GrantContactView[] = []
  for (const item of p.contacts.slice(0, GRANT_CONTACTS_CAP)) {
    const v = parseView(item)
    if (v && inScope(v, scope)) contacts.push(v)
  }
  const env: GrantEnvelope = { v: 1, scope, contacts, publishedAt: p.publishedAt }
  if (p.revoked === true) env.revoked = true
  return env
}

// Companion data rail — the wire envelope shared by signet-app (sharer) and an
// owner-controlled companion app (consumer). See signet-plans
// 2026-07-17-companion-data-rail-design.md.
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

export function buildGrantEnvelope(
  scope: GrantScope,
  views: GrantContactView[],
  publishedAt: number,
  opts?: { revoked?: true },
): string {
  const env: GrantEnvelope = { v: 1, scope, contacts: views, publishedAt }
  if (opts?.revoked) env.revoked = true
  return JSON.stringify(env)
}

function isValidScope(s: unknown): s is GrantScope {
  if (typeof s !== 'object' || s === null) return false
  const o = s as Record<string, unknown>
  if (!Array.isArray(o.tiers) || o.tiers.some(t => !TIERS.includes(t as never))) return false
  if (o.personas !== 'all') {
    if (!Array.isArray(o.personas) || o.personas.some(p => typeof p !== 'string' || !HEX64.test(p))) return false
  }
  return true
}

function parseView(item: unknown): GrantContactView | null {
  if (typeof item !== 'object' || item === null) return null
  const c = item as Record<string, unknown>
  if (typeof c.pubkey !== 'string' || !HEX64.test(c.pubkey)) return null
  if (typeof c.ownerPubkey !== 'string' || !HEX64.test(c.ownerPubkey)) return null
  if (!TIERS.includes(c.tier as never)) return null
  if (typeof c.addedAt !== 'number') return null
  const view: GrantContactView = {
    pubkey: c.pubkey, ownerPubkey: c.ownerPubkey,
    tier: c.tier as GrantContactView['tier'], addedAt: c.addedAt,
  }
  if (typeof c.displayName === 'string') view.displayName = c.displayName.slice(0, 200)
  if (c.tier === 'kin' && typeof c.relationship === 'string' && KIN_RELS.includes(c.relationship)) {
    view.relationship = c.relationship as GrantContactView['relationship']
  }
  if (c.tier === 'ken' && typeof c.nip05 === 'string') view.nip05 = c.nip05.slice(0, 200)
  return view
}

export function parseGrantEnvelope(json: string): GrantEnvelope | null {
  let raw: unknown
  try { raw = JSON.parse(json) } catch { return null }
  if (typeof raw !== 'object' || raw === null) return null
  const p = raw as Record<string, unknown>
  if (p.v !== 1) return null
  if (!isValidScope(p.scope)) return null
  if (typeof p.publishedAt !== 'number') return null
  if (!Array.isArray(p.contacts)) return null
  const contacts: GrantContactView[] = []
  for (const item of p.contacts) {
    const v = parseView(item)
    if (v) contacts.push(v)
  }
  const env: GrantEnvelope = { v: 1, scope: p.scope, contacts, publishedAt: p.publishedAt }
  if (p.revoked === true) env.revoked = true
  return env
}

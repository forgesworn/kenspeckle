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

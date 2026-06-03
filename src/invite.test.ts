// kindred ./invite — tests.
//
// Two surfaces under one subpath:
//   (1) JoinInvite — a "come join this game" token. The inviter signs a canonical string over the
//       (namespace, serverId, inviterPubkey, nonce, expiresAt) tuple with @noble schnorr (a
//       CUSTOM-payload sig, not a Nostr event), and an invitee verifies + expiry-checks it before
//       acting. The sig binds the exact field values, so a free-form `serverId` containing colons is
//       safe here (the canonical string is only ever RECOMPUTED from the parsed structured fields —
//       it is never the sole carrier, unlike a capability whose string IS the wire).
//   (2) verifyBondAttestation — single-attestation anti-sybil brick (spec §9.2). Verifies ONE real
//       kindred-bond attestation (the kind-31000 event K-4's `buildBondAttestation` builds + the
//       caller finalizes) and returns the attester + subject. NO graph traversal, NO counting — the
//       consuming app does distinct-human counting over many of these.
//
// The bond-attestation round-trip is THE key test: it builds via `buildBondAttestation` (K-4) and
// finalizes, proving `verifyBondAttestation` parses the REAL nostr-attestations tag shape — not a
// guessed one. Tamper tests use a wire-shaped JSON clone: `finalizeEvent` returns a `VerifiedEvent`
// carrying nostr-tools' enumerable `verifiedSymbol: true` cache, which `verifyEvent` short-circuits
// on; mutating the original (or an object-spread of it) would copy that stale `true` and produce a
// FALSE GREEN. `JSON.parse(JSON.stringify(ev))` drops the symbol so tampering genuinely re-verifies.

import { describe, it, expect } from 'vitest'
import { schnorr } from '@noble/curves/secp256k1.js'
import { bytesToHex, hexToBytes } from '@noble/hashes/utils.js'
import { finalizeEvent, generateSecretKey, getPublicKey } from 'nostr-tools/pure'
import { buildBondAttestation } from './bond.js'
import { buildJoinInvite, parseJoinInvite, serializeJoinInvite, verifyBondAttestation } from './invite.js'
import type { JoinInvite, NostrEvent } from './types.js'

// --- Fixtures -------------------------------------------------------------------------------------

const NAMESPACE = 'com.example.game'
const SERVER_ID = 'play.example.com'
// A free-form serverId that contains colons — proves colon-in-serverId is unambiguous (the canonical
// string is recomputed from parsed fields, never the sole carrier).
const COLON_SERVER_ID = 'play.example.com:7777:eu-west'
const NONCE = 'deadbeefcafebabe' // even-length lowercase hex

/** A fresh real keypair: 32-byte secret + its 64-hex x-only pubkey (matches schnorr.getPublicKey). */
function freshInviter(): { privHex: string; pubHex: string } {
  const sk = generateSecretKey()
  return { privHex: bytesToHex(sk), pubHex: getPublicKey(sk) }
}

/** Serialize a JoinInvite object to wire bytes the way a consumer would (build→object, then encode).
 *  `buildJoinInvite` returns the OBJECT; the transport (QR/URL) carries the JSON; `parseJoinInvite`
 *  takes bytes. `serializeJoinInvite` is the kit-provided symmetry helper (the consumer no longer
 *  hand-rolls `TextEncoder().encode(JSON.stringify(...))`); the round-trip is build → serialize →
 *  parse. */
function toWireBytes(invite: JoinInvite): Uint8Array {
  return serializeJoinInvite(invite)
}

/** Build a real, signed kind-31000 kindred-bond attestation over `subjectPubHex`, signed by `sk`. */
function finalizedBondAttestation(subjectPubHex: string, sk: Uint8Array): NostrEvent {
  const template = buildBondAttestation({ subjectPubHex })
  return finalizeEvent({ ...template, created_at: Math.floor(Date.now() / 1000) }, sk) as NostrEvent
}

/**
 * Model an event as it would arrive FROM THE WIRE: plain JSON, no in-process `verifiedSymbol` cache.
 * Mutating this re-verifies for real (the stale `true` cache on the original would be a false green).
 */
function tamperedFromWire(ev: NostrEvent, mutate: (e: Record<string, unknown>) => void): NostrEvent {
  const wire = JSON.parse(JSON.stringify(ev)) as Record<string, unknown>
  mutate(wire)
  return wire as unknown as NostrEvent
}

// --- JoinInvite: build → serialize → parse round-trip ---------------------------------------------

describe('serializeJoinInvite — the build/parse symmetry helper', () => {
  it('produces exactly `TextEncoder().encode(JSON.stringify(invite))` (canonical wire bytes)', () => {
    const { privHex, pubHex } = freshInviter()
    const invite = buildJoinInvite(
      { namespace: NAMESPACE, serverId: SERVER_ID, inviterPubkey: pubHex, nonce: NONCE },
      privHex,
    )
    const expected = new TextEncoder().encode(JSON.stringify(invite))
    expect(serializeJoinInvite(invite)).toEqual(expected)
  })

  it('build → serialize → parse round-trips deep-equal (symmetry: no hand-rolled encode needed)', () => {
    const { privHex, pubHex } = freshInviter()
    const expiresAt = Math.floor(Date.now() / 1000) + 3600
    const invite = buildJoinInvite(
      { namespace: NAMESPACE, serverId: COLON_SERVER_ID, inviterPubkey: pubHex, nonce: NONCE, expiresAt },
      privHex,
    )
    const parsed = parseJoinInvite(serializeJoinInvite(invite), expiresAt - 1)
    expect(parsed).toEqual(invite)
  })
})

describe('buildJoinInvite / parseJoinInvite — signed invite round-trip', () => {
  it('round-trips: build → wire bytes → parse deep-equals the invite and the sig verifies', () => {
    const { privHex, pubHex } = freshInviter()
    const invite = buildJoinInvite(
      { namespace: NAMESPACE, serverId: SERVER_ID, inviterPubkey: pubHex, nonce: NONCE },
      privHex,
    )
    expect(invite.v).toBe(1)
    expect(invite.sig).toMatch(/^[0-9a-f]{128}$/) // 64-byte schnorr sig
    expect(invite.inviterPubkey).toBe(pubHex)

    const parsed = parseJoinInvite(toWireBytes(invite))
    expect(parsed).toEqual(invite) // deep-equal: every field round-trips
  })

  it('round-trips an invite with an expiresAt and a colon-bearing serverId', () => {
    const { privHex, pubHex } = freshInviter()
    const expiresAt = Math.floor(Date.now() / 1000) + 3600
    const invite = buildJoinInvite(
      { namespace: NAMESPACE, serverId: COLON_SERVER_ID, inviterPubkey: pubHex, nonce: NONCE, expiresAt },
      privHex,
    )
    // injected `now` strictly before expiry → parses cleanly.
    const parsed = parseJoinInvite(toWireBytes(invite), expiresAt - 1)
    expect(parsed).toEqual(invite)
    expect(parsed.serverId).toBe(COLON_SERVER_ID)
    expect(parsed.expiresAt).toBe(expiresAt)
  })

  it('lowercase-normalizes hex fields on parse (uppercase pubkey/nonce in JSON → lowercased out)', () => {
    const { privHex, pubHex } = freshInviter()
    const invite = buildJoinInvite(
      { namespace: NAMESPACE, serverId: SERVER_ID, inviterPubkey: pubHex, nonce: NONCE },
      privHex,
    )
    // Uppercase the hex fields in the wire JSON; the recomputed digest + sig must still verify because
    // the canonical string lowercases, and the parsed output is normalized.
    const wire = JSON.parse(JSON.stringify(invite)) as JoinInvite
    wire.inviterPubkey = wire.inviterPubkey.toUpperCase()
    wire.nonce = wire.nonce.toUpperCase()
    wire.sig = wire.sig.toUpperCase()
    const parsed = parseJoinInvite(new TextEncoder().encode(JSON.stringify(wire)))
    expect(parsed.inviterPubkey).toBe(pubHex) // lowercased
    expect(parsed.nonce).toBe(NONCE)
    expect(parsed.sig).toBe(invite.sig) // lowercased back
  })
})

// --- JoinInvite: signature rejection --------------------------------------------------------------

describe('parseJoinInvite — signature verification', () => {
  it('throws on a tampered namespace (sig no longer binds the canonical string)', () => {
    const { privHex, pubHex } = freshInviter()
    const invite = buildJoinInvite(
      { namespace: NAMESPACE, serverId: SERVER_ID, inviterPubkey: pubHex, nonce: NONCE },
      privHex,
    )
    const wire = JSON.parse(JSON.stringify(invite)) as JoinInvite
    wire.namespace = 'com.evil.swap' // tamper a signed field
    expect(() => parseJoinInvite(new TextEncoder().encode(JSON.stringify(wire)))).toThrow(/bad signature/)
  })

  it('throws on a tampered serverId', () => {
    const { privHex, pubHex } = freshInviter()
    const invite = buildJoinInvite(
      { namespace: NAMESPACE, serverId: SERVER_ID, inviterPubkey: pubHex, nonce: NONCE },
      privHex,
    )
    const wire = JSON.parse(JSON.stringify(invite)) as JoinInvite
    wire.serverId = 'evil.example.com'
    expect(() => parseJoinInvite(new TextEncoder().encode(JSON.stringify(wire)))).toThrow(/bad signature/)
  })

  it('throws when the inviterPubkey is swapped to a different valid key (sig was over the original)', () => {
    const { privHex, pubHex } = freshInviter()
    const other = freshInviter()
    const invite = buildJoinInvite(
      { namespace: NAMESPACE, serverId: SERVER_ID, inviterPubkey: pubHex, nonce: NONCE },
      privHex,
    )
    const wire = JSON.parse(JSON.stringify(invite)) as JoinInvite
    wire.inviterPubkey = other.pubHex // a valid but wrong key
    expect(() => parseJoinInvite(new TextEncoder().encode(JSON.stringify(wire)))).toThrow(/bad signature/)
  })
})

// --- JoinInvite: expiry ---------------------------------------------------------------------------

describe('parseJoinInvite — expiry enforcement', () => {
  it('throws "expired" when now > expiresAt (injected clock)', () => {
    const { privHex, pubHex } = freshInviter()
    const expiresAt = 1_700_000_000
    const invite = buildJoinInvite(
      { namespace: NAMESPACE, serverId: SERVER_ID, inviterPubkey: pubHex, nonce: NONCE, expiresAt },
      privHex,
    )
    expect(() => parseJoinInvite(toWireBytes(invite), expiresAt + 1)).toThrow(/expired/)
  })

  it('accepts when now === expiresAt (boundary: expiry is exclusive — not yet past)', () => {
    const { privHex, pubHex } = freshInviter()
    const expiresAt = 1_700_000_000
    const invite = buildJoinInvite(
      { namespace: NAMESPACE, serverId: SERVER_ID, inviterPubkey: pubHex, nonce: NONCE, expiresAt },
      privHex,
    )
    expect(() => parseJoinInvite(toWireBytes(invite), expiresAt)).not.toThrow()
  })

  it('accepts when not yet expired (now < expiresAt)', () => {
    const { privHex, pubHex } = freshInviter()
    const expiresAt = 1_700_000_000
    const invite = buildJoinInvite(
      { namespace: NAMESPACE, serverId: SERVER_ID, inviterPubkey: pubHex, nonce: NONCE, expiresAt },
      privHex,
    )
    expect(parseJoinInvite(toWireBytes(invite), expiresAt - 1)).toEqual(invite)
  })

  it('an invite WITHOUT expiresAt never expires (no expiry field → no expiry check)', () => {
    const { privHex, pubHex } = freshInviter()
    const invite = buildJoinInvite(
      { namespace: NAMESPACE, serverId: SERVER_ID, inviterPubkey: pubHex, nonce: NONCE },
      privHex,
    )
    expect(invite.expiresAt).toBeUndefined()
    // even with a far-future injected clock, no expiresAt means no rejection.
    expect(() => parseJoinInvite(toWireBytes(invite), 9_999_999_999)).not.toThrow()
  })
})

// --- JoinInvite: size + malformed guards ----------------------------------------------------------

describe('parseJoinInvite — size + malformed guards', () => {
  it('throws when the blob exceeds 8192 bytes (size cap is checked before parse)', () => {
    const oversized = new Uint8Array(8193)
    expect(() => parseJoinInvite(oversized)).toThrow(/too large/)
  })

  it('throws on non-JSON bytes (no raw SyntaxError leak)', () => {
    const garbage = new TextEncoder().encode('not json at all {{{')
    expect(() => parseJoinInvite(garbage)).toThrow(/malformed JSON/)
  })

  it('throws when v !== 1', () => {
    const { privHex, pubHex } = freshInviter()
    const invite = buildJoinInvite(
      { namespace: NAMESPACE, serverId: SERVER_ID, inviterPubkey: pubHex, nonce: NONCE },
      privHex,
    )
    const wire = { ...JSON.parse(JSON.stringify(invite)), v: 2 }
    expect(() => parseJoinInvite(new TextEncoder().encode(JSON.stringify(wire)))).toThrow(/version/)
  })

  it('throws when inviterPubkey is not 64 hex', () => {
    const { privHex, pubHex } = freshInviter()
    const invite = buildJoinInvite(
      { namespace: NAMESPACE, serverId: SERVER_ID, inviterPubkey: pubHex, nonce: NONCE },
      privHex,
    )
    const wire = { ...JSON.parse(JSON.stringify(invite)), inviterPubkey: 'nothex' }
    expect(() => parseJoinInvite(new TextEncoder().encode(JSON.stringify(wire)))).toThrow(/inviterPubkey/)
  })

  it('throws when nonce is not hex', () => {
    const { privHex, pubHex } = freshInviter()
    const invite = buildJoinInvite(
      { namespace: NAMESPACE, serverId: SERVER_ID, inviterPubkey: pubHex, nonce: NONCE },
      privHex,
    )
    const wire = { ...JSON.parse(JSON.stringify(invite)), nonce: 'zzzz' }
    expect(() => parseJoinInvite(new TextEncoder().encode(JSON.stringify(wire)))).toThrow(/nonce/)
  })

  it('throws when sig is not 128 hex', () => {
    const { privHex, pubHex } = freshInviter()
    const invite = buildJoinInvite(
      { namespace: NAMESPACE, serverId: SERVER_ID, inviterPubkey: pubHex, nonce: NONCE },
      privHex,
    )
    const wire = { ...JSON.parse(JSON.stringify(invite)), sig: 'ab'.repeat(10) } // too short
    expect(() => parseJoinInvite(new TextEncoder().encode(JSON.stringify(wire)))).toThrow(/sig/)
  })

  it('throws when namespace is empty', () => {
    const { privHex, pubHex } = freshInviter()
    const invite = buildJoinInvite(
      { namespace: NAMESPACE, serverId: SERVER_ID, inviterPubkey: pubHex, nonce: NONCE },
      privHex,
    )
    const wire = { ...JSON.parse(JSON.stringify(invite)), namespace: '' }
    expect(() => parseJoinInvite(new TextEncoder().encode(JSON.stringify(wire)))).toThrow(/namespace/)
  })

  it('throws when expiresAt is present but not a finite number', () => {
    const { privHex, pubHex } = freshInviter()
    const invite = buildJoinInvite(
      { namespace: NAMESPACE, serverId: SERVER_ID, inviterPubkey: pubHex, nonce: NONCE },
      privHex,
    )
    const wire = { ...JSON.parse(JSON.stringify(invite)), expiresAt: 'soon' }
    expect(() => parseJoinInvite(new TextEncoder().encode(JSON.stringify(wire)))).toThrow(/expiresAt/)
  })
})

// --- buildJoinInvite: input validation ------------------------------------------------------------

describe('buildJoinInvite — input validation', () => {
  it('throws when inviterPrivHex is not 64 hex', () => {
    const { pubHex } = freshInviter()
    expect(() =>
      buildJoinInvite(
        { namespace: NAMESPACE, serverId: SERVER_ID, inviterPubkey: pubHex, nonce: NONCE },
        'nothex',
      ),
    ).toThrow(/[Pp]riv/)
  })

  it('throws when inviterPubkey is not 64 hex', () => {
    const { privHex } = freshInviter()
    expect(() =>
      buildJoinInvite(
        { namespace: NAMESPACE, serverId: SERVER_ID, inviterPubkey: 'nothex', nonce: NONCE },
        privHex,
      ),
    ).toThrow(/inviterPubkey/)
  })

  it('throws when nonce is not hex', () => {
    const { privHex, pubHex } = freshInviter()
    expect(() =>
      buildJoinInvite(
        { namespace: NAMESPACE, serverId: SERVER_ID, inviterPubkey: pubHex, nonce: 'zz' },
        privHex,
      ),
    ).toThrow(/nonce/)
  })

  it('throws when namespace or serverId is empty', () => {
    const { privHex, pubHex } = freshInviter()
    expect(() =>
      buildJoinInvite({ namespace: '', serverId: SERVER_ID, inviterPubkey: pubHex, nonce: NONCE }, privHex),
    ).toThrow(/namespace/)
    expect(() =>
      buildJoinInvite({ namespace: NAMESPACE, serverId: '', inviterPubkey: pubHex, nonce: NONCE }, privHex),
    ).toThrow(/serverId/)
  })

  it('throws when inviterPubkey does not match the public key derived from inviterPrivHex', () => {
    const { privHex } = freshInviter()
    const other = freshInviter()
    // A caller must not mint an invite for an inviter key they do not control.
    expect(() =>
      buildJoinInvite(
        { namespace: NAMESPACE, serverId: SERVER_ID, inviterPubkey: other.pubHex, nonce: NONCE },
        privHex,
      ),
    ).toThrow(/does not match|mismatch/)
  })
})

// --- verifyBondAttestation: THE key round-trip ----------------------------------------------------

describe('verifyBondAttestation — single-attestation verification (spec §9.2)', () => {
  it('round-trips a real finalized kindred-bond attestation: valid + attester + subject', () => {
    const subject = 'cd'.repeat(32)
    const sk = generateSecretKey()
    const attesterPub = getPublicKey(sk)
    const finalized = finalizedBondAttestation(subject, sk)

    // Wire-clone to drop the verifiedSymbol cache so verifyEvent actually re-checks the signature.
    const wire = JSON.parse(JSON.stringify(finalized)) as NostrEvent
    const result = verifyBondAttestation(wire)
    expect(result).toEqual({ ok: true, attesterPubHex: attesterPub, subjectPubHex: subject })
  })

  it('rejects a wrong-kind event (not 31000)', () => {
    const sk = generateSecretKey()
    const ev = finalizeEvent(
      { kind: 1, tags: [['p', 'cd'.repeat(32)]], content: '', created_at: Math.floor(Date.now() / 1000) },
      sk,
    ) as NostrEvent
    const wire = JSON.parse(JSON.stringify(ev)) as NostrEvent
    expect(verifyBondAttestation(wire)).toEqual({ ok: false })
  })

  it('rejects a tampered attestation whose signature no longer verifies', () => {
    const sk = generateSecretKey()
    const finalized = finalizedBondAttestation('cd'.repeat(32), sk)
    // Tamper the content on a wire-clone (symbol-free) so verifyEvent genuinely fails the sig check.
    const tampered = tamperedFromWire(finalized, (e) => {
      e.content = 'tampered-after-signing'
    })
    expect(verifyBondAttestation(tampered)).toEqual({ ok: false })
  })

  it('rejects a kind-31000 event missing the kindred-bond type tag', () => {
    const sk = generateSecretKey()
    // A real, correctly-signed kind-31000 event but with NO ["type","kindred-bond"] tag.
    const ev = finalizeEvent(
      {
        kind: 31000,
        tags: [['p', 'cd'.repeat(32)]], // p-tag present, but no type tag
        content: '',
        created_at: Math.floor(Date.now() / 1000),
      },
      sk,
    ) as NostrEvent
    const wire = JSON.parse(JSON.stringify(ev)) as NostrEvent
    expect(verifyBondAttestation(wire)).toEqual({ ok: false })
  })

  it('rejects a kind-31000 kindred-bond event missing the subject p-tag', () => {
    const sk = generateSecretKey()
    const ev = finalizeEvent(
      {
        kind: 31000,
        tags: [['type', 'kindred-bond']], // type present, but no p-tag subject
        content: '',
        created_at: Math.floor(Date.now() / 1000),
      },
      sk,
    ) as NostrEvent
    const wire = JSON.parse(JSON.stringify(ev)) as NostrEvent
    expect(verifyBondAttestation(wire)).toEqual({ ok: false })
  })

  it('rejects an event whose type tag is not exactly "kindred-bond" (e.g. a different attestation)', () => {
    const sk = generateSecretKey()
    const ev = finalizeEvent(
      {
        kind: 31000,
        tags: [
          ['type', 'some-other-attestation'],
          ['p', 'cd'.repeat(32)],
        ],
        content: '',
        created_at: Math.floor(Date.now() / 1000),
      },
      sk,
    ) as NostrEvent
    const wire = JSON.parse(JSON.stringify(ev)) as NostrEvent
    expect(verifyBondAttestation(wire)).toEqual({ ok: false })
  })
})

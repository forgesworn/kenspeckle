// kindred ./bond — tests. The migration-vector test (frozen ECDH secret) is THE gate: if it
// stops matching `fd2644…26f9`, the byte-exact-with-signet-protocol construction has drifted and
// every migrated contact's verification words break. Do NOT change the expected value to make it
// pass — debug the construction (spec §5.2, K-4).

import { describe, it, expect } from 'vitest'
import { secp256k1 } from '@noble/curves/secp256k1.js'
import {
  deriveBondSecret,
  bondWords,
  verifyBondWord,
  buildBondAttestation,
  retractBondAssertion,
  KINDRED_BOND_NAMESPACE,
} from './bond.js'
import type { BondAssertion } from './types.js'

// A fixed, valid secp256k1 keypair-derived secret for the word/attestation tests (any 32-byte hex).
const SECRET = 'fd264454c8f37c9c4b000f0672399b9c76011de71f489fd8a043e25e558226f9'
// Two distinct, valid 64-hex x-only pubkeys (the migration-vector pubkeys — known on-curve).
const PUB_A = '4f355bdcb7cc0af728ef3cceb9615d90684bb5b2ca5f859ab0f0b704075871aa'
const PUB_B = '466d7fcae563e5cb09a0d1870bb580344804617879a14949cf22285f1bae3f27'

describe('deriveBondSecret — byte-exact ECDH with signet-protocol', () => {
  it('reproduces the frozen signet-protocol bond secret (migration vector)', () => {
    const privA = '11'.repeat(32),
      privB = '22'.repeat(32)
    const pubA = '4f355bdcb7cc0af728ef3cceb9615d90684bb5b2ca5f859ab0f0b704075871aa'
    const pubB = '466d7fcae563e5cb09a0d1870bb580344804617879a14949cf22285f1bae3f27'
    const expected = 'fd264454c8f37c9c4b000f0672399b9c76011de71f489fd8a043e25e558226f9'
    // self-validate the vector's pubkeys derive from the privs (x-only):
    const xOnly = (p: string) =>
      secp256k1.Point.BASE.multiply(BigInt('0x' + p)).toAffine().x.toString(16).padStart(64, '0')
    expect(xOnly(privA)).toBe(pubA)
    expect(xOnly(privB)).toBe(pubB)
    expect(deriveBondSecret(privA, pubB)).toBe(expected)
    expect(deriveBondSecret(privB, pubA)).toBe(expected) // symmetric agreement (only x hashed)
  })

  it('is case-insensitive on inputs (uppercase priv/pub normalize to the same secret)', () => {
    const privA = '11'.repeat(32)
    const lower = deriveBondSecret(privA, PUB_B)
    const upper = deriveBondSecret(privA.toUpperCase(), PUB_B.toUpperCase())
    expect(upper).toBe(lower)
  })

  it('rejects malformed private keys (bad hex / wrong length)', () => {
    expect(() => deriveBondSecret('xyz', PUB_B)).toThrow(/priv must be 64 hex/)
    expect(() => deriveBondSecret('11'.repeat(31), PUB_B)).toThrow(/priv must be 64 hex/)
    expect(() => deriveBondSecret('11'.repeat(32) + 'ff', PUB_B)).toThrow(/priv must be 64 hex/)
  })

  it('rejects malformed pubkeys (bad hex / wrong length)', () => {
    expect(() => deriveBondSecret('11'.repeat(32), 'nothex')).toThrow(/pubkey must be 64 hex/)
    expect(() => deriveBondSecret('11'.repeat(32), 'ab'.repeat(31))).toThrow(/pubkey must be 64 hex/)
  })

  it('rejects a pubkey that is well-formed hex but not on the curve', () => {
    // x = 7 has no even-y point on secp256k1 → Point.fromHex('02'+x) throws.
    const notOnCurve = '07'.padStart(64, '0')
    expect(() => deriveBondSecret('11'.repeat(32), notOnCurve)).toThrow(/invalid curve point/)
  })

  it('rejects non-canonical scalars (0 and >= N)', () => {
    const zero = '00'.repeat(32)
    expect(() => deriveBondSecret(zero, PUB_B)).toThrow(/non-canonical scalar/)
    // N (the curve order) is exactly out of range — scalar must be in [1, N-1].
    const N = secp256k1.Point.Fn.ORDER
    const nHex = N.toString(16).padStart(64, '0')
    expect(() => deriveBondSecret(nHex, PUB_B)).toThrow(/non-canonical scalar/)
    // N + 1 is also out of range.
    const nPlus1Hex = (N + 1n).toString(16).padStart(64, '0')
    expect(() => deriveBondSecret(nPlus1Hex, PUB_B)).toThrow(/non-canonical scalar/)
  })
})

describe('bondWords — directional spoken-token pair', () => {
  it('returns two distinct, non-empty words for a counter', () => {
    const { mine, theirs } = bondWords(SECRET, PUB_A, PUB_B, 0)
    expect(typeof mine).toBe('string')
    expect(typeof theirs).toBe('string')
    expect(mine.length).toBeGreaterThan(0)
    expect(theirs.length).toBeGreaterThan(0)
    expect(mine).not.toBe(theirs) // directional: each party speaks a different word
  })

  it('both parties compute matching cross words (A.mine === B.theirs, A.theirs === B.mine)', () => {
    // A is the caller (own persona first); B is the caller (own persona first, args swapped).
    const A = bondWords(SECRET, PUB_A, PUB_B, 7)
    const B = bondWords(SECRET, PUB_B, PUB_A, 7)
    expect(A.mine).toBe(B.theirs)
    expect(A.theirs).toBe(B.mine)
  })

  it('rotates with the counter (different counters → different words)', () => {
    const c0 = bondWords(SECRET, PUB_A, PUB_B, 0)
    const c1 = bondWords(SECRET, PUB_A, PUB_B, 1)
    expect(c0.mine).not.toBe(c1.mine)
  })

  it('is order-independent in the underlying sort (caller may pass pubkeys in any order)', () => {
    // Sorting [a,b] inside bondWords means the SECRET-derived pair is keyed by lo/hi regardless of
    // the arg order; the caller's own pubkey just selects which role is "mine".
    const A = bondWords(SECRET, PUB_A, PUB_B, 3)
    const B = bondWords(SECRET, PUB_B, PUB_A, 3)
    // the SET of words is the same; only the mine/theirs labelling flips.
    expect(new Set([A.mine, A.theirs])).toEqual(new Set([B.mine, B.theirs]))
  })
})

describe('verifyBondWord — constant-time compare of the counterparty word', () => {
  it('returns valid for the spoken counterpart word', () => {
    // From A's seat: the counterparty (B) speaks A.theirs. A verifies it.
    const A = bondWords(SECRET, PUB_A, PUB_B, 11)
    expect(verifyBondWord(SECRET, PUB_A, PUB_B, 11, A.theirs)).toEqual({ status: 'valid' })
  })

  it('returns invalid for a wrong word', () => {
    expect(verifyBondWord(SECRET, PUB_A, PUB_B, 11, 'definitely-not-the-word')).toEqual({
      status: 'invalid',
    })
  })

  it('returns invalid when the wrong-direction word is spoken (mine, not theirs)', () => {
    // A speaking its OWN word back is the echo attack spoken-token defends against: must be invalid.
    const A = bondWords(SECRET, PUB_A, PUB_B, 11)
    expect(verifyBondWord(SECRET, PUB_A, PUB_B, 11, A.mine)).toEqual({ status: 'invalid' })
  })

  it('returns invalid for the right word at the wrong counter', () => {
    const A = bondWords(SECRET, PUB_A, PUB_B, 11)
    expect(verifyBondWord(SECRET, PUB_A, PUB_B, 12, A.theirs)).toEqual({ status: 'invalid' })
  })
})

describe('buildBondAttestation — kind-31000 via nostr-attestations', () => {
  it('returns a kind-31000 EventTemplate', () => {
    const tmpl = buildBondAttestation({ subjectPubHex: PUB_B })
    expect(tmpl.kind).toBe(31000)
    expect(Array.isArray(tmpl.tags)).toBe(true)
  })

  it('uses type "kindred-bond" (NOT the reserved "assertion") and does not throw', () => {
    expect(() => buildBondAttestation({ subjectPubHex: PUB_B })).not.toThrow()
    const tmpl = buildBondAttestation({ subjectPubHex: PUB_B })
    const typeTag = tmpl.tags.find((t) => t[0] === 'type')
    expect(typeTag).toBeDefined()
    expect(typeTag![1]).toBe('kindred-bond')
  })

  it('p-tags the subject pubkey', () => {
    const tmpl = buildBondAttestation({ subjectPubHex: PUB_B })
    const pTag = tmpl.tags.find((t) => t[0] === 'p')
    expect(pTag).toBeDefined()
    expect(pTag![1]).toBe(PUB_B)
  })

  it('carries an optional summary when provided', () => {
    const tmpl = buildBondAttestation({ subjectPubHex: PUB_B, summary: 'met at the village fete' })
    const summaryTag = tmpl.tags.find((t) => t[0] === 'summary')
    expect(summaryTag).toBeDefined()
    expect(summaryTag![1]).toBe('met at the village fete')
  })
})

describe('retractBondAssertion — NIP-09 kind-5', () => {
  it('returns kind 5 with an e-tag referencing assertion.mineId', () => {
    const assertion: BondAssertion = {
      mineId: 'ab'.repeat(32),
      relay: 'wss://relay.example',
      createdAt: 1_700_000_000,
    }
    const tmpl = retractBondAssertion(assertion)
    expect(tmpl.kind).toBe(5)
    expect(tmpl.content).toBe('')
    const eTag = tmpl.tags.find((t) => t[0] === 'e')
    expect(eTag).toBeDefined()
    expect(eTag![1]).toBe(assertion.mineId)
  })
})

describe('module surface', () => {
  it('exports the bond namespace constant', () => {
    expect(KINDRED_BOND_NAMESPACE).toBe('kindred:bond')
  })
})

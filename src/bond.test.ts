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

  it('rejects a malformed secretHex with a KIT-shaped error (not a raw spoken-token / @noble error)', () => {
    // `secretHex` must be the 64-hex shape `deriveBondSecret` emits. Without the guard, an odd-length
    // or non-hex secret leaks `deriveDirectionalPair`'s raw `hexToBytes: odd-length hex string` (or
    // similar) from inside spoken-token/@noble — an opaque error at the kindred boundary. The guard
    // surfaces a consistent `bondWords:` error instead. (verifyBondWord calls bondWords, so it's
    // covered transitively.)
    const ODD = 'abc' // odd-length hex → would raise the raw hexToBytes error
    const NONHEX = 'z'.repeat(64) // 64 chars but not hex
    const SHORT = 'ab'.repeat(8) // valid hex but only 16 bytes (not the 64-hex secret shape)
    for (const bad of [ODD, NONHEX, SHORT, '']) {
      expect(() => bondWords(bad, PUB_A, PUB_B, 0)).toThrow('bondWords: secret must be 64 hex chars')
    }
    // And it must NOT leak the raw spoken-token/@noble message.
    expect(() => bondWords(ODD, PUB_A, PUB_B, 0)).not.toThrow(/hexToBytes|odd-length/)
    // verifyBondWord routes through bondWords, so the same guard fires there.
    expect(() => verifyBondWord(ODD, PUB_A, PUB_B, 0, 'whatever')).toThrow(
      'bondWords: secret must be 64 hex chars',
    )
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
  it('returns ok:true for the spoken counterpart word', () => {
    // From A's seat: the counterparty (B) speaks A.theirs. A verifies it.
    const A = bondWords(SECRET, PUB_A, PUB_B, 11)
    expect(verifyBondWord(SECRET, PUB_A, PUB_B, 11, A.theirs)).toEqual({ ok: true })
  })

  it('returns ok:false for a wrong word', () => {
    expect(verifyBondWord(SECRET, PUB_A, PUB_B, 11, 'definitely-not-the-word')).toEqual({
      ok: false,
    })
  })

  it('returns ok:false when the wrong-direction word is spoken (mine, not theirs)', () => {
    // A speaking its OWN word back is the echo attack spoken-token defends against: must be ok:false.
    const A = bondWords(SECRET, PUB_A, PUB_B, 11)
    expect(verifyBondWord(SECRET, PUB_A, PUB_B, 11, A.mine)).toEqual({ ok: false })
  })

  it('returns ok:false for the right word at the wrong counter', () => {
    const A = bondWords(SECRET, PUB_A, PUB_B, 11)
    expect(verifyBondWord(SECRET, PUB_A, PUB_B, 12, A.theirs)).toEqual({ ok: false })
  })
})

// --- signet-me compatibility opts (migration continuity) ------------------------------------------
// signet-app's `signet-me` derives words with namespace 'signet:me' + a ±tolerance counter window.
// The `namespace` opt lets a migrated kindred contact reproduce those exact words to cross-verify with
// a peer who hasn't migrated yet (each seat passes its OWN pubkey first). We verify the opt behaviour
// IN ISOLATION (no signet/signet-protocol dependency) — the param mapping itself was confirmed by
// reading signet/src/signet-me.ts.
//
// WHY THERE IS NO role-order knob (verified against the installed spoken-token): `deriveDirectionalPair`
// keys each word on `namespace + '\0' + role` — i.e. PURELY on the role STRING, independent of the
// role's POSITION in the tuple. So `pair[X]` is identical whether roles are `[X,Y]` or `[Y,X]`, and
// `namespace` is the only knob that changes the words; signet-me compat is achieved by `namespace`
// alone. NB: PUB_A ('4f35…') > PUB_B ('466d…').

describe('bondWords / verifyBondWord — signet-me compat opts', () => {
  it('a different namespace yields different words for the same (secret, pubkeys, counter)', () => {
    const def = bondWords(SECRET, PUB_A, PUB_B, 4)
    const signetMe = bondWords(SECRET, PUB_A, PUB_B, 4, { namespace: 'signet:me' })
    // domain separation: changing only the namespace must change both directional words.
    expect(signetMe.mine).not.toBe(def.mine)
    expect(signetMe.theirs).not.toBe(def.theirs)
  })

  it("two seats reproduce signet-me's cross words with { namespace: 'signet:me' } (each passes own pub first)", () => {
    const opts = { namespace: 'signet:me' }
    // A's seat (A passes itself first); B's seat (B passes itself first) — signet-me's [myPub, theirPub].
    const A = bondWords(SECRET, PUB_A, PUB_B, 9, opts)
    const B = bondWords(SECRET, PUB_B, PUB_A, 9, opts)
    expect(A.mine).toBe(B.theirs)
    expect(A.theirs).toBe(B.mine)
    expect(A.mine).not.toBe(A.theirs) // still directional
  })

  it('tolerance:1 accepts a word generated at counter-1 and counter+1', () => {
    const opts = { namespace: 'signet:me' }
    // The counterparty's word, as it would have been at the neighbouring counters.
    const prev = bondWords(SECRET, PUB_A, PUB_B, 99, opts).theirs
    const next = bondWords(SECRET, PUB_A, PUB_B, 101, opts).theirs
    const vopts = { ...opts, tolerance: 1 }
    // Window centre 100 ± 1 covers 99 and 101.
    expect(verifyBondWord(SECRET, PUB_A, PUB_B, 100, prev, vopts)).toEqual({ ok: true })
    expect(verifyBondWord(SECRET, PUB_A, PUB_B, 100, next, vopts)).toEqual({ ok: true })
  })

  it('tolerance:1 still rejects an unrelated word', () => {
    const vopts = { namespace: 'signet:me', tolerance: 1 }
    expect(verifyBondWord(SECRET, PUB_A, PUB_B, 100, 'definitely-not-the-word', vopts)).toEqual({
      ok: false,
    })
  })

  it('tolerance:1 rejects a word two counters away (outside the ±1 window)', () => {
    const opts = { namespace: 'signet:me' }
    const twoAway = bondWords(SECRET, PUB_A, PUB_B, 102, opts).theirs
    const vopts = { ...opts, tolerance: 1 }
    expect(verifyBondWord(SECRET, PUB_A, PUB_B, 100, twoAway, vopts)).toEqual({ ok: false })
  })

  it('default opts reproduce the existing behaviour (kindred:bond + exact counter)', () => {
    // Explicit default must equal the no-opts call — the additive param is backward-compatible.
    const noOpts = bondWords(SECRET, PUB_A, PUB_B, 7)
    const explicit = bondWords(SECRET, PUB_A, PUB_B, 7, { namespace: KINDRED_BOND_NAMESPACE })
    expect(explicit).toEqual(noOpts)
    // verifyBondWord with default opts (tolerance 0) matches only the exact counter.
    expect(verifyBondWord(SECRET, PUB_A, PUB_B, 7, noOpts.theirs)).toEqual({ ok: true })
    expect(verifyBondWord(SECRET, PUB_A, PUB_B, 7, noOpts.theirs, {})).toEqual({ ok: true })
    expect(verifyBondWord(SECRET, PUB_A, PUB_B, 8, noOpts.theirs)).toEqual({ ok: false })
  })

  it('verifyBondWord with signet-me opts accepts a word built with the matching bondWords opts', () => {
    // End-to-end: derive with the signet-me opts, verify with the SAME opts → ok.
    const opts = { namespace: 'signet:me' }
    const theirWord = bondWords(SECRET, PUB_A, PUB_B, 12, opts).theirs
    expect(verifyBondWord(SECRET, PUB_A, PUB_B, 12, theirWord, opts)).toEqual({ ok: true })
    // and the DEFAULT-opts verify rejects it (different namespace → different word).
    expect(verifyBondWord(SECRET, PUB_A, PUB_B, 12, theirWord)).toEqual({ ok: false })
  })
})

// The tolerance window re-derives the counterparty word at every counter in [counter-t, counter+t].
// A boundary counter (0 or 0xFFFFFFFF) plus a tolerance would push a candidate counter outside the
// valid uint32 range, and spoken-token's `counterBe32` throws a RangeError on such a counter. Since
// `verifyBondWord` returns `{ ok }` and MUST NOT throw on a valid-shaped call, the window (and the
// tolerance itself) are clamped fail-soft. (R5 review hardening.)
describe('verifyBondWord — tolerance window is clamped fail-soft (does not throw at boundaries)', () => {
  it('counter:0 + tolerance:1 does NOT throw and still checks counters 0 and 1', () => {
    // Without the [0, 0xFFFFFFFF] clamp this would probe counter -1 → counterBe32 RangeError.
    const at0 = bondWords(SECRET, PUB_A, PUB_B, 0).theirs
    const at1 = bondWords(SECRET, PUB_A, PUB_B, 1).theirs
    expect(() => verifyBondWord(SECRET, PUB_A, PUB_B, 0, at0, { tolerance: 1 })).not.toThrow()
    // counter 0 (the centre) matches:
    expect(verifyBondWord(SECRET, PUB_A, PUB_B, 0, at0, { tolerance: 1 })).toEqual({ ok: true })
    // counter 1 (the +1 edge, the only in-range neighbour) also matches → window 0 and 1 both checked:
    expect(verifyBondWord(SECRET, PUB_A, PUB_B, 0, at1, { tolerance: 1 })).toEqual({ ok: true })
    // a word from counter 2 (outside the clamped window [0,1]) is rejected:
    const at2 = bondWords(SECRET, PUB_A, PUB_B, 2).theirs
    expect(verifyBondWord(SECRET, PUB_A, PUB_B, 0, at2, { tolerance: 1 })).toEqual({ ok: false })
  })

  it('counter:0xFFFFFFFF + tolerance:1 does NOT throw and checks the top of the uint32 range', () => {
    // Without the clamp this would probe counter 0x100000000 → counterBe32 RangeError.
    const MAX = 0xffffffff
    const atMax = bondWords(SECRET, PUB_A, PUB_B, MAX).theirs
    const atPrev = bondWords(SECRET, PUB_A, PUB_B, MAX - 1).theirs
    expect(() => verifyBondWord(SECRET, PUB_A, PUB_B, MAX, atMax, { tolerance: 1 })).not.toThrow()
    expect(verifyBondWord(SECRET, PUB_A, PUB_B, MAX, atMax, { tolerance: 1 })).toEqual({ ok: true })
    // the MAX-1 edge (the only in-range neighbour) matches → window MAX-1 and MAX both checked:
    expect(verifyBondWord(SECRET, PUB_A, PUB_B, MAX, atPrev, { tolerance: 1 })).toEqual({ ok: true })
  })

  it('a huge tolerance is clamped to MAX_BOND_TOLERANCE (no unbounded loop, finishes fast)', () => {
    // If the window were NOT clamped, a tolerance of 1e9 would attempt ~2e9 re-derivations and either
    // hang or throw. Clamped to 10, this returns essentially instantly. We assert it returns promptly
    // AND that words OUTSIDE the ±10 clamped window are rejected (proving the window did not widen).
    const centre = 1_000_000
    const start = Date.now()
    const exact = bondWords(SECRET, PUB_A, PUB_B, centre).theirs
    expect(verifyBondWord(SECRET, PUB_A, PUB_B, centre, exact, { tolerance: 1e9 })).toEqual({ ok: true })
    // counter+10 is the edge of the clamped window → accepted; counter+11 is just outside → rejected.
    const edge = bondWords(SECRET, PUB_A, PUB_B, centre + 10).theirs
    const justOutside = bondWords(SECRET, PUB_A, PUB_B, centre + 11).theirs
    expect(verifyBondWord(SECRET, PUB_A, PUB_B, centre, edge, { tolerance: 1e9 })).toEqual({ ok: true })
    expect(verifyBondWord(SECRET, PUB_A, PUB_B, centre, justOutside, { tolerance: 1e9 })).toEqual({
      ok: false,
    })
    // Sanity: the clamp keeps the whole thing well under a second (an unbounded loop would not).
    expect(Date.now() - start).toBeLessThan(2000)
  })

  it('negative / NaN tolerance is treated as 0 (exact-counter match), never throws', () => {
    const exact = bondWords(SECRET, PUB_A, PUB_B, 50).theirs
    const neighbour = bondWords(SECRET, PUB_A, PUB_B, 51).theirs
    for (const bad of [-1, -1000, NaN, Number.POSITIVE_INFINITY, Number.NEGATIVE_INFINITY]) {
      expect(() => verifyBondWord(SECRET, PUB_A, PUB_B, 50, exact, { tolerance: bad })).not.toThrow()
      // tolerance coerced to 0 → only the exact counter matches.
      expect(verifyBondWord(SECRET, PUB_A, PUB_B, 50, exact, { tolerance: bad })).toEqual({ ok: true })
      expect(verifyBondWord(SECRET, PUB_A, PUB_B, 50, neighbour, { tolerance: bad })).toEqual({
        ok: false,
      })
    }
  })

  it('a fractional tolerance is truncated toward zero (1.9 → 1)', () => {
    const prev = bondWords(SECRET, PUB_A, PUB_B, 99).theirs
    const twoAway = bondWords(SECRET, PUB_A, PUB_B, 98).theirs
    // 1.9 truncates to 1 → window [99,101] covers 99 but not 98.
    expect(verifyBondWord(SECRET, PUB_A, PUB_B, 100, prev, { tolerance: 1.9 })).toEqual({ ok: true })
    expect(verifyBondWord(SECRET, PUB_A, PUB_B, 100, twoAway, { tolerance: 1.9 })).toEqual({
      ok: false,
    })
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

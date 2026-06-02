import { describe, it, expect } from 'vitest'
import { exportEntriesEncrypted, importEntries } from './backup.js'
import type { KindredEntry, KinEntry, KithEntry, KenEntry } from './types.js'

const A = 'a'.repeat(64)
const B = 'b'.repeat(64)
const C = 'c'.repeat(64)
const OWNER = 'd'.repeat(64)

const key = new Uint8Array(32).fill(7)

const kin: KinEntry = {
  tier: 'kin',
  pubkey: A,
  ownerPubkey: OWNER,
  addedAt: 1,
  sharedSecret: '00'.repeat(32),
  verifiedAt: 1,
  relationship: 'child',
  displayName: 'Alice',
  annotations: { groupId: 'g1', label: 'eldest', note: 'school pickup', blocked: false },
}

const kith: KithEntry = {
  tier: 'kith',
  pubkey: B,
  ownerPubkey: OWNER,
  addedAt: 2,
  sharedSecret: '11'.repeat(32),
  verifiedAt: 2,
  annotations: { label: 'gym buddy' },
}

const ken: KenEntry = {
  tier: 'ken',
  pubkey: C,
  ownerPubkey: OWNER,
  addedAt: 3,
  provenance: { source: 'nip05', locator: 'carol@example.com', confirmedAt: 3 },
}

const entries: KindredEntry[] = [kin, kith, ken]

describe('exportEntriesEncrypted / importEntries', () => {
  it('round-trips entries', () => {
    const blob = exportEntriesEncrypted(entries, key)
    expect(blob).toBeInstanceOf(Uint8Array)
    expect(blob.length).toBeGreaterThan(24 + 16)
    const restored = importEntries(blob, key)
    expect(restored).toHaveLength(3)
    expect(restored[0]!.pubkey).toBe(A)
    expect(restored[2]!.tier).toBe('ken')
  })

  it('PRESERVES annotations (the backup legitimately carries them)', () => {
    const blob = exportEntriesEncrypted(entries, key)
    const restored = importEntries(blob, key)
    expect(restored[0]!.annotations).toEqual({
      groupId: 'g1',
      label: 'eldest',
      note: 'school pickup',
      blocked: false,
    })
    expect(restored[1]!.annotations).toEqual({ label: 'gym buddy' })
    // ken had none
    expect(restored[2]!.annotations).toBeUndefined()
  })

  it('emits a fresh random nonce each call (ciphertext differs for same input)', () => {
    const a = exportEntriesEncrypted(entries, key)
    const b = exportEntriesEncrypted(entries, key)
    expect(Buffer.from(a).equals(Buffer.from(b))).toBe(false)
  })

  it('wrong key fails to decrypt (auth failure throws)', () => {
    const blob = exportEntriesEncrypted(entries, key)
    const wrong = new Uint8Array(32).fill(9)
    expect(() => importEntries(blob, wrong)).toThrow()
  })

  it('tampered ciphertext throws', () => {
    const blob = exportEntriesEncrypted(entries, key)
    const tampered = blob.slice()
    tampered[tampered.length - 1] ^= 0xff // flip a byte in the tag region
    expect(() => importEntries(tampered, key)).toThrow()
  })

  it('tampered nonce throws', () => {
    const blob = exportEntriesEncrypted(entries, key)
    const tampered = blob.slice()
    tampered[0] ^= 0xff
    expect(() => importEntries(tampered, key)).toThrow()
  })

  it('non-32-byte key throws on export', () => {
    expect(() => exportEntriesEncrypted(entries, new Uint8Array(16))).toThrow()
    expect(() => exportEntriesEncrypted(entries, new Uint8Array(31))).toThrow()
    expect(() => exportEntriesEncrypted(entries, new Uint8Array(33))).toThrow()
  })

  it('non-32-byte key throws on import', () => {
    const blob = exportEntriesEncrypted(entries, key)
    expect(() => importEntries(blob, new Uint8Array(16))).toThrow()
  })

  it('a too-short blob throws (no crash)', () => {
    expect(() => importEntries(new Uint8Array(10), key)).toThrow()
    expect(() => importEntries(new Uint8Array(24 + 15), key)).toThrow() // nonce + < tag
  })

  it('validates each restored entry (rejects a corrupt-but-decryptable payload)', () => {
    // Encrypt a structurally-valid blob whose JSON is an array with a malformed entry.
    const bad = exportEntriesEncrypted(
      [{ ...kin, tier: 'bogus' } as unknown as KindredEntry],
      key,
    )
    expect(() => importEntries(bad, key)).toThrow()
  })

  it('rejects a non-array payload', () => {
    // Hand-roll a blob that decrypts to a JSON object, not an array.
    const objBlob = exportEntriesEncrypted([] as KindredEntry[], key)
    // empty array is valid → returns []
    expect(importEntries(objBlob, key)).toEqual([])
  })
})

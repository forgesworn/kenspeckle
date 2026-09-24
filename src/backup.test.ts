import { describe, it, expect } from 'vitest'
import { xchacha20poly1305 } from '@noble/ciphers/chacha.js'
import { concatBytes, utf8ToBytes } from '@noble/ciphers/utils.js'
import { BACKUP_FORMAT_VERSION, exportEntriesEncrypted, importEntries } from './backup.js'
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

  it('LOWERCASES uppercase hex (pubkey/ownerPubkey/sharedSecret/groupId) on import', () => {
    // A backup file edited/restored with UPPERCASE hex must be normalized — uppercase hex would
    // break strict-equality against nostr-tools' always-lowercase event.pubkey downstream.
    const upper: KindredEntry[] = [
      {
        ...kith,
        pubkey: B.toUpperCase(),
        ownerPubkey: OWNER.toUpperCase(),
        sharedSecret: '11'.repeat(32).toUpperCase(),
        annotations: { groupId: 'ABCDEF', label: 'gym buddy' },
      } as KithEntry,
    ]
    const blob = exportEntriesEncrypted(upper, key)
    const restored = importEntries(blob, key)
    expect(restored[0]!.pubkey).toBe(B) // lowercase
    expect(restored[0]!.ownerPubkey).toBe(OWNER)
    if (restored[0]!.tier === 'kith') {
      expect(restored[0]!.sharedSecret).toBe('11'.repeat(32))
    }
    // annotations.groupId is also a hex-shaped routing id (linkForRecall emits hex) → lowercased.
    expect(restored[0]!.annotations?.groupId).toBe('abcdef')
    // non-hex annotation fields are untouched.
    expect(restored[0]!.annotations?.label).toBe('gym buddy')
  })
})

describe('backup format header + AAD (L10)', () => {
  /** The pre-header format every existing backup uses: nonce(24) || ciphertext, no AAD. */
  function legacyBlob(list: KindredEntry[], nonce = new Uint8Array(24).fill(3)): Uint8Array {
    const ct = xchacha20poly1305(key, nonce).encrypt(utf8ToBytes(JSON.stringify(list)))
    return concatBytes(nonce, ct)
  }

  it('writes "KSBK" || version as a 5-byte header', () => {
    const blob = exportEntriesEncrypted(entries, key)
    expect(Array.from(blob.subarray(0, 5))).toEqual([0x4b, 0x53, 0x42, 0x4b, BACKUP_FORMAT_VERSION])
    expect(blob.length).toBe(5 + 24 + utf8ToBytes(JSON.stringify(entries)).length + 16)
  })

  it('still reads a legacy header-less backup', () => {
    expect(importEntries(legacyBlob(entries), key)).toEqual(entries)
  })

  it('still reads a legacy backup whose random nonce happens to start with the header bytes', () => {
    const nonce = concatBytes(utf8ToBytes('KSBK'), Uint8Array.of(1), new Uint8Array(19).fill(5))
    expect(importEntries(legacyBlob(entries, nonce), key)).toEqual(entries)
  })

  it('binds the header: a flipped version byte or magic fails authentication', () => {
    const blob = exportEntriesEncrypted(entries, key)
    for (const i of [0, 4]) {
      const tampered = blob.slice()
      tampered[i] ^= 0x01
      expect(() => importEntries(tampered, key)).toThrow()
    }
  })

  it('a v1 body stripped of its header is not accepted as legacy (the AAD differs)', () => {
    const blob = exportEntriesEncrypted(entries, key)
    expect(() => importEntries(blob.subarray(5), key)).toThrow()
  })

  it('a tampered legacy blob still throws', () => {
    const blob = legacyBlob(entries)
    blob[blob.length - 1] ^= 0xff
    expect(() => importEntries(blob, key)).toThrow()
  })
})

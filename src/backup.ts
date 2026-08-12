// kenspeckle — encrypted self-backup (spec §6.7, §12.1).
//
// The user's own portable, AES-grade backup of their relationship roster. Sealed with
// XChaCha20-Poly1305 (`@noble/ciphers/chacha.js`), format `nonce(24) || ciphertext(+16 tag)`.
//
// Unlike the wire form (model.ts), this INCLUDES private annotations: it is the user's own
// encrypted copy, not a graph disclosure (§6.7). It never leaves the device unencrypted, and only
// the holder of the 32-byte key can read it. Decryption is authenticated — a wrong key or any
// tampered byte throws (Poly1305 tag failure), never silently returns garbage.

import { xchacha20poly1305 } from '@noble/ciphers/chacha.js'
// All byte helpers from @noble/ciphers/utils.js — note `bytesToUtf8` exists HERE, not in
// @noble/hashes/utils.js (which only ships the encode direction `utf8ToBytes`).
import { randomBytes, concatBytes, utf8ToBytes, bytesToUtf8 } from '@noble/ciphers/utils.js'
import type { KindredEntry } from './types.js'
import { validateEntryShape } from './validate.js'

const KEY_LEN = 32
const NONCE_LEN = 24
const TAG_LEN = 16

function requireKey(key: Uint8Array): void {
  if (key.length !== KEY_LEN) {
    throw new Error(`kenspeckle backup: key must be ${KEY_LEN} bytes, got ${key.length}`)
  }
}

/** Encrypt the roster (WITH annotations) under a 32-byte key. Returns `nonce(24) || ciphertext`.
 *  A fresh random 24-byte nonce is drawn per call, so identical input yields distinct blobs. */
export function exportEntriesEncrypted(entries: KindredEntry[], key: Uint8Array): Uint8Array {
  requireKey(key)
  const nonce = randomBytes(NONCE_LEN)
  const plaintext = utf8ToBytes(JSON.stringify(entries))
  const ct = xchacha20poly1305(key, nonce).encrypt(plaintext)
  return concatBytes(nonce, ct)
}

/** Decrypt + validate a backup blob. Throws on a wrong key / tamper (auth failure), a malformed
 *  blob (too short), or any structurally-invalid entry. Annotations ARE preserved. */
export function importEntries(blob: Uint8Array, key: Uint8Array): KindredEntry[] {
  requireKey(key)
  if (blob.length < NONCE_LEN + TAG_LEN) {
    throw new Error('kenspeckle backup: blob too short (need nonce + tag)')
  }
  const nonce = blob.subarray(0, NONCE_LEN)
  const ct = blob.subarray(NONCE_LEN)
  // Throws on authentication failure (wrong key or tampered ciphertext/nonce).
  const pt = xchacha20poly1305(key, nonce).decrypt(ct)

  let raw: unknown
  try {
    raw = JSON.parse(bytesToUtf8(pt))
  } catch {
    throw new Error('kenspeckle backup: decrypted payload is not valid JSON')
  }
  if (!Array.isArray(raw)) throw new Error('kenspeckle backup: payload must be a JSON array')
  // allowAnnotations=true: the backup legitimately carries private annotations (§6.7).
  return raw.map((e) => validateEntryShape(e, true))
}

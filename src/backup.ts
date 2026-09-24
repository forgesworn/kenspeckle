// kenspeckle — encrypted self-backup (spec §6.7, §12.1).
//
// The user's own portable, AES-grade backup of their relationship roster. Sealed with
// XChaCha20-Poly1305 (`@noble/ciphers/chacha.js`). Format (v1, PROTOCOL.md §12):
//
//   header(5) = "KSBK" || 0x01          magic + format version
//   blob      = header || nonce(24) || ciphertext(+16 tag)      AAD = header
//
// The header is bound as AAD, so a flipped version byte or magic fails authentication, and a blob
// sealed under the same 32-byte key by some other protocol (with different or no AAD) is not accepted
// as a v1 backup. LEGACY blobs written before the header existed — bare `nonce(24) || ciphertext`,
// no AAD — are still READ (a user's existing backups must stay restorable), but never written.
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

/** Current backup format version (the byte after the magic). */
export const BACKUP_FORMAT_VERSION = 1
/** `"KSBK" || version` — prefixed to every blob and bound as AAD. */
const HEADER = concatBytes(utf8ToBytes('KSBK'), Uint8Array.of(BACKUP_FORMAT_VERSION))

function requireKey(key: Uint8Array): void {
  if (key.length !== KEY_LEN) {
    throw new Error(`kenspeckle backup: key must be ${KEY_LEN} bytes, got ${key.length}`)
  }
}

function hasHeader(blob: Uint8Array): boolean {
  if (blob.length < HEADER.length + NONCE_LEN + TAG_LEN) return false
  return HEADER.every((b, i) => blob[i] === b)
}

/** Encrypt the roster (WITH annotations) under a 32-byte key. Returns `header || nonce(24) ||
 *  ciphertext`, the header bound as AAD. A fresh random 24-byte nonce is drawn per call, so
 *  identical input yields distinct blobs. */
export function exportEntriesEncrypted(entries: KindredEntry[], key: Uint8Array): Uint8Array {
  requireKey(key)
  const nonce = randomBytes(NONCE_LEN)
  const plaintext = utf8ToBytes(JSON.stringify(entries))
  const ct = xchacha20poly1305(key, nonce, HEADER).encrypt(plaintext)
  return concatBytes(HEADER, nonce, ct)
}

/** Decrypt the v1 form, falling back to the legacy header-less form. Throws if neither authenticates. */
function decryptBackup(blob: Uint8Array, key: Uint8Array): Uint8Array {
  if (hasHeader(blob)) {
    const body = blob.subarray(HEADER.length)
    try {
      return xchacha20poly1305(key, body.subarray(0, NONCE_LEN), HEADER).decrypt(body.subarray(NONCE_LEN))
    } catch {
      // A legacy blob whose random nonce happened to start with the header (≈2⁻⁴⁰) lands here;
      // fall through and try it as legacy. A tampered v1 blob fails both and throws below.
    }
  }
  if (blob.length < NONCE_LEN + TAG_LEN) {
    throw new Error('kenspeckle backup: blob too short (need nonce + tag)')
  }
  // Legacy: nonce(24) || ciphertext, no AAD. Throws on authentication failure.
  return xchacha20poly1305(key, blob.subarray(0, NONCE_LEN)).decrypt(blob.subarray(NONCE_LEN))
}

/** Decrypt + validate a backup blob (v1, or the legacy header-less form). Throws on a wrong key /
 *  tamper (auth failure), a malformed blob (too short), or any structurally-invalid entry.
 *  Annotations ARE preserved. */
export function importEntries(blob: Uint8Array, key: Uint8Array): KindredEntry[] {
  requireKey(key)
  const pt = decryptBackup(blob, key)

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

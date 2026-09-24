// kenspeckle (`./handshake` subpath) — the handshake wire format (spec §5.1).
//
// The handshake is the first message of a kith bond: I present the persona pubkey I'm bonding as,
// a fresh nonce (freshness for the spoken-token ceremony counter seed), an optional display name,
// and — optionally, consensually — a list of additional personas I'm disclosing to this peer.
//
// This is a STANDALONE subpath entry (consumers `import { ... } from 'kenspeckle/handshake'`); it is
// deliberately NOT re-exported from the `.` barrel. It has no dependency on the relationship model.
//
// `buildHandshakePayload` stamps `v:1` and UTF-8-encodes the JSON. `parseHandshakePayload` hardens
// every field of this attacker-controlled blob per signet-app security conventions:
//   - an 8192-byte cap is enforced BEFORE any decode/parse work (cheap DoS guard);
//   - `v` must be exactly 1; `pubkey` is 64-hex AND a valid curve x; `nonce` is exactly 32 hex chars;
//   - hex fields are lowercase-normalized on output so two callers agree byte-for-byte;
//   - `personas` is a bounded array (≤16) of `{ pubkey: 64-hex on-curve, label?: string }`, with no
//     duplicates and none equal to `pubkey`.
// `buildHandshakePayload` builds from an explicit field allowlist and runs the parser over its own
// output, so it cannot emit anything the peer would reject — or anything the caller didn't mean to send.
//
// One field is INTENTIONALLY not touched: `displayName` is returned verbatim. It is
// attacker-controlled free text — the CONSUMER truncates/sanitizes it at the point of display.
// Sanitizing here would silently mangle legitimate names (and give a false sense of safety).
//
// UTF-8 ⇄ bytes uses the built-in TextEncoder/TextDecoder (globals in node>=22 + browsers) — no
// dependency, no `bytesToUtf8`-lives-in-which-package nuance. No console output anywhere.
//
// `TextEncoder`/`TextDecoder` (and, for ./ken, `fetch`/`Response`) are WHATWG web globals present in
// node>=22 and every browser. Their TYPES come from `@types/node` (a devDependency), enabled via
// `tsconfig.json`'s `"types": ["node"]`. K-3 hand-rolled a per-file ambient for the two text
// constructors; K-5 needed `fetch`/`Response` typed too (those can't be cleanly hand-rolled), so the
// per-file ambient was retired in favour of one project-wide `@types/node` opt-in. Runtime is
// unaffected (these are real globals); @types/node only teaches `tsc` their shape and adds NO runtime
// dependency (it's a devDep, and its declarations emit nothing into `dist/`).

import { secp256k1 } from '@noble/curves/secp256k1.js'

/** The persona/pubkey exchange that bootstraps a kith bond. */
export interface HandshakePayload {
  /** Wire-format version. Exactly 1 for this revision. */
  v: 1
  /** 64-hex: the persona pubkey I present for this bond. Lowercase-normalized on parse. */
  pubkey: string
  /** Optional display name. ATTACKER-CONTROLLED — the consumer truncates/sanitizes on display.
   *  Returned verbatim by `parseHandshakePayload` (this parser does NOT sanitize it). */
  displayName?: string
  /** 16-byte hex (exactly 32 hex chars): freshness for the ceremony counter seed. Lowercased. */
  nonce: string
  /** Optional, consensually-disclosed additional personas. Bounded to ≤16 on parse. */
  personas?: { pubkey: string; label?: string }[]
}

/** Max additional personas a single handshake may consensually disclose (bound the array). */
const PERSONAS_CAP = 16

/** Max accepted blob size, in bytes. Enforced BEFORE decode/parse (cheap DoS guard). Mirrors the
 *  8192-byte QR/payload cap used across signet-app's untrusted-input parsers. */
const MAX_BLOB_BYTES = 8192

/** Exactly 64 hex chars (case-insensitive; the caller lowercases on the way out). */
const HEX64 = /^[0-9a-f]{64}$/i
/** Exactly 32 hex chars = 16 bytes (case-insensitive; lowercased on the way out). */
const HEX32 = /^[0-9a-f]{32}$/i

function isRecord(v: unknown): v is Record<string, unknown> {
  return v !== null && typeof v === 'object' && !Array.isArray(v)
}

/** Validate a 64-hex pubkey field and return it lowercase-normalized. */
function normHex64(value: unknown, field: string): string {
  if (typeof value !== 'string' || !HEX64.test(value)) {
    throw new Error(`handshake: ${field} must be 64 hex chars`)
  }
  return value.toLowerCase()
}

/** Validate a 64-hex pubkey that must also be a valid BIP-340 x-coordinate (liftable with even y).
 *  Catching an off-curve key here beats a later `deriveBondSecret: invalid curve point`. */
function normPubkey(value: unknown, field: string): string {
  const hex = normHex64(value, field)
  try {
    secp256k1.Point.fromHex('02' + hex)
  } catch {
    throw new Error(`handshake: ${field} is not a valid curve point`)
  }
  return hex
}

/**
 * Build the handshake wire blob from an explicit ALLOWLIST of fields → `JSON.stringify` → UTF-8 bytes.
 *
 * Only `pubkey`, `nonce`, `displayName` and `personas[].{pubkey,label}` are copied — never the caller's
 * object. TypeScript's excess-property check does not apply to a non-literal argument, so spreading
 * `p` would put whatever else the caller's object held (a `privkey`, say) on the wire. Hex is
 * lowercased, and the built bytes are run through `parseHandshakePayload` so a caller cannot mint a
 * handshake its peer's parser would reject (oversize, >16 personas, off-curve key, bad label type…).
 * The key order is fixed (`v, pubkey, nonce, displayName, personas`), so equal inputs give equal bytes.
 */
export function buildHandshakePayload(p: Omit<HandshakePayload, 'v'>): Uint8Array {
  if (!isRecord(p)) throw new Error('handshake: payload must be an object')
  if (typeof p.pubkey !== 'string' || !HEX64.test(p.pubkey)) {
    throw new Error('handshake: pubkey must be 64 hex chars')
  }
  if (typeof p.nonce !== 'string' || !HEX32.test(p.nonce)) {
    throw new Error('handshake: nonce must be 32 hex chars (16 bytes)')
  }
  const payload: HandshakePayload = { v: 1, pubkey: p.pubkey.toLowerCase(), nonce: p.nonce.toLowerCase() }
  if (p.displayName !== undefined) payload.displayName = p.displayName
  if (p.personas !== undefined) {
    if (!Array.isArray(p.personas)) throw new Error('handshake: personas must be an array')
    payload.personas = p.personas.map((el) => {
      if (!isRecord(el)) throw new Error('handshake: each persona must be an object')
      const persona: { pubkey: string; label?: string } = {
        pubkey: typeof el.pubkey === 'string' ? el.pubkey.toLowerCase() : el.pubkey,
      }
      if (el.label !== undefined) persona.label = el.label
      return persona
    })
  }
  const bytes = new TextEncoder().encode(JSON.stringify(payload))
  parseHandshakePayload(bytes) // same validators as the peer; throws on anything it would reject
  return bytes
}

/**
 * Parse + harden an untrusted handshake blob into a typed `HandshakePayload`.
 *
 * Order matters: the 8192-byte size cap is checked BEFORE any UTF-8 decode or JSON parse, so an
 * oversized blob is rejected without spending decode/parse work on it. A non-JSON blob surfaces a
 * clear `Error` (never a raw `SyntaxError` leak / crash). All fields are validated; hex is
 * lowercase-normalized. `displayName` is returned VERBATIM (the consumer sanitizes it on display).
 */
export function parseHandshakePayload(blob: Uint8Array): HandshakePayload {
  // (1) Size cap FIRST — before decode/parse.
  if (blob.length > MAX_BLOB_BYTES) {
    throw new Error('handshake: payload too large')
  }

  // (2) Decode + parse, rethrowing a clear Error for non-JSON (no raw SyntaxError surface).
  let raw: unknown
  try {
    raw = JSON.parse(new TextDecoder().decode(blob))
  } catch {
    throw new Error('handshake: malformed JSON')
  }

  // (3) Structural + field guards.
  if (!isRecord(raw)) throw new Error('handshake: payload must be a JSON object')
  if (raw.v !== 1) throw new Error('handshake: unsupported version (v must be 1)')

  const pubkey = normPubkey(raw.pubkey, 'pubkey')

  if (typeof raw.nonce !== 'string' || !HEX32.test(raw.nonce)) {
    throw new Error('handshake: nonce must be 32 hex chars (16 bytes)')
  }
  const nonce = raw.nonce.toLowerCase()

  const out: HandshakePayload = { v: 1, pubkey, nonce }

  // displayName: validate TYPE only — NEVER sanitize/truncate (the consumer's job, by design).
  if (raw.displayName !== undefined) {
    if (typeof raw.displayName !== 'string') {
      throw new Error('handshake: displayName must be a string')
    }
    out.displayName = raw.displayName
  }

  if (raw.personas !== undefined) {
    if (!Array.isArray(raw.personas)) throw new Error('handshake: personas must be an array')
    if (raw.personas.length > PERSONAS_CAP) {
      throw new Error(`handshake: personas exceeds cap of ${PERSONAS_CAP}`)
    }
    // Personas must be distinct from each other and from the presenting pubkey — a duplicate or a
    // restatement of `pubkey` would count one key twice in whatever the consumer does with the list.
    const seen = new Set<string>([pubkey])
    out.personas = raw.personas.map((el): { pubkey: string; label?: string } => {
      if (!isRecord(el)) throw new Error('handshake: each persona must be an object')
      const pPubkey = normPubkey(el.pubkey, 'persona pubkey')
      if (seen.has(pPubkey)) {
        throw new Error('handshake: persona pubkey duplicates another persona or the presenting pubkey')
      }
      seen.add(pPubkey)
      const persona: { pubkey: string; label?: string } = { pubkey: pPubkey }
      if (el.label !== undefined) {
        if (typeof el.label !== 'string') throw new Error('handshake: persona label must be a string')
        persona.label = el.label // free text — not lowercased, not sanitized
      }
      return persona
    })
  }

  return out
}

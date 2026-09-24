// Frozen golden-vector checker for @forgesworn/kenspeckle.
//
// This is the cross-implementation / future-Rust-port + signet-protocol-migration CONTRACT for the
// bond ECDH construction (`./bond` `deriveBondSecret`). For each `vectors/bond.ecdh.*.json` it:
//   1. asserts `deriveBondSecret(privA, pubBXOnly) === secret` using the REAL built code in dist/,
//   2. asserts `deriveBondSecret(privB, pubAXOnly) === secret` — the SAME secret in both directions
//      (only the shared x-coordinate is hashed, so each seat lands on it regardless of y-parity),
//   3. asserts (via `@noble/curves` schnorr.getPublicKey) that `pubAXOnly` / `pubBXOnly` are the
//      x-only (BIP-340) pubkeys of `privA` / `privB` — so the vector's pubkeys provably belong to its
//      privkeys and a future implementation can regenerate them.
//
// WHY this is byte-exact and load-bearing: signet-app migrates kith contacts whose bond secret was
// computed by signet-protocol. If `deriveBondSecret` here does not reproduce `secret` to the byte,
// every migrated contact gets a DIFFERENT secret -> different spoken words -> verification breaks for
// both parties. So this vector is frozen; a drift in the construction must fail the build.
//
// It also checks the other frozen wire contracts: bond spoken words (`bond.words.*`), the invite v2
// signing encoding (`invite.*`), the handshake bytes (`handshake.*`) and the companion rail
// (`companion-rail.*`, `companion-return.*`). A vector file with any other prefix is an error, not
// silently skipped.
//
// Exits non-zero on ANY mismatch or malformation (strict -- this gates releases).

import { readdirSync, readFileSync } from 'node:fs'
import path from 'node:path'
import process from 'node:process'
import { fileURLToPath } from 'node:url'

import { schnorr } from '@noble/curves/secp256k1.js'
import { sha256 } from '@noble/hashes/sha2.js'
import { bytesToHex, hexToBytes, utf8ToBytes } from '@noble/hashes/utils.js'

import { bondWords, deriveBondSecret, verifyBondWord } from '../dist/bond.js'
import { buildHandshakePayload, parseHandshakePayload } from '../dist/handshake.js'
import { parseJoinInvite, serializeJoinInvite } from '../dist/invite.js'
import {
  RETURN_ADDITIONS_CAP,
  RETURN_CORROBORATIONS_CAP,
  RETURN_D_TAG,
  RETURN_LOCATOR_MAX,
  applyCompanionSnapshot,
  buildPairingAck,
  buildPairingUri,
  buildReturnEnvelope,
  landReturnedKen,
  parsePairingAck,
  parsePairingRequest,
  parseReturnEnvelope,
} from '../dist/companion-rail.js'

const __filename = fileURLToPath(import.meta.url)
const __dirname = path.dirname(__filename)
const rootDir = path.resolve(__dirname, '..')
const vectorsDir = path.join(rootDir, 'vectors')

const files = readdirSync(vectorsDir)
  .filter((name) => name.endsWith('.json') && name !== 'schema.json')
  .sort()

if (files.length === 0) {
  console.error('[vectors] No vector files found in vectors/')
  process.exit(1)
}

const failures = []
let assertionCount = 0

const KNOWN_PREFIXES = ['bond.ecdh.', 'bond.words.', 'invite.', 'handshake.', 'companion-rail.', 'companion-return.']
for (const fileName of files) {
  if (!KNOWN_PREFIXES.some((prefix) => fileName.startsWith(prefix))) {
    failures.push({ fileName, message: 'Unrecognised vector file prefix (it would not be checked)' })
  }
}

/** Read + JSON-parse a vector file, recording a failure and returning undefined on error. */
function loadVector(fileName) {
  try {
    return JSON.parse(readFileSync(path.join(vectorsDir, fileName), 'utf8'))
  } catch (error) {
    failures.push({ fileName, message: `Failed to parse JSON: ${String(error)}` })
    return undefined
  }
}

/** Assert `fn` throws an error whose message contains `needle`. */
function expectThrow(fileName, label, needle, fn) {
  assertionCount++
  try {
    fn()
    failures.push({ fileName, message: `${label}: accepted, expected rejection containing "${needle}"` })
  } catch (error) {
    if (!String(error?.message ?? error).includes(needle)) {
      failures.push({ fileName, message: `${label}: rejected with "${String(error)}", expected "${needle}"` })
    }
  }
}

for (const fileName of files.filter((name) => name.startsWith('bond.ecdh.'))) {
  const fullPath = path.join(vectorsDir, fileName)
  let vector
  try {
    vector = JSON.parse(readFileSync(fullPath, 'utf8'))
  } catch (error) {
    failures.push({ fileName, message: `Failed to parse JSON: ${String(error)}` })
    continue
  }

  const shapeError = validateShape(vector)
  if (shapeError) {
    failures.push({ fileName, message: shapeError })
    continue
  }

  const { privA, privB, pubAXOnly, pubBXOnly, secret } = vector

  // 1. A's seat: deriveBondSecret(privA, theirPub = pubBXOnly) MUST equal the frozen secret.
  assertionCount++
  try {
    const got = deriveBondSecret(privA, pubBXOnly)
    if (got !== secret) {
      failures.push({
        fileName,
        message:
          'deriveBondSecret(privA, pubBXOnly) MISMATCH (bond ECDH construction drifted).\n' +
          `  expected: ${secret}\n` +
          `  actual:   ${got}`,
      })
    }
  } catch (error) {
    failures.push({ fileName, message: `deriveBondSecret(privA, pubBXOnly) threw: ${String(error)}` })
  }

  // 2. B's seat: deriveBondSecret(privB, theirPub = pubAXOnly) MUST equal the SAME secret (symmetry).
  assertionCount++
  try {
    const got = deriveBondSecret(privB, pubAXOnly)
    if (got !== secret) {
      failures.push({
        fileName,
        message:
          'deriveBondSecret(privB, pubAXOnly) MISMATCH (ECDH is not symmetric on this vector — only the\n' +
          '  shared x-coordinate should be hashed, so both directions MUST yield the same secret).\n' +
          `  expected: ${secret}\n` +
          `  actual:   ${got}`,
      })
    }
  } catch (error) {
    failures.push({ fileName, message: `deriveBondSecret(privB, pubAXOnly) threw: ${String(error)}` })
  }

  // 3. The vector's pubkeys MUST be the x-only (BIP-340) pubkeys of its privkeys, so the vector is
  //    self-consistent and regenerable. schnorr.getPublicKey returns the 32-byte x-only key.
  for (const [label, priv, expectedPub] of [
    ['A', privA, pubAXOnly],
    ['B', privB, pubBXOnly],
  ]) {
    assertionCount++
    let derivedPub
    try {
      derivedPub = bytesToHex(schnorr.getPublicKey(hexToBytes(priv)))
    } catch (error) {
      failures.push({ fileName, message: `schnorr.getPublicKey(priv${label}) threw: ${String(error)}` })
      continue
    }
    if (derivedPub !== expectedPub) {
      failures.push({
        fileName,
        message:
          `pub${label}XOnly is NOT the x-only pubkey of priv${label} (vector is internally inconsistent).\n` +
          `  declared: ${expectedPub}\n` +
          `  derived:  ${derivedPub}`,
      })
    }
  }
}

for (const fileName of files.filter((name) => name.startsWith('companion-rail.'))) {
  const fullPath = path.join(vectorsDir, fileName)
  let vector
  try {
    vector = JSON.parse(readFileSync(fullPath, 'utf8'))
  } catch (error) {
    failures.push({ fileName, message: `Failed to parse JSON: ${String(error)}` })
    continue
  }

  if (!vector?.pairing?.options || !vector?.pairing?.uri || !vector?.ack?.plaintext || !vector?.snapshots) {
    failures.push({ fileName, message: 'Missing companion pairing, ack or snapshots fixture' })
    continue
  }

  assertionCount++
  try {
    const uri = buildPairingUri(vector.pairing.options)
    if (uri !== vector.pairing.uri) {
      failures.push({ fileName, message: `pairing URI drifted.\n  expected: ${vector.pairing.uri}\n  actual:   ${uri}` })
    }
  } catch (error) {
    failures.push({ fileName, message: `buildPairingUri threw: ${String(error)}` })
  }

  assertionCount++
  const request = parsePairingRequest(vector.pairing.uri, { nowSec: vector.nowSec })
  if (JSON.stringify(request.request) !== JSON.stringify(vector.pairing.parsed) || request.warnings.length !== 0) {
    failures.push({ fileName, message: 'Signet-side pairing request parse drifted' })
  }

  assertionCount++
  const ack = parsePairingAck(vector.ack.plaintext, vector.pairing.options.challenge)
  if (!ack || buildPairingAck(ack) !== vector.ack.plaintext) {
    failures.push({ fileName, message: 'pairing ack parse/build drifted' })
  }

  assertionCount++
  if (parsePairingAck(vector.ack.malformedPlaintext, vector.pairing.options.challenge) !== null) {
    failures.push({ fileName, message: 'malformed pairing ack no longer fails closed' })
  }

  const initial = vector.snapshots.initial
  assertionCount++
  const fresh = applyCompanionSnapshot(initial, vector.snapshots.freshEnvelope)
  if (
    fresh.lastPublishedAt !== vector.snapshots.freshExpected.lastPublishedAt ||
    fresh.revoked !== vector.snapshots.freshExpected.revoked ||
    fresh.contacts.length !== vector.snapshots.freshExpected.contactCount
  ) {
    failures.push({ fileName, message: 'fresh snapshot transition drifted' })
  }

  assertionCount++
  if (applyCompanionSnapshot(initial, vector.snapshots.staleEnvelope) !== initial) {
    failures.push({ fileName, message: 'stale snapshot no longer returns the exact input state' })
  }

  assertionCount++
  const revoked = applyCompanionSnapshot(fresh, vector.snapshots.revokedEnvelope)
  if (
    revoked.lastPublishedAt !== vector.snapshots.revokedExpected.lastPublishedAt ||
    revoked.revoked !== vector.snapshots.revokedExpected.revoked ||
    revoked.contacts.length !== vector.snapshots.revokedExpected.contactCount ||
    revoked.pairing !== undefined
  ) {
    failures.push({ fileName, message: 'revocation transition drifted (or pairing not cleared)' })
  }

  // Revocation is terminal: a NEWER non-revoked snapshot must not bring contacts back.
  assertionCount++
  const resurrect = JSON.parse(vector.snapshots.freshEnvelope)
  resurrect.publishedAt = revoked.lastPublishedAt + 1
  if (applyCompanionSnapshot(revoked, JSON.stringify(resurrect)) !== revoked) {
    failures.push({ fileName, message: 'a post-revocation snapshot resurrected state (revocation must be terminal)' })
  }
}

// Companion RETURN rail (design §10). Frozen for the same reason as the forward rail: these are
// byte-level decisions two independently-built apps must agree on. The `landReturnedKen` locator
// grammar is the load-bearing one — `companion:<appName>:<locator>` with `:`/`%` escaped is what
// keeps a relayed CLAIM structurally distinguishable from a first-party confirmation. Drift there
// is a security regression, not a cosmetic one, so it must fail the build.
for (const fileName of files.filter((name) => name.startsWith('companion-return.'))) {
  const fullPath = path.join(vectorsDir, fileName)
  let vector
  try {
    vector = JSON.parse(readFileSync(fullPath, 'utf8'))
  } catch (error) {
    failures.push({ fileName, message: `Failed to parse JSON: ${String(error)}` })
    continue
  }

  if (!vector?.envelope?.json || !vector?.landed || !vector?.constants) {
    failures.push({ fileName, message: 'Missing return envelope, landed entry or constants fixture' })
    continue
  }

  assertionCount++
  if (
    RETURN_D_TAG !== vector.constants.dTag ||
    RETURN_ADDITIONS_CAP !== vector.constants.additionsCap ||
    RETURN_CORROBORATIONS_CAP !== vector.constants.corroborationsCap ||
    RETURN_LOCATOR_MAX !== vector.constants.locatorMax
  ) {
    failures.push({ fileName, message: 'return rail constants drifted' })
  }

  assertionCount++
  try {
    const json = buildReturnEnvelope(vector.envelope.additions)
    if (json !== vector.envelope.json) {
      failures.push({
        fileName,
        message: `return envelope bytes drifted.\n  expected: ${vector.envelope.json}\n  actual:   ${json}`,
      })
    }
  } catch (error) {
    failures.push({ fileName, message: `buildReturnEnvelope threw: ${String(error)}` })
  }

  assertionCount++
  if (JSON.stringify(parseReturnEnvelope(vector.envelope.json)) !== JSON.stringify(vector.envelope.parsed)) {
    failures.push({ fileName, message: 'return envelope parse drifted' })
  }

  if (!Array.isArray(vector.malformedEnvelopes) || vector.malformedEnvelopes.length === 0) {
    failures.push({ fileName, message: 'Missing malformedEnvelopes fixture (the negative check would pass vacuously)' })
  }
  for (const malformed of vector.malformedEnvelopes ?? []) {
    assertionCount++
    if (parseReturnEnvelope(malformed) !== null) {
      failures.push({ fileName, message: `malformed return envelope no longer fails closed: ${malformed}` })
    }
  }

  // The landing projection: primary provenance, namespaced corroborations, clamped timestamps.
  assertionCount++
  const landed = landReturnedKen(vector.envelope.additions[0], {
    appName: vector.appName,
    ownerPubkeyHex: vector.ownerPubkey,
    nowSec: vector.nowSec,
  })
  if (JSON.stringify(landed) !== JSON.stringify(vector.landed)) {
    failures.push({
      fileName,
      message:
        'landReturnedKen projection drifted (primary provenance, locator namespacing or clamping changed).\n' +
        `  expected: ${JSON.stringify(vector.landed)}\n  actual:   ${JSON.stringify(landed)}`,
    })
  }

  // The namespace-forgery defence: a `:` in appName must be escaped, or a hostile app can emit a
  // locator byte-identical to another app's.
  assertionCount++
  const spoof = landReturnedKen(vector.spoof.input, {
    appName: vector.spoof.appName,
    ownerPubkeyHex: vector.ownerPubkey,
    nowSec: vector.nowSec,
  })
  if (JSON.stringify(spoof) !== JSON.stringify(vector.spoof.landed)) {
    failures.push({
      fileName,
      message:
        'appName namespace escaping drifted — a companion app may be able to forge another app\'s locator.\n' +
        `  expected: ${JSON.stringify(vector.spoof.landed)}\n  actual:   ${JSON.stringify(spoof)}`,
    })
  }
}

// Bond spoken words. Frozen against spoken-token's internals: a dependency bump that changes a word
// changes every contact's verification words, so it must fail here rather than in the field.
for (const fileName of files.filter((name) => name.startsWith('bond.words.'))) {
  const vector = loadVector(fileName)
  if (!vector) continue
  if (!isHex64Lower(vector.secret) || !isHex64Lower(vector.pubA) || !isHex64Lower(vector.pubB) || !Array.isArray(vector.words) || vector.words.length === 0) {
    failures.push({ fileName, message: 'Missing secret / pubA / pubB / words fixture' })
    continue
  }
  for (const row of vector.words) {
    const opts = { namespace: row.namespace }
    assertionCount++
    try {
      const a = bondWords(vector.secret, vector.pubA, vector.pubB, row.counter, opts)
      const b = bondWords(vector.secret, vector.pubB, vector.pubA, row.counter, opts)
      if (a.mine !== row.aMine || a.theirs !== row.aTheirs || b.mine !== row.aTheirs || b.theirs !== row.aMine) {
        failures.push({
          fileName,
          message:
            `bond words drifted at ${row.namespace}#${row.counter}.\n` +
            `  expected: A{mine:${row.aMine}, theirs:${row.aTheirs}}\n` +
            `  actual:   A{mine:${a.mine}, theirs:${a.theirs}} B{mine:${b.mine}, theirs:${b.theirs}}`,
        })
      }
      if (!verifyBondWord(vector.secret, vector.pubB, vector.pubA, row.counter, row.aMine, opts).ok) {
        failures.push({ fileName, message: `verifyBondWord rejected the frozen word at ${row.namespace}#${row.counter}` })
      }
    } catch (error) {
      failures.push({ fileName, message: `bondWords threw at ${row.namespace}#${row.counter}: ${String(error)}` })
    }
  }
}

// Invite v2 canonical signing encoding. The digest is recomputed HERE from the documented formula
// (not via the library) so the vector pins the spec, and the frozen sig is reproduced with BIP-340
// using the vector's aux randomness.
for (const fileName of files.filter((name) => name.startsWith('invite.'))) {
  const vector = loadVector(fileName)
  if (!vector) continue
  if (!isHex64Lower(vector.privkey) || !isHex64Lower(vector.inviterPubkey) || !Array.isArray(vector.cases) || !Array.isArray(vector.negatives) || vector.negatives.length === 0) {
    failures.push({ fileName, message: 'Missing privkey / inviterPubkey / cases / negatives fixture' })
    continue
  }
  assertionCount++
  if (bytesToHex(schnorr.getPublicKey(hexToBytes(vector.privkey))) !== vector.inviterPubkey) {
    failures.push({ fileName, message: 'inviterPubkey is not the x-only pubkey of privkey' })
  }
  for (const c of vector.cases) {
    const f = c.fields
    const canonical = JSON.stringify(['kenspeckle-invite', 2, f.namespace, f.serverId, vector.inviterPubkey, f.nonce, f.expiresAt ?? null])
    assertionCount++
    if (canonical !== c.canonical) {
      failures.push({ fileName, message: `${c.name}: canonical encoding drifted.\n  expected: ${c.canonical}\n  actual:   ${canonical}` })
    }
    const digest = sha256(utf8ToBytes(canonical))
    assertionCount++
    if (bytesToHex(digest) !== c.digest) {
      failures.push({ fileName, message: `${c.name}: digest drifted` })
    }
    assertionCount++
    if (bytesToHex(schnorr.sign(digest, hexToBytes(vector.privkey), hexToBytes(vector.auxRand))) !== c.sig) {
      failures.push({ fileName, message: `${c.name}: BIP-340 sig (fixed aux) does not reproduce` })
    }
    assertionCount++
    try {
      const parsed = parseJoinInvite(utf8ToBytes(c.wire), vector.now)
      if (JSON.stringify(parsed) !== JSON.stringify(c.parsed)) {
        failures.push({ fileName, message: `${c.name}: parseJoinInvite drifted` })
      }
      if (new TextDecoder().decode(serializeJoinInvite(parsed)) !== c.wire) {
        failures.push({ fileName, message: `${c.name}: serializeJoinInvite bytes drifted` })
      }
    } catch (error) {
      failures.push({ fileName, message: `${c.name}: parseJoinInvite threw: ${String(error)}` })
    }
  }
  for (const n of vector.negatives) {
    expectThrow(fileName, `negative "${n.name}"`, n.error, () => parseJoinInvite(utf8ToBytes(n.wire), n.now ?? vector.now))
  }
}

// Handshake wire bytes: allowlisted fields, fixed key order, lowercase hex.
for (const fileName of files.filter((name) => name.startsWith('handshake.'))) {
  const vector = loadVector(fileName)
  if (!vector) continue
  if (!Array.isArray(vector.cases) || vector.cases.length === 0 || !Array.isArray(vector.negatives) || vector.negatives.length === 0) {
    failures.push({ fileName, message: 'Missing cases / negatives fixture' })
    continue
  }
  for (const c of vector.cases) {
    assertionCount++
    try {
      const wire = new TextDecoder().decode(buildHandshakePayload(c.input))
      if (wire !== c.wire) {
        failures.push({ fileName, message: `${c.name}: handshake bytes drifted.\n  expected: ${c.wire}\n  actual:   ${wire}` })
      }
      if (JSON.stringify(parseHandshakePayload(utf8ToBytes(c.wire))) !== JSON.stringify(c.parsed)) {
        failures.push({ fileName, message: `${c.name}: handshake parse drifted` })
      }
    } catch (error) {
      failures.push({ fileName, message: `${c.name}: threw: ${String(error)}` })
    }
  }
  for (const n of vector.negatives) {
    expectThrow(fileName, `negative "${n.name}"`, n.error, () => parseHandshakePayload(utf8ToBytes(n.wire)))
  }
}

if (failures.length > 0) {
  console.error('[vectors] Frozen golden-vector check FAILED.')
  for (const failure of failures) {
    console.error(`- ${failure.fileName}: ${failure.message}`)
  }
  console.error(
    '[vectors] If this change is intentional, regenerate the golden vector against the new code and ' +
      'add a CHANGELOG note — silent bond, invite, handshake or companion-rail wire drift breaks existing consumers.',
  )
  process.exit(1)
}

console.log(`[vectors] OK (${files.length} file(s), ${assertionCount} assertions).`)

/** Strict structural validation of a bond ECDH golden vector file. Returns an error string or null. */
function validateShape(vector) {
  if (!vector || typeof vector !== 'object' || Array.isArray(vector)) {
    return 'Vector file must be a JSON object'
  }
  if (typeof vector.description !== 'string' || vector.description.length === 0) {
    return 'Missing or invalid "description"'
  }
  for (const field of ['privA', 'privB', 'pubAXOnly', 'pubBXOnly', 'secret']) {
    if (!isHex64Lower(vector[field])) {
      return `"${field}" must be a 64-char lowercase hex string`
    }
  }
  return null
}

function isHex64Lower(value) {
  return typeof value === 'string' && /^[0-9a-f]{64}$/.test(value)
}

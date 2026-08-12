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
// Exits non-zero on ANY mismatch or malformation (strict -- this gates releases).

import { readdirSync, readFileSync } from 'node:fs'
import path from 'node:path'
import process from 'node:process'
import { fileURLToPath } from 'node:url'

import { schnorr } from '@noble/curves/secp256k1.js'
import { bytesToHex, hexToBytes } from '@noble/hashes/utils.js'

import { deriveBondSecret } from '../dist/bond.js'
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
    revoked.contacts.length !== vector.snapshots.revokedExpected.contactCount
  ) {
    failures.push({ fileName, message: 'revocation transition drifted' })
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

  assertionCount++
  for (const malformed of vector.malformedEnvelopes ?? []) {
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

if (failures.length > 0) {
  console.error('[vectors] Frozen golden-vector check FAILED.')
  for (const failure of failures) {
    console.error(`- ${failure.fileName}: ${failure.message}`)
  }
  console.error(
    '[vectors] If this change is intentional, regenerate the golden vector against the new code and ' +
      'add a CHANGELOG note — silent bond or companion-rail wire drift breaks existing consumers.',
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

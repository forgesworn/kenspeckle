// Frozen golden-vector checker for @forgesworn/kindred.
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

for (const fileName of files) {
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

if (failures.length > 0) {
  console.error('[vectors] Frozen golden-vector check FAILED.')
  for (const failure of failures) {
    console.error(`- ${failure.fileName}: ${failure.message}`)
  }
  console.error(
    '[vectors] If this change is intentional, regenerate the golden vector against the new code and ' +
      'add a CHANGELOG note — a silent change to the bond ECDH construction breaks every contact ' +
      'migrated from signet-protocol (different secret → different spoken words → broken verification).',
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

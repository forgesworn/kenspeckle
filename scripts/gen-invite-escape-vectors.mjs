// Generate the JSON-escaping cases of vectors/invite.v2.json WITHOUT the library.
//
// The invite v2 digest is sha256(utf8(JSON.stringify(["kenspeckle-invite", 2, namespace, serverId,
// inviterPubkey, nonce, expiresAt ?? null]))) (PROTOCOL §6.1). A non-JS implementer has to match
// JSON.stringify's escaping byte for byte: `"` and `\` escaped, `\b \f \n \r \t` short forms, other
// C0 controls as lowercase `\u00XX`, and everything else — `/`, DEL, `<>&`, U+2028/2029, non-ASCII
// and astral characters — emitted RAW as UTF-8, with no whitespace. The ASCII-only cases already in
// the vector cannot catch a mismatch there, so these cases pin it.
//
// Each `canonical` below is WRITTEN BY HAND as the literal JSON text, not produced by the library or
// by JSON.stringify. The script only cross-checks it against JSON.stringify (so a typo fails
// loudly), then hashes it with @noble/hashes and signs it with @noble/curves directly.
//
//   node scripts/gen-invite-escape-vectors.mjs          print the cases
//   node scripts/gen-invite-escape-vectors.mjs --write  replace/add them (by name) in the vector file
//
// check-vectors.mjs then verifies the library against the frozen result.

import { readFileSync, writeFileSync } from 'node:fs'
import path from 'node:path'
import process from 'node:process'
import { fileURLToPath } from 'node:url'

import { schnorr } from '@noble/curves/secp256k1.js'
import { sha256 } from '@noble/hashes/sha2.js'
import { bytesToHex, hexToBytes, utf8ToBytes } from '@noble/hashes/utils.js'

const VECTOR_PATH = path.join(path.dirname(fileURLToPath(import.meta.url)), '..', 'vectors', 'invite.v2.json')
const vector = JSON.parse(readFileSync(VECTOR_PATH, 'utf8'))
const PUB = vector.inviterPubkey

const CASES = [
  {
    name: 'non-ASCII namespace and serverId are raw UTF-8, never \\u-escaped',
    fields: { namespace: 'jeu.café', serverId: 'サーバー:🎲', nonce: '0123456789abcdef0123456789abcdef', expiresAt: 1700086400 },
    canonical: `["kenspeckle-invite",2,"jeu.café","サーバー:🎲","${PUB}","0123456789abcdef0123456789abcdef",1700086400]`,
  },
  {
    name: 'quote and backslash in fields are backslash-escaped',
    fields: { namespace: 'say "hi"', serverId: 'C:\\srv\\eu', nonce: 'aaaaaaaaaaaaaaaabbbbbbbbbbbbbbbb' },
    canonical: String.raw`["kenspeckle-invite",2,"say \"hi\"","C:\\srv\\eu","` + PUB + String.raw`","aaaaaaaaaaaaaaaabbbbbbbbbbbbbbbb",null]`,
  },
  {
    name: 'escape-sensitive: control chars escaped; slash, DEL, <>&, U+2028 raw',
    fields: {
      namespace: 'tab\there\nnew\u0001\u001f',
      serverId: 'a/b\u007f<x>&y\u2028z\u2029',
      nonce: 'cccccccccccccccccccccccccccccccc',
      expiresAt: 4102444800,
    },
    canonical:
      String.raw`["kenspeckle-invite",2,"tab\there\nnew\u0001\u001f","a/b` +
      '\u007f<x>&y\u2028z\u2029' +
      '","' + PUB + '","cccccccccccccccccccccccccccccccc",4102444800]',
  },
]

const out = []
for (const c of CASES) {
  const f = c.fields
  const viaStringify = JSON.stringify(['kenspeckle-invite', 2, f.namespace, f.serverId, PUB, f.nonce, f.expiresAt ?? null])
  if (viaStringify !== c.canonical) {
    console.error(`gen-invite-escape-vectors: hand-written canonical for "${c.name}" disagrees with JSON.stringify:`)
    console.error(`  hand:      ${c.canonical}\n  stringify: ${viaStringify}`)
    process.exit(1)
  }
  const digest = sha256(utf8ToBytes(c.canonical))
  const sig = bytesToHex(schnorr.sign(digest, hexToBytes(vector.privkey), hexToBytes(vector.auxRand)))
  const parsed = { v: 2, namespace: f.namespace, serverId: f.serverId, inviterPubkey: PUB, nonce: f.nonce, sig }
  if (f.expiresAt !== undefined) parsed.expiresAt = f.expiresAt
  out.push({ name: c.name, fields: f, canonical: c.canonical, digest: bytesToHex(digest), sig, wire: JSON.stringify(parsed), parsed })
}

if (process.argv.includes('--write')) {
  const names = new Set(out.map((c) => c.name))
  vector.cases = [...vector.cases.filter((c) => !names.has(c.name)), ...out]
  writeFileSync(VECTOR_PATH, JSON.stringify(vector, null, 2) + '\n')
  console.log(`gen-invite-escape-vectors: wrote ${out.length} cases to ${path.relative(process.cwd(), VECTOR_PATH)}`)
} else {
  console.log(JSON.stringify(out, null, 2))
}

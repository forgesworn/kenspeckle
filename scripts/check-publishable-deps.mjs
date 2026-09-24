// Prepublish guard: fail if any `dependencies` or `peerDependencies` entry in package.json is a
// git, file, or http(s) URL spec instead of a plain registry semver range.
//
// WHY THIS EXISTS (H1 audit finding). `@forgesworn/kenspeckle` previously shipped
// `@forgesworn/tessera-kit` as a `git+https://…` dependency. `prepublishOnly` ran typecheck, test,
// build and the frozen-vector check, but had NOTHING that inspected the dependency specs
// themselves — so nothing stopped `npm publish` from shipping a git/file/http dependency. Once
// published, `npm i @forgesworn/kenspeckle` fails for every external user: npm cannot clone a
// private git remote it has no credentials for, and a `file:` path only ever resolved on the
// machine that published it. This script is the guard that was missing: it is wired into
// `prepublishOnly` (package.json) so a publish attempt fails LOUDLY, before anything reaches the
// registry, rather than failing silently for downstream installers.
//
// `devDependencies` are deliberately NOT checked — a git/file/http devDependency never ships (npm
// only publishes `dependencies` + `peerDependencies` metadata into the published manifest) and
// tooling commonly pins a fork or a local path there.
//
// Exits non-zero with a clear, per-offending-package message on ANY match. Never silently passes
// on a malformed package.json — a read/parse failure is also a hard failure (fail-closed).

import { readFileSync } from 'node:fs'
import path from 'node:path'
import process from 'node:process'
import { fileURLToPath } from 'node:url'

const __dirname = path.dirname(fileURLToPath(import.meta.url))
const PACKAGE_JSON_PATH = path.join(__dirname, '..', 'package.json')

// Any spec that is not a plain registry range (semver, `^`/`~`/`*`/`x`, a dist-tag, etc.) and
// instead names an install SOURCE npm would need to reach at install time for every downstream
// consumer: a git remote (`git+…`, `git://…`, the shorthand `user/repo`), a local filesystem path
// (`file:`), a bare tarball URL (`http://`/`https://`), or the `github:` shorthand.
const NON_REGISTRY_SPEC = /^(git\+|git:\/\/|file:|https?:\/\/|github:)/i

function loadPackageJson() {
  let raw
  try {
    raw = readFileSync(PACKAGE_JSON_PATH, 'utf8')
  } catch (err) {
    console.error(`check-publishable-deps: could not read ${PACKAGE_JSON_PATH}: ${err.message}`)
    process.exit(1)
  }
  try {
    return JSON.parse(raw)
  } catch (err) {
    console.error(`check-publishable-deps: ${PACKAGE_JSON_PATH} is not valid JSON: ${err.message}`)
    process.exit(1)
  }
}

function findOffenders(pkg) {
  const offenders = []
  for (const field of ['dependencies', 'peerDependencies']) {
    const deps = pkg[field]
    if (deps === null || typeof deps !== 'object') continue
    for (const [name, spec] of Object.entries(deps)) {
      if (typeof spec === 'string' && NON_REGISTRY_SPEC.test(spec.trim())) {
        offenders.push({ field, name, spec })
      }
    }
  }
  return offenders
}

const pkg = loadPackageJson()
const offenders = findOffenders(pkg)

if (offenders.length > 0) {
  console.error('check-publishable-deps: refusing to publish — non-registry dependency spec(s) found:')
  for (const { field, name, spec } of offenders) {
    console.error(`  ${field}.${name} = "${spec}"`)
  }
  console.error('')
  console.error(
    'A git/file/http(s) dependency only resolves on the machine (or with the credentials) that ' +
      'published it — `npm i @forgesworn/kenspeckle` fails for every external user. Publish the ' +
      'dependency to the npm registry and pin a plain semver range before publishing kenspeckle.',
  )
  process.exit(1)
}

console.log('check-publishable-deps: all dependencies/peerDependencies are plain registry specs.')

// Prepublish guard: fail if any `dependencies`, `optionalDependencies` or `peerDependencies` entry
// in package.json is a git, file, link, or http(s) URL spec instead of a plain registry range.
//
// WHY THIS EXISTS (H1 audit finding). `@forgesworn/kenspeckle` previously shipped
// `@forgesworn/tessera-kit` as a `git+https://…` dependency. `prepublishOnly` ran typecheck, test,
// build and the frozen-vector check, but had NOTHING that inspected the dependency specs
// themselves — so nothing stopped `npm publish` from shipping a git/file/http dependency. Once
// published, `npm i @forgesworn/kenspeckle` fails for every external user: npm cannot clone a
// private git remote it has no credentials for, and a `file:` path only ever resolved on the
// machine that published it. This script is the guard that was missing: it is wired into
// `prepack` (package.json) so a publish attempt fails LOUDLY, before anything reaches the
// registry, rather than failing silently for downstream installers.
//
// WHY `prepack`, NOT `prepublishOnly`: the release pipeline (forgesworn/anvil
// `steps/record-tarball.sh`) builds the artefact with `npm pack` and later uploads it with
// `npm publish <tarball>`, which never runs `prepublishOnly`. `npm pack` does run `prepack`, and so
// does a plain `npm publish`. Installing kenspeckle from git runs only `prepare` (pacote), never
// `prepack`, so this cannot break a git-pinned consumer's install. CI also runs this script as an
// explicit step (ci.yml).
//
// `devDependencies` are deliberately NOT checked — a devDependency is never installed for a
// downstream consumer (only `dependencies`, `optionalDependencies` and `peerDependencies` are) and
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
// consumer: a git remote (`git+…`, `git://…`, `git@host:…`, the `github:`/`gitlab:`/`bitbucket:`/
// `gist:` shorthands, or the bare `user/repo` shorthand), a local filesystem path (`file:`,
// `link:`), or a bare tarball URL (`http://`/`https://`). A registry range never contains `/`, and
// the `npm:@scope/name@range` alias form cannot match `REPO_SHORTHAND` (its first segment has `:`).
const NON_REGISTRY_SPEC = /^(git\+|git:\/\/|git@|file:|link:|https?:\/\/|github:|gitlab:|bitbucket:|gist:)/i
const REPO_SHORTHAND = /^[a-z0-9][\w.-]*\/[\w.-]+(#.*)?$/i

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
  for (const field of ['dependencies', 'optionalDependencies', 'peerDependencies']) {
    const deps = pkg[field]
    if (deps === null || typeof deps !== 'object') continue
    for (const [name, spec] of Object.entries(deps)) {
      if (typeof spec === 'string' && (NON_REGISTRY_SPEC.test(spec.trim()) || REPO_SHORTHAND.test(spec.trim()))) {
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

console.log('check-publishable-deps: all dependencies/optionalDependencies/peerDependencies are plain registry specs.')

// Packaging lint: `publint` (package.json / exports / files shape) + `attw` (are the types wrong?),
// WITHOUT ever running `npm pack`'s normal lifecycle scripts.
//
// WHY THIS SCRIPT EXISTS, RATHER THAN THE OBVIOUS `publint && attw --pack . --profile esm-only`:
// `attw --pack .` and a plain `npm pack` both run the `prepack` lifecycle, which runs THIS repo's
// own `check:publishable-deps` guard (see scripts/check-publishable-deps.mjs) — and that guard is
// SUPPOSED to fail for as long as `@forgesworn/tessera-kit` stays a git dependency (H1 audit
// finding: it is the thing that stops an unpublishable tarball reaching npm). Wiring `lint:package`
// through the same lifecycle would make routine linting fail for a reason that has nothing to do
// with the actual package shape, and — worse — would tempt someone to weaken that guard just to get
// CI green. So this script gets the SAME two answers (is package.json/exports/files sane? are the
// published .d.ts files resolvable the way ESM consumers need?) via paths that skip `prepack`
// entirely:
//   - `publint --pack false` lints the WORKING DIRECTORY directly — no packing at all.
//   - `npm pack --ignore-scripts` builds a real tarball (the same file list `npm publish` would
//     ship) WITHOUT running prepack/postpack, and `attw` then inspects that tarball directly.
//
// The actual `prepack` guard is untouched — a real `npm pack` / `npm publish` / `npm pack --dry-run`
// (no `--ignore-scripts`) still runs `check:publishable-deps` and still refuses to ship a git
// dependency. This script only changes how ROUTINE LINTING gets its answer.
//
// Exits non-zero (propagating the first tool's exit code) on any lint failure. Always removes the
// tarball it created, even if `attw` itself fails or throws.

import { spawnSync } from 'node:child_process'
import { existsSync, rmSync } from 'node:fs'
import path from 'node:path'
import process from 'node:process'
import { fileURLToPath } from 'node:url'

const __dirname = path.dirname(fileURLToPath(import.meta.url))
const rootDir = path.resolve(__dirname, '..')
const binDir = path.join(rootDir, 'node_modules', '.bin')

/** Run a local devDependency binary (node_modules/.bin/<name>), streaming its output, and return
 *  its exit code (never throws on a non-zero exit — that is a normal lint failure, not a script bug). */
function run(bin, args, opts = {}) {
  const result = spawnSync(path.join(binDir, bin), args, { cwd: rootDir, stdio: 'inherit', ...opts })
  if (result.error) {
    console.error(`lint-package: failed to run ${bin}: ${result.error.message}`)
    return 1
  }
  return result.status ?? 1
}

// 1. publint — directory mode (`--pack false`), so it never shells out to `npm pack` and therefore
//    never touches `prepack` / `check:publishable-deps`.
const publintStatus = run('publint', ['run', '--pack', 'false'])
if (publintStatus !== 0) process.exit(publintStatus)

// 2. Build a real tarball with `npm pack --ignore-scripts` — the same file list a real publish
//    would ship, but WITHOUT running prepack/postpack. `--silent` makes stdout just the filename.
const packResult = spawnSync('npm', ['pack', '--ignore-scripts', '--silent'], { cwd: rootDir, encoding: 'utf8' })
if (packResult.error || packResult.status !== 0) {
  console.error('lint-package: `npm pack --ignore-scripts` failed:')
  console.error(packResult.stdout ?? '')
  console.error(packResult.stderr ?? packResult.error?.message ?? '')
  process.exit(packResult.status ?? 1)
}
const tarballName = packResult.stdout.trim().split('\n').pop()
const tarballPath = path.join(rootDir, tarballName)

// 3. attw against the tarball directly (not `--pack`, which would re-run `npm pack` WITH scripts).
let attwStatus = 1
try {
  attwStatus = run('attw', [tarballPath, '--profile', 'esm-only'])
} finally {
  // Always clean up the tarball, even if attw failed or threw.
  if (existsSync(tarballPath)) rmSync(tarballPath)
}

process.exit(attwStatus)

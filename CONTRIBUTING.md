# Contributing to kenspeckle

## Setup

```bash
git clone https://github.com/forgesworn/kenspeckle.git
cd kenspeckle
npm install
```

> **Dependency note.** `@forgesworn/kenspeckle` depends on
> `@forgesworn/tessera-kit` (`^0.2.1`) from npm, so a plain `npm install` / `npm ci`
> is all you need.
>
> `scripts/check-publishable-deps.mjs` runs in `prepack` (every `npm pack` / `npm publish`) and **refuses to
> publish** while any `dependencies`/`optionalDependencies`/`peerDependencies` entry is a git/file/http(s)
> spec. If you ever point a dependency at a git commit or local path for development, move it back to a
> registry range before releasing.

## Commands

| Command | Purpose |
|---------|---------|
| `npm test` | Run all tests (vitest) |
| `npm run test:watch` | Watch mode |
| `npm run build` | Compile TypeScript to dist/ |
| `npm run typecheck` | Type-check without emitting |
| `npm run test:coverage` | Run all tests with v8 coverage |
| `npm run vectors:check` | Verify every frozen golden vector in `vectors/` against the built code |
| `npm run lint:package` | Check the packed package with publint and attw (skips lifecycle scripts, so it runs while a dependency is still a git spec) |
| `npm run check:publishable-deps` | Fail if any `dependencies`/`optionalDependencies`/`peerDependencies` entry is a git/file/link/http(s) spec (runs in `prepack`) |

## Project Structure

```
src/
  types.ts      — relationship model types + canonical nostr-tools aliases (EventTemplate/NostrEvent/NostrFilter)
  model.ts      — local relationship ops: scope, search, private-link, canonical serialize/parse (`.` surface)
  backup.ts     — encrypted self-backup export/import (includes private annotations)
  handshake.ts  — out-of-band persona handshake (./handshake subpath)
  bond.ts       — migration-critical bond ceremony: deriveBondSecret / bondWords / verifyBondWord (./bond subpath)
  ken.ts        — ken trust-store: pin, live key-control proof, rotation detection (./ken subpath)
  discovery.ts  — local presence discovery over @forgesworn/tessera-kit (./discovery subpath)
  invite.ts     — Schnorr-signed join invite + single-attestation verify (./invite subpath)
  validate.ts   — shared input validation
  index.ts      — `.` barrel (model + local ops only; the five subpaths are deliberately NOT re-exported)
```

The five conceptual subpaths (`@forgesworn/kenspeckle/handshake`, `/bond`, `/ken`,
`/discovery`, `/invite`) are imported via their own export so a consumer that only
needs, say, the bond ceremony does not pull the discovery / tessera-kit graph.
Keeping them off the `.` barrel is the load-bearing tree-shaking + dependency-isolation
boundary, not an oversight.

## Conventions

- **British English** — colour, behaviour, serialise, licence
- **Minimal runtime deps** — `@forgesworn/tessera-kit`, `@noble/curves`,
  `@noble/hashes`, `@noble/ciphers`, `spoken-token`, `nostr-attestations`; `nostr-tools`
  is a **peer** dependency. No others.
- **ESM-only** — `"type": "module"` in package.json
- **TDD** — write a failing test first, then implement
- **One canonical event type** — Nostr events are the re-exported nostr-tools
  `EventTemplate` / `NostrEvent` from `./types.js`; never hand-rolled event shapes.
- **Verify results are `{ ok, reason? }`** — verification entry points return a
  discriminated object, never a bare boolean. A verdict that can fail names its
  `reason`. Functions that return `{ ok }` (e.g. `verifyBondWord`) **must not throw**
  on a valid-shaped call — fail soft.
- **Migration byte-exactness** — `deriveBondSecret` MUST stay byte-for-byte
  identical to signet-protocol. The frozen vector gates this; never edit the vector
  to make a changed construction pass (see below).
- **No `console.*` in library code** — `src/` is silent; the `scripts/` checkers may log.

## Frozen golden vectors

`vectors/bond.ecdh.v1.json` is the cross-implementation / future-Rust-port /
signet-protocol-migration **contract** for the bond ECDH construction.
`npm run vectors:check` re-derives the secret from the vector's inputs in **both**
ECDH directions, asserts it equals the frozen `secret`, and asserts the vector's
pubkeys are the x-only (BIP-340) pubkeys of its privkeys. It runs in CI and gates
releases.

If you intentionally change the bond ECDH construction, regenerate the vector
against the new code and add a `CHANGELOG.md` note — a silent change to the secret
breaks **every contact migrated from signet-protocol** (different secret → different
spoken words → broken verification for both parties).

## Testing

Tests live alongside source files as `*.test.ts` (unit, fuzz, and property-based).

```bash
# Run all tests
npm test

# Run a specific test file
npx vitest run src/bond.test.ts

# Watch mode
npm run test:watch
```

## Submitting Changes

1. Fork the repository
2. Create a feature branch: `git checkout -b feat/my-change`
3. Write tests for your changes
4. Ensure all tests pass: `npm test`
5. Ensure types check: `npm run typecheck`
6. Ensure the golden vectors still hold: `npm run vectors:check`
7. Commit with a conventional message (see below)
8. Open a pull request against `main`

## Commit Messages

This project uses conventional-commit prefixes:

| Prefix | Version bump | Example |
|--------|-------------|---------|
| `feat:` | Minor (0.x.0) | `feat: add collective-attestation verify` |
| `fix:` | Patch (0.0.x) | `fix: clamp verifyBondWord tolerance window` |
| `docs:` | None | `docs: clarify signet-me migration opts` |
| `chore:` | None | `chore: update dev dependencies` |
| `refactor:` | None | `refactor: extract role-token derivation` |

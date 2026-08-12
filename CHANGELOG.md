# Changelog

All notable changes to `@forgesworn/kenspeckle` are documented here. The format is
based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and this
project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.1.0] — Unreleased

First public release: **verified relationships across three social distances** —
*kin* (family), *kith* (mutually verified), *ken* (one-way recognised) — with an
encrypted out-of-band handshake, a migration-critical spoken-token bond ceremony,
a live-control ken trust-store, and privacy-preserving local presence discovery
layered over `@forgesworn/tessera-kit`.

### Added

- **Relationship model + local ops** (`.`) — the three-distance model, canonical
  serialize/parse, persona scoping, search, and private-recall links, plus an
  encrypted self-backup (`exportEntriesEncrypted` / `importEntries`) that includes
  private annotations (the user's own sealed copy, never a graph disclosure).
- **Out-of-band handshake** (`./handshake`) — `buildHandshakePayload` /
  `parseHandshakePayload` for exchanging persona identity off-relay.
- **Bond ceremony** (`./bond`) — the migration-critical kith surface.
  `deriveBondSecret` reproduces signet-protocol's ECDH construction
  **byte-for-byte** (`SHA-256` of the shared x-coordinate); `bondWords` /
  `verifyBondWord` derive the rotating directional spoken-token word pair;
  `buildBondAttestation` / `retractBondAssertion` build the optional, consensual
  kind-31000 record and its NIP-09 retraction.
- **Ken trust-store** (`./ken`) — pin a key from a NIP-05, then prove **live
  control** (`buildKeyControlChallenge` / `verifyKeyControl`) and detect rotation,
  so recognition tracks the *current* key rather than a stale pin.
- **Corroborated provenance** (`.` + `./ken`) — an **optional**
  `KenEntry.corroborations?: KenProvenance[]` records *additional independent
  channels* that agree a key belongs to a person, so "verified in person **and**
  matches their domain" can be expressed instead of keeping one source and
  discarding the rest. Corroboration is the defence when any single channel can be
  compromised. Helpers: `addCorroboration(entry, provenance)` (pure; never touches
  the primary `provenance`), `summarizeKenProvenance(entry)`, and an optional
  `corroborations` argument on `pinKen`.
  **Fully additive — nothing breaks.** `provenance` remains required and singular,
  so every existing reader is untouched; an entry *without* `corroborations`
  serialises **byte-identically** to before (asserted explicitly in `model.test.ts`
  against strings frozen from the pre-change build), and the frozen vectors pass
  unmoved. The `KenProvenance['source']` union is **unchanged** — adding a value
  there would be breaking, because `validateProvenance` throws on an unrecognised
  source and an older validator would reject the *entire* entry.
  *Known, accepted caveat:* because `parseEntry` reconstructs from a whitelist, an
  old client that parses and re-serialises a new entry silently drops
  `corroborations` — round-trip data loss through old code, not breakage. It argues
  for landing kenspeckle and signet-app together rather than skewed.
- **Companion return rail** (`./companion-rail`) — `WireKen`,
  `buildReturnEnvelope` / `parseReturnEnvelope`, `landReturnedKen`, and the
  `RETURN_D_TAG` / `RETURN_ADDITIONS_CAP` / `RETURN_CORROBORATIONS_CAP` constants.
  A proposing companion app can now carry the provenance it **claims**
  (`claimedProvenance` / `claimedCorroborations`) instead of having real
  `in-person` evidence flattened to "manual, via some app" in transit. signet-app
  stays the authority: `landReturnedKen` keeps the primary `provenance` as
  `{ source:'manual', locator:'companion:<appName>' }` and files every claim as a
  **corroboration** whose locator is sanitised and namespaced
  `companion:<appName>:<locator>` (with `:`/`%` percent-escaped in the app-name
  segment so the grammar is injective and one app cannot forge another's
  namespace) and `confirmedAt` clamped into `[0, now]` — so a claim is preserved
  in full yet can never be misread as a first-party confirmation. `entry.nip05` is
  deliberately **not** set from a claim: it is the address `resolveKen` re-fetches,
  so populating it would let a companion choose a ken's re-resolution authority;
  a claimed identifier is shape-guarded and filed as evidence instead. Types +
  validators only; relay I/O, encryption and storage remain the app's.
- **`summarizeKenProvenance().claimed`** — how many of a ken's confirmations are
  *relayed companion claims* rather than first-hand checks, counted via the
  reserved `companion:` locator prefix (`COMPANION_LOCATOR_PREFIX`). Without it a
  fully attacker-authored ken reports six confirmations across six distinct
  sources with nothing verified; a consumer rendering corroboration must show
  `confirmations - claimed`.
- **Frozen companion return-rail vector** (`vectors/companion-return.v1.json`) —
  envelope bytes, claim preservation, the `landReturnedKen` projection, and the
  namespace-escaping defence. The existing bond and companion-rail vectors are
  untouched; the checker now runs 17 assertions across 3 files.
- **Local presence discovery** (`./discovery`) — `discoverPresent` /
  `parseFilterPublication` test a held contact key against a community's signed
  membership-filter publication **locally**, with no enumeration affordance. Filter
  mechanics (build/sign/serialize/parse) are delegated to `@forgesworn/tessera-kit`;
  kenspeckle owns the relationship layer and the Nostr **kinds**.
- **Join invites** (`./invite`) — a custom-payload Schnorr-signed invite plus
  single-attestation verification.
- **Companion data rail** (`./companion-rail`) — the shared Signet/Fledgling
  pairing URI, ack, wire constants and monotonic snapshot reducer. It is pure
  protocol code: apps retain relay I/O, timers, storage, encryption and UI.
- **Frozen companion rail vector** (`vectors/companion-rail.v1.json`) covering
  the Fledgling request, Signet ack, malformed ack, fresh/stale snapshot and
  revocation transition in addition to the existing bond vector.
- **Frozen golden vector** (`vectors/bond.ecdh.v1.json`) + strict checker
  (`npm run vectors:check`): the byte-exact cross-implementation /
  future-Rust-port / signet-protocol-migration contract for `deriveBondSecret`. It
  asserts the secret in **both** ECDH directions and that the vector's pubkeys are
  the x-only (BIP-340) pubkeys of its privkeys. Runs in CI and gates releases.
- CI (push/PR: `npm ci` → typecheck → build → `vectors:check` → test, Node 22),
  tag-triggered release, dependabot + auto-merge workflows.

### Changed (breaking)

- **Verify results unified to `{ ok, reason? }`.** All verification entry points
  now return a discriminated object rather than a bare boolean or an ad-hoc shape.
  `verifyKeyControl` / `verifyEventAgainstPin` (`./ken`) return `{ ok, reason? }`
  where `reason` names the failure (`'revoked'`, `'bad-nonce'`,
  `'pubkey-not-current-pin'`, `'nonce-mismatch'`, `'bad-signature'`,
  `'rotated-away-key'`, `'pubkey-mismatch'`); `verifyBondWord` (`./bond`) returns
  `{ ok }`; the single-attestation verify (`./invite`) returns
  `{ ok, attesterPubHex?, subjectPubHex? }`. Consumers that branched on a boolean
  must now read `.ok`.

### Security

- **Nonce-strength gate (`./ken`).** `verifyKeyControl` requires the challenge
  `nonce` to match `/^[0-9a-f]{64}$/` (≥ 256 bits, hex) and returns
  `{ ok:false, reason:'bad-nonce' }` otherwise. This gate is **load-bearing** for
  the claim that a stale/empty/low-entropy challenge can **never** be replayed into
  a false "live control" verdict — without it an attacker-chosen weak nonce would
  undermine the proof.
- **Keyed-pool salt guard (`./discovery`).** A zero-length / malformed salt is
  rejected before it can collapse a keyed membership pool to the open construction;
  honest about the residual: keying a discovery pool is a **speed-bump** against a
  salt-holder, not a cryptographic barrier (see `SECURITY.md` §7).
- **`verifyBondWord` tolerance window is now fail-soft.** The `[counter-t, counter+t]`
  window is clamped to the valid uint32 counter range `[0, 0xFFFFFFFF]` and the
  `tolerance` itself is coerced to an integer in `[0, 10]` (mirroring spoken-token's
  `MAX_TOLERANCE`; negative/NaN → `0`, larger → `10`). A boundary counter (e.g.
  `counter = 0, tolerance = 1`) previously threw a `RangeError` out of spoken-token's
  `counterBe32`, breaking the `{ ok }` contract; it now never throws on a
  valid-shaped call.
- **Hex inputs lowercased; namespace colon-guarded.** Hex is normalised before
  comparison/derivation; the bond namespace cannot smuggle a stray separator.

### Notes

- **Scoped package name.** This package publishes as **`@forgesworn/kenspeckle`**.
- **Renamed from `kindred` (2026-08-12, pre-publish).** "Kindred" became the
  ForgeSworn app-suite umbrella brand, so the library (developed as
  `@forgesworn/kindred`, never published) was renamed to *kenspeckle* (Scots:
  *easily recognised, known by sight*). The **wire protocol keeps the historical
  `kindred` naming, frozen**: bond namespace `'kindred:bond'`
  (`KINDRED_BOND_NAMESPACE`), discovery d-tag prefix `'kindred:members:'`,
  attestation type `'kindred-bond'`, and kinds 30444/30445 are unchanged —
  renaming them would change every deployed bond word and published filter.
  Exported identifiers that name those wire strings (`KINDRED_*`) and the model
  types (`KindredEntry`, `KindredTier`) also keep their names.
- **Publish order + lockfile.** `@forgesworn/tessera-kit` **MUST be on npm first** —
  `@forgesworn/kenspeckle` depends on it. The lockfile currently resolves the dep via
  `file:../tessera-kit/forgesworn-tessera-kit-0.1.0.tgz` for local development; once
  `@forgesworn/tessera-kit` is published, **repoint the lockfile off `file:`** (run
  `npm install` against the registry) before publishing `kenspeckle`.
- **signet-me migration caveat (`./bond`).** With **default** opts `bondWords` uses
  namespace `'kindred:bond'`, so its words **differ** from signet-app's `signet-me`
  (`'signet:me'`) — a naive migration silently changes a contact's verification
  words. To cross-verify with a peer who has not migrated, pass
  `{ namespace: 'signet:me' }` to `bondWords` and
  `{ namespace: 'signet:me', tolerance: 1 }` to `verifyBondWord`; both peers must
  upgrade together or use these opts during rollout. See `PROTOCOL.md` §2.1.
- **Relationship layer only.** kenspeckle owns relationships, personas, and Nostr
  *kinds*; the relationship-agnostic filter primitive lives in
  `@forgesworn/tessera-kit`.

[0.1.0]: https://github.com/forgesworn/kenspeckle/releases/tag/v0.1.0

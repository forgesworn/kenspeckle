# Changelog

All notable changes to `@forgesworn/kenspeckle` are documented here. The format is
based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and this
project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.2.0] — Unreleased

Security-audit fix pass over `ken`/`discovery`/`model`/`validate`/`types` and
over `handshake`/`bond`/`invite`/`grant-envelope`/`backup`/`companion-rail`, plus
packaging and CI hardening. Findings below are from two internal audits; the
`H`/`M`/`L` labels are severity (High/Medium/Low), not part of any public API.
Labels prefixed `core-` come from the second audit (the ceremony/rail modules) and
are numbered independently.

### Security (breaking)

- **H4 — `toWire`/`serializeEntry` now strip `sharedSecret`.** Previously only
  `annotations` was excluded, so code trusting the "wire-safe" name could publish
  a kin/kith's ECDH secret. A `WireEntry` for those tiers no longer round-trips
  through `parseEntry` (it lacks a field `validateEntryShape` requires) — that is
  intentional. **New:** `toSyncForm`/`serializeEntryForSync` (types `SyncEntry`)
  KEEP `sharedSecret`, for the one legitimate case that needs it to travel:
  syncing a roster across the user's own devices over an already-private
  transport. Never publish that output. `backup.ts` is unaffected — it already
  bypassed this module entirely.
- **M2 — `parseFilterPublication` now requires the event signer to equal the
  in-blob signer by default** (new `opts.requireAuthorIsSigner`, default `true`),
  and requires the `n` tag to equal the namespace recovered from the d-tag. The
  in-blob Schnorr signature covers neither `namespace` nor `serverId`; without
  this, a genuinely server-signed blob could be re-wrapped under a different
  `serverId` (or namespace) by anyone and still report the real server's
  `signerPubkeyHex`. **A previously-parseable cross-serverId republish now
  returns `null`** unless the caller passes `{ requireAuthorIsSigner: false }`.
- **L6 — `disclosureFor` now takes the parsed `MembershipFilter`, not
  `{ salt? }`.** The old signature derived `keyed` from salt PRESENCE, a second
  source of truth that could disagree with the filter's own `keyed` flag. Callers
  pass the filter object they already have after `parseFilter`.

- **core-H2 — invites are now `v: 2` with an injective signing encoding.** The
  digest is `sha256(utf8(JSON.stringify(["kenspeckle-invite", 2, namespace,
  serverId, inviterPubkey, nonce, expiresAt ?? null])))`. The v1 colon-joined
  digest was not injective: an invite signed for `("game", "eu:prod")` verified as
  `("game:eu", "prod")`. **v1 invites are rejected** (no fallback). Strings with
  lone surrogates are rejected at build and parse. Frozen vector
  `vectors/invite.v2.json` includes that cross-field shift as a negative case.
- **core-L5 — invite field hygiene.** The nonce must be at least 16 bytes of hex
  (new `generateInviteNonce()`), `expiresAt` a non-negative safe integer, and
  `parseJoinInvite` accepts only lowercase `inviterPubkey`/`nonce`/`sig` (one wire
  spelling per invite). `buildJoinInvite` takes an optional `now` and refuses an
  already-expired invite. Dedupe on `(inviterPubkey, nonce)` for one-time invites.
- **core-H1/L4 — `verifyBondAttestation(event, now?)` rejects revoked, expired,
  not-yet-active and self-attestations** (via nostr-attestations `isValid`), requires
  exactly one `p` tag and a `d` tag of `kindred-bond:<subject>`, lowercases both
  returned pubkeys, and returns a `reason` on failure (types
  `BondAttestationResult`/`BondAttestationRejection`).
- **core-M3 — `retractBondAssertion(assertion, { attesterPubHex, subjectPubHex })`**
  now needs the attestation's address, validates `mineId` as 64-hex and emits
  `["e", mineId]`, `["a", "31000:<attester>:kindred-bond:<subject>"]` and
  `["k", "31000"]`. It is a supplement to the new **`buildBondRevocation`**
  (`./bond`), a kind-31000 `status:revoked` event via nostr-attestations
  `createRevocation`, which is now the primary retraction.
- **core-M1/M2 — companion rail: revocation is terminal, timestamps are safe
  integers.** Once `state.revoked` is true, `applyCompanionSnapshot` ignores every
  later envelope (a re-pair starts from a fresh state), and a revocation applies even
  when its `publishedAt` is not newer. `publishedAt`/`addedAt` must be non-negative
  safe integers; `1e400` (`Infinity`) used to freeze the rail and block revocation.
- **core-L6 — `parseGrantEnvelope` consistency.** Lowercases hex, strips
  control/bidi characters from `displayName`/`nip05`, returns a projected `scope`,
  drops contacts outside the envelope's own scope, and reads at most
  `GRANT_CONTACTS_CAP` (5000) contacts.
- **core-M5 — builders serialise an allowlist, never the caller's object.**
  `buildHandshakePayload`, `buildPairingAck`, `buildGrantEnvelope` and
  `serializeJoinInvite` copy only declared fields, so an extra property on a
  non-literal argument (a private key, say) no longer reaches the wire.
  `buildHandshakePayload`/`buildGrantEnvelope` also throw on anything the peer's
  parser would reject.
- **core-L7 — `parsePairingRequest` is strict.** `t` must be plain digits; only
  `signet-grant:`/`https:` (or a bare query) are accepted; `#fragment`s are ignored;
  input is capped at `PAIRING_INPUT_MAX` (4096) and the challenge at
  `PAIRING_CHALLENGE_MAX` (128) hex characters, also in `buildPairingUri` and
  `parsePairingAck`; a non-finite or negative `nowSec`/`freshnessSeconds` throws
  instead of silently disabling the freshness check.
- **core-L9 — `parseHandshakePayload` rejects** pubkeys that are not valid curve
  points, duplicate personas, and a persona equal to the presenting pubkey.
- **core-L1 — `bondWords` throws** for non-64-hex pubkeys, a self-bond and an empty
  namespace; `verifyBondWord` returns `{ ok: false }` for them instead of throwing.

### Security

- **H2 — `acceptKenRotation` refuses a replay.** Throws if `rotation.accepted` is
  already `true` (a double-click / re-invoked accept could previously append the
  now-current pubkey into `previousPubkeys` again, making `attributeSignature`
  reject the legitimate current key) or if `rotation.newPubkey` equals the
  current pin. `rotation.newPubkey` is re-validated as 64-hex.
- **H3 — a NIP-05 "rollback" to a previously-rotated-away key is flagged, not
  proposed as an ordinary rotation.** `resolveKen` sets `rotation.rollback: true`
  when the resolved key is already in `previousPubkeys` (a compromised/reverted
  domain re-serving an old key). `acceptKenRotation(entry, opts)` refuses a
  flagged rollback unless `opts.allowRevert` is `true`, and — when accepted —
  removes the reverted-to key from `previousPubkeys` before re-adding the old
  current key, so the two never end up in a self-contradictory state.
  `validateEntryShape` also rejects a stored/imported ken whose `pubkey` appears
  in its own `previousPubkeys`, or whose `rotation.newPubkey` equals `pubkey`.
- **M1 — strict NIP-05 validation.** `pinKen`, `pinKenFromNip05`,
  `validateEntryShape` (parse/import), and `resolveNip05` itself (the choke
  point) all validate a strict `local@domain` shape: no port, no userinfo, no
  path/query/fragment, and no bare IP literal. Previously only
  `pinKenFromNip05` validated shape at all, and even that check was permissive
  enough (and bypassable via `pinKen`/import) that a crafted `nip05` field could
  turn `resolveKen` into an arbitrary-URL fetch.
- **M3 — `discoverPresent` throws if a salt is passed to an OPEN filter.**
  Mirrors the existing keyed-without-salt guard: either mismatch previously
  hashed every candidate against the wrong construction and silently returned
  `[]` — a false "no friends here".
- **M4 — `pinKen`/`addCorroboration` run the same provenance validation and
  `MAX_CORROBORATIONS` (64) cap as `importEntries`/`parseEntry`.** A builder
  could previously mint an entry the parser would later refuse — including one
  that exported fine but could never be restored from backup.
- **M5 — `pinKen`/`addCorroboration` reject the reserved `companion:` locator
  prefix.** That prefix is reserved for `landReturnedKen` (`./companion-rail`)
  to mark a RELAYED claim; a first-party call minting one let a companion-app
  claim masquerade as a first-hand confirmation.
- **L1 — NIP-05 fetch hardening.** `redirect:'error'` (NIP-05 requires ignoring
  redirects), a bounded `AbortSignal.timeout`, and a size-capped body read
  before `JSON.parse` (previously unbounded `res.json()`).
- **L2 — NIP-05 case-folding.** Both the local part and domain are lowercased
  before querying/looking up, so `Bob@Example.com` matches a server publishing
  `bob`.
- **L3 — `resolveKen` no longer proposes a rotation for a `revoked` entry.**
  Returns it unchanged (no network call), matching the no-`nip05` case.
- **L4 — `verifyKeyControl` gains opt-in `opts` for partial verifier/freshness
  binding** (`expectedCreatedAt`/`maxAgeSec`/`verifierTag`), documented as a
  partial mitigation for a relay/phishing-verifier attack; the full fix needs a
  dedicated event kind (protocol-level, out of this file's scope). Also
  documents that single-use nonce tracking is the consumer's responsibility.
- **L5 — `buildOptOutRequest` rejects a namespace containing a colon** (mirrors
  `buildFilterPublication`'s d-tag misparse guard) and documents the privacy
  exposure of a public opt-out event and its lack of replay/freshness semantics.
- **L7 — documents `parseFilterPublication`'s strict `minEpoch` (`<=`)
  behaviour**: re-reading the same current publication returns `null`,
  indistinguishable from a forgery from the return value alone; recommends
  tracking last-OBSERVED epoch rather than last-accepted, or comparing epochs
  before calling.
- **L8 — `validate.ts` strictness inconsistencies closed:** a malformed
  `bondAssertion` now throws instead of being silently dropped; `pubkey ===
  ownerPubkey` is rejected; `rotation.newPubkey === pubkey` is rejected;
  `displayName` (256 chars), `provenance.locator` (1024 chars — see note below),
  and `annotations.note` (2000 chars) are now length-capped, matching the
  existing `MAX_CORROBORATIONS` cap's rationale. (`provenance.locator`'s cap is
  enforced by callers via a new `capLocator` helper, not inside
  `validateProvenance` itself, which `./companion-rail`'s `landReturnedKen`
  still uses as a pre-truncation structural check on a raw, not-yet-clamped
  claim.)
- **L9 — documents that `tier:'kith'` is a shape, not proof a bond happened.**
  `parseEntry`/`importEntries` accept any syntactically-valid `sharedSecret`;
  kenspeckle cannot authenticate a sync/import source itself, so the consumer
  MUST authenticate/encrypt whatever channel feeds them.
- **M7 — `WireEntry`/`SyncEntry` and `scopeToPersona` are now built with a
  genuinely distributive `Omit`** (`DistributiveOmit<T, K> = T extends unknown ?
  Omit<T, K> : never`, exported from `types.ts`). The previous bare
  `Omit<KindredEntry, 'annotations'>` collapsed to the INTERSECTION of every
  tier's keys (TS's `keyof` of a union), silently dropping `sharedSecret`,
  `provenance`, `relationship` and other tier-specific fields from the type —
  narrowing on `tier` couldn't see them, and `scopeToPersona` hid the mismatch
  behind an `as KindredEntry` cast (now removed; no cast needed). Compile-time
  regression checks live in `types.ts` (not `*.test.ts` — the house `tsconfig`
  excludes test files from `tsc`, and vitest's esbuild transpile doesn't
  type-check, so a `@ts-expect-error`/`expectTypeOf` in a test file would never
  actually run — same reasoning as the pre-existing `_WireAnnotationsExclusionCheck`).

- **core-L8 — invisible characters are stripped from the `companion:<appName>`
  locator segment** (word joiner, BOM, tag characters), and rail display text is
  truncated by code point. Claimed `nip05` values on the return rail now go
  through the strict `validateNip05` rather than a local permissive regex.
- **core-L10 — encrypted backups carry a version header.** Written as
  `"KSBK" ‖ 0x01 ‖ nonce ‖ ciphertext` with the header bound as AAD
  (`BACKUP_FORMAT_VERSION`). Existing header-less backups are still read, so the
  backup key must not be reused elsewhere (SECURITY.md §13).
- **core-L3 — `deriveBondSecret` no longer makes an unused, wiped byte copy of the
  key**, and the docs no longer claim zeroization for it.
- **core-L2 — spoken-word guessing odds documented** (SECURITY.md §10): one word is
  11 bits, so a guess succeeds with about `(2t + 1) / 2048` at tolerance `t`.

### Packaging & CI

- **H1 — `@forgesworn/tessera-kit` stays a pinned git dependency** (a decision,
  not a fix — see the sibling-dependency notes in README/CONTRIBUTING). **New:**
  `scripts/check-publishable-deps.mjs`, wired into `prepack` (which `npm pack` runs — the release pipeline builds its tarball with `npm pack` and then runs `npm publish <tarball>`, which skips `prepublishOnly`) and run as an explicit CI step, fails the
  publish if any `dependencies`/`optionalDependencies`/`peerDependencies` entry is a git/file/http(s)
  spec, with a clear error naming the offending package(s). README, llms.txt,
  and CONTRIBUTING no longer describe a `file:` tarball flow (that was never how
  this repo's lockfile actually resolved the dependency).
- **M6 — `release.yml`'s reusable workflow is pinned to a commit SHA** (was the
  mutable `v0` tag) with the tag in a trailing comment, resolved via `git
  ls-remote`. This job holds `contents: write` + `id-token: write` (npm
  provenance); anyone who could move `v0` upstream previously controlled what
  got published with provenance under this repo's identity.
- **M6/L11 — crypto/protocol dependencies are never auto-merged.**
  `dependabot.yml`'s `production-minor` group now excludes `@noble/*`,
  `@scure/*`, `nostr-tools`, `spoken-token`, and `@forgesworn/*` (they get their
  own individual PR); `dependabot-auto-merge.yml` also refuses to auto-merge any
  PR touching one of them by name, as defense in depth.
- **L10 — `ci.yml`:** adds a top-level `permissions: contents: read`; the
  install-scoped `FORGESWORN_READ_PAT` git-credential rewrite is now explicitly
  revoked immediately after `npm ci` (`if: always()`) instead of staying live in
  the global git config through typecheck/build/vectors/test; fixes the
  `actions/setup-node` pin comment (said `# v6`, the SHA was already `v7.0.0`).
- **L11 — `dependabot.yml`'s `nostr-tools` ignore-rule comment corrected:** it
  claimed "repos pin 2.23.9", but the actual devDependency here is `^2.24.1`.

### Fixed

- **L12 — README:** the `.` API table now lists
  `toGrantView`/`buildGrantEnvelope`/`parseGrantEnvelope` and the grant types
  (previously omitted despite `index.ts` exporting them); the discovery example
  no longer imports the unused `verifyFilterBlob` or reaches past `./discovery`
  into `@forgesworn/tessera-kit` for `parseFilter` (re-exported); `ken.ts`/
  `index.ts` doc comments now say `@forgesworn/kenspeckle/ken` /
  `@forgesworn/kenspeckle/bond` (the actual package name), not bare `kenspeckle/…`.

- **Vectors.** New frozen vectors `vectors/handshake.v1.json` and
  `vectors/bond.words.v1.json` (the words pin spoken-token internals, so a
  dependency bump that changes them fails the build). `scripts/check-vectors.mjs`
  now fails on unrecognised vector prefixes, requires and counts each
  `malformedEnvelopes` item, and checks that revocation clears `pairing` and cannot
  be undone by a newer snapshot.

### Notes

- No stored-entry migration is required for this release: every shape change
  (`KenRotation.rollback?`, the length caps, the `pubkey`/`previousPubkeys` and
  `pubkey`/`ownerPubkey` invariants) is additive or tightens validation of
  already-invalid shapes; a previously-valid entry remains valid.
- Existing encrypted backups remain readable. Invites built by 0.1.x (v1) are no
  longer accepted and must be re-issued.
- Open question (core-M4): PROTOCOL.md calls the handshake nonce a "ceremony counter
  seed" but specifies no derivation from the two nonces to a spoken-word counter.
  kenspeckle implements none; the counter stays the consumer's choice.

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
- **`@forgesworn/tessera-kit` dependency.** Not yet on npm; `package.json` resolves
  it as a **pinned git dependency** (a specific commit, not a moving branch/tag).
  See `[0.2.0]` below for the `prepublishOnly` guard that enforces this cannot
  reach a publish unresolved.
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

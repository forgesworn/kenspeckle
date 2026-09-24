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

Every entry that is still a breaking change is marked **BREAKING** — all of
this section, and the individually marked entries in the sections after it.

### Security — **BREAKING**

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
- **`parseFilterPublication(Result)` now REQUIRES `opts: { namespace, serverId,
  minEpoch?, requireAuthorIsSigner? }`** (moving onto `@forgesworn/tessera-kit`
  0.2.0, which binds every filter-blob signature to a caller-supplied `context`
  string). `opts.namespace`/`opts.serverId` were previously optional — parsed
  out of the event's own d-tag; they are now REQUIRED, and `context` (for the
  kindred convention, `filterSignatureContext(namespace, serverId)`, identical
  to the d-tag value) is built **only** from them, never from the event's own
  tags. This closes cross-server/namespace filter substitution
  **cryptographically**: previously, `pinnedPubkeyHex` (or, since M2 above,
  `requireAuthorIsSigner`) was the only defence against a relay/MITM
  re-serving one deployment's validly-signed blob in place of another's under
  the SAME signing key; `context` binding means a blob signed for the wrong
  deployment fails the in-blob signature check itself, no matter what label
  the serving event wears. New `FilterPublicationRejection` codes
  `'invalid-opts'` (missing/invalid `opts.namespace`/`opts.serverId` — a
  rejection, never a throw) and `'address-mismatch'` (the event's own d-tag
  does not exactly equal `filterSignatureContext(opts.namespace,
  opts.serverId)`, checked before the blob signature). **Removed:**
  `'bad-d-tag'`, `'d-tag-no-colon'`, and `'empty-namespace-or-serverid'` —
  these existed to parse `namespace`/`serverId` OUT of the d-tag, which is no
  longer their source of truth. New export `filterSignatureContext(namespace,
  serverId): string`. `buildFilterPublication` now itself verifies `p.blob`
  against `filterSignatureContext(p.namespace, p.serverId)` and throws if it
  doesn't verify, catching a wrong-context blob before it is ever published.
  `discoverPresent` now also throws on an EMPTY-STRING `saltHex` for a KEYED
  filter (tessera-kit 0.2.0 rejects an empty salt outright — see tessera-kit
  CHANGELOG [0.2.0]). **Migrate:** pass `{ namespace, serverId }` at every
  `parseFilterPublication`/`parseFilterPublicationResult` call site; re-sign
  every stored filter blob with `signFilterBlob(unsigned, priv, context)`
  using the new required `context` argument.
- **`@forgesworn/tessera-kit` is temporarily a `file:../tessera-kit` dependency**
  (was a pinned `git+https://…` dependency), tracking tessera-kit 0.2.0 ahead of
  its npm release. This only resolves in a checkout with `tessera-kit` cloned as
  a sibling directory — `scripts/check-publishable-deps.mjs` (`prepack` + CI)
  correctly refuses to publish while this is the case, unchanged from the
  git-dependency era. Revert to a pinned git commit or a plain semver range
  once tessera-kit 0.2.0 is published.
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
  later envelope (a re-pair starts from a fresh state). `state.pairing.pairedAt`
  is now a floor: any snapshot or revocation with `publishedAt` below it is
  ignored, so a tombstone from an earlier pairing (a re-pair re-derives the same
  rail key and `d` tag) cannot be replayed to kill the new pairing. At or above
  the floor a revocation applies even when its `publishedAt` is not newer than
  the last snapshot. Set `pairedAt` when the pairing is established, no later
  than the request's `t`. `publishedAt`/`addedAt` must be non-negative safe
  integers; `1e400` (`Infinity`) used to freeze the rail and block revocation.
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
  `signet-grant:`/`https:` (or a bare query, with or without the leading `?` of
  `window.location.search`) are accepted; `#fragment`s are ignored;
  input is capped at `PAIRING_INPUT_MAX` (4096) and the challenge at
  `PAIRING_CHALLENGE_MAX` (128) hex characters, also in `buildPairingUri` and
  `parsePairingAck`; a non-finite or negative `nowSec`/`freshnessSeconds` throws
  instead of silently disabling the freshness check.
- **core-L9 — `parseHandshakePayload` rejects** pubkeys that are not valid curve
  points, duplicate personas, and a persona equal to the presenting pubkey.
- **core-L1 — `bondWords` throws** for non-64-hex pubkeys, a self-bond and an empty
  namespace; `verifyBondWord` returns `{ ok: false }` for them instead of throwing.

### Security

- **BREAKING — H2 — `acceptKenRotation` refuses a replay.** Throws if `rotation.accepted` is
  already `true` (a double-click / re-invoked accept could previously append the
  now-current pubkey into `previousPubkeys` again, making `attributeSignature`
  reject the legitimate current key) or if `rotation.newPubkey` equals the
  current pin. `rotation.newPubkey` is re-validated as 64-hex.
- **BREAKING — H3 — a NIP-05 "rollback" to a previously-rotated-away key is flagged, not
  proposed as an ordinary rotation.** `resolveKen` sets `rotation.rollback: true`
  when the resolved key is already in `previousPubkeys` (a compromised/reverted
  domain re-serving an old key). `acceptKenRotation(entry, opts)` refuses a
  flagged rollback unless `opts.allowRevert` is `true`, and — when accepted —
  removes the reverted-to key from `previousPubkeys` before re-adding the old
  current key, so the two never end up in a self-contradictory state.
  `validateEntryShape` (parse/import) repairs rather than rejects a stored ken
  whose `pubkey` appears in its own `previousPubkeys` (the state 0.1.x's H2 bug
  wrote): it drops the current key from `previousPubkeys` and de-duplicates.
  **BREAKING:** it rejects a **pending** rotation (`accepted: false`) whose
  `newPubkey` equals `pubkey`. An **accepted** rotation — `acceptKenRotation`
  leaves `rotation.newPubkey === pubkey` with `accepted: true` — parses, exports
  and restores normally.
- **BREAKING — M1 — strict NIP-05 validation.** `pinKen`, `pinKenFromNip05`,
  `resolveKen` and `resolveNip05` itself (the choke point) all validate a strict
  `local@domain` shape: at least two labels, a last label that is alphabetic
  (2–63 letters) or punycode (`xn--`), no port, no userinfo, no
  path/query/fragment. That rejects an IP literal in every form a URL parser
  accepts, including shorthand such as `127.1`, `0x7f.1` and `10.1`, and any
  all-numeric TLD. Previously only `pinKenFromNip05` validated shape at all, and
  even that check was permissive enough (and bypassable via `pinKen`/import) that
  a crafted `nip05` field could turn `resolveKen` into an arbitrary-URL fetch.
  `parseEntry`/`importEntries` only type-check a stored `nip05`, so data 0.1.x
  wrote still restores; `resolveKen` treats a stored value that fails the strict
  check as unresolvable (returns the entry unchanged, never fetches).
- **BREAKING — M3 — `discoverPresent` throws if a salt is passed to an OPEN filter.**
  Mirrors the existing keyed-without-salt guard: either mismatch previously
  hashed every candidate against the wrong construction and silently returned
  `[]` — a false "no friends here".
- **BREAKING — M4 — `pinKen`/`addCorroboration` run the same provenance validation and
  `MAX_CORROBORATIONS` (64) cap as `importEntries`/`parseEntry`.** A builder
  could previously mint an entry the parser would later refuse — including one
  that exported fine but could never be restored from backup.
- **BREAKING — M5 — `pinKen`/`addCorroboration` reject the reserved `companion:` locator
  prefix.** That prefix is reserved for `landReturnedKen` (`./companion-rail`)
  to mark a RELAYED claim; a first-party call minting one let a companion-app
  claim masquerade as a first-hand confirmation.
- **L1 — NIP-05 fetch hardening.** `redirect:'error'` (NIP-05 requires ignoring
  redirects), a bounded `AbortSignal.timeout`, and a size-capped body read
  before `JSON.parse` (previously unbounded `res.json()`).
- **L2 — NIP-05 case-folding.** Both the local part and domain are lowercased
  before querying/looking up, so `Bob@Example.com` matches a server publishing
  `bob`.
- **BREAKING — L3 — `resolveKen` no longer proposes a rotation for a `revoked` entry.**
  Returns it unchanged (no network call), matching the no-`nip05` case.
- **BREAKING — `acceptKenRotation` now refuses a `revoked` entry.** Throws `ken:
  cannot accept a rotation on a revoked entry`, checked FIRST — before the
  no-pending-rotation check — mirroring `attributeSignature`/`verifyKeyControl`,
  which both check `revoked` before anything else. Previously there was no
  `entry.revoked` guard at all: given an entry that was BOTH revoked and carried
  a pending rotation (proposed before the revoke, or hand-built), `acceptKenRotation`
  would silently move the pin to `rotation.newPubkey` and mark the rotation
  accepted, with no explicit un-revoke step — a revoked pin has no business
  adopting a new key. A caller that genuinely wants to un-revoke and rotate must
  now do so explicitly (clear `revoked` first).
- **L4 — `verifyKeyControl` gains opt-in `opts` for partial verifier/freshness
  binding** (`expectedCreatedAt`/`maxAgeSec`/`verifierTag`), documented as a
  partial mitigation for a relay/phishing-verifier attack; the full fix needs a
  dedicated event kind (protocol-level, out of this file's scope). Also
  documents that single-use nonce tracking is the consumer's responsibility.
- **BREAKING — L5 — `buildOptOutRequest` rejects a namespace containing a colon** (mirrors
  `buildFilterPublication`'s d-tag misparse guard) and documents the privacy
  exposure of a public opt-out event and its lack of replay/freshness semantics.
- **L7 — documents `parseFilterPublication`'s strict `minEpoch` (`<=`)
  behaviour**: re-reading the same current publication returns `null`,
  indistinguishable from a forgery from the return value alone; recommends
  tracking last-OBSERVED epoch rather than last-accepted, or comparing epochs
  before calling.
- **BREAKING — L8 — `validate.ts` strictness inconsistencies closed.** Parse and
  import reject a self-entry (`pubkey === ownerPubkey`) and a pending
  self-rotation (see H3); `pinKen` and `landReturnedKen` now refuse to mint a
  self-entry too. `displayName` (256) and `provenance.locator` (1024) are
  length-capped on the **creation** paths — `pinKen`, `addCorroboration`,
  `landReturnedKen` — measured everywhere in Unicode **code points** (the unit
  the companion rail already slices by), so no builder can mint a value another
  check calls over-length. Parse and import apply no length caps and still drop
  (not reject) a malformed `bondAssertion`, as 0.1.x did, so a backup 0.1.x
  wrote still restores. (`provenance.locator`'s cap is enforced via the
  `capLocator` helper, not inside `validateProvenance` itself, which
  `landReturnedKen` still uses as a pre-truncation structural check on a raw,
  not-yet-clamped claim.)
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

- **BREAKING — core-L8 — invisible characters are stripped from the `companion:<appName>`
  locator segment** (word joiner, BOM, tag characters), and rail display text is
  truncated by code point. Claimed `nip05` values on the return rail now go
  through the strict `validateNip05` rather than a local permissive regex.
- **BREAKING — core-L10 — encrypted backups carry a version header.** Written as
  `"KSBK" ‖ 0x01 ‖ nonce ‖ ciphertext` with the header bound as AAD
  (`BACKUP_FORMAT_VERSION`). Existing header-less backups are still read, so the
  backup key must not be reused elsewhere (SECURITY.md §13). 0.1.x cannot read a
  backup written by this release.
- **core-L3 — `deriveBondSecret` no longer makes an unused, wiped byte copy of the
  key**, and the docs no longer claim zeroization for it.
- **core-L2 — spoken-word guessing odds documented** (SECURITY.md §10): one word is
  11 bits, so a guess succeeds with about `(2t + 1) / 2048` at tolerance `t`.

### Packaging & CI

- **H1 — `@forgesworn/tessera-kit` stays a pinned git dependency** (a decision,
  not a fix — see the sibling-dependency notes in README/CONTRIBUTING). **New:**
  `scripts/check-publishable-deps.mjs`, wired into `prepack` (which `npm pack` runs — the release pipeline builds its tarball with `npm pack` and then runs `npm publish <tarball>`, which skips `prepublishOnly`) fails the
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
  `@scure/*`, `nostr-tools`, `nostr-attestations`, `spoken-token`, and `@forgesworn/*` (they get their
  own individual PR); `dependabot-auto-merge.yml` also refuses to auto-merge any
  PR touching one of them by name, as defense in depth.
- **L10 — `ci.yml`:** adds a top-level `permissions: contents: read`; the
  install-scoped `FORGESWORN_READ_PAT` git-credential rewrite is now explicitly
  revoked immediately after `npm ci` (`if: always()`) instead of staying live in
  the global git config through typecheck/build/vectors/test; fixes the
  `actions/setup-node` pin comment (said `# v6`, the SHA was already `v7.0.0`).
- **L11 — `dependabot.yml`'s `nostr-tools` ignore-rule comment corrected:** it
  claimed "repos pin 2.23.9", but the actual devDependency here is `^2.24.1`.

### Added

- **`./bond` — ceremony counter derivation.** `deriveCeremonyCounter(nonceAHex,
  nonceBHex)` resolves the core-M4 open question below: both bond-ceremony
  parties derive the SAME `counter` from their two handshake nonces
  (`SHA-256(utf8('kindred:bond:counter') ‖ 0x00 ‖ lo ‖ hi)`, `lo`/`hi` the
  ascending-byte-order pair; digest's first 4 bytes as a big-endian uint32),
  symmetric in argument order. New const `CEREMONY_COUNTER_TAG`.
  `timeCounter(nowSec, periodSec)` supports a later time-bucketed
  re-verification (`Math.floor(nowSec / periodSec)`, which must fit uint32 —
  it throws otherwise, rather than clamping). New
  frozen vector `vectors/bond.counter.v1.json` (independently computed with
  python3 `hashlib`, wired into `scripts/check-vectors.mjs`). See PROTOCOL.md
  §2 and §7.1.
- **`./bond` — spoken-word normalisation.** `normalizeSpokenWord(s)` (NFKC +
  trim + lowercase) is now applied to `spoken` inside `verifyBondWord` before
  the constant-time compare, so "Fruit ", " FRUIT" and "fruit" all verify
  identically — spoken-token's own wordlist is already lowercase, so this only
  forgives how a human said or typed the word back.
- **`./discovery` — `parseFilterPublicationResult(event, opts)`.** Additive
  alongside `parseFilterPublication`: returns `{ ok: true, value } | { ok:
  false, reason: FilterPublicationRejection }`, naming which check failed
  instead of collapsing every rejection to `null`. `parseFilterPublication` is
  now a thin wrapper over this (`r.ok ? r.value : null`) — its behaviour is
  unchanged. (`opts` became REQUIRED, and the check list changed, in the later
  tessera-kit-0.2.0 entry above — this entry documents when the function was
  first added.)
- **Packaging.** `exports` gains `"./package.json"`. New `test:coverage`
  (`vitest run --coverage`, via new devDependency `@vitest/coverage-v8`) and
  `lint:package` (`publint && attw --pack . --profile esm-only`, via new
  devDependencies `publint` and `@arethetypeswrong/cli`) scripts. CI now runs
  the full suite on Node 22 **and** 24, plus `lint:package` and `npm pack
  --dry-run`.

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
  be undone by a newer snapshot. `vectors/invite.v2.json` gains cases that freeze
  the canonical JSON escaping (non-ASCII, `"`, `\`, control characters, and the
  characters `JSON.stringify` leaves raw), generated from hand-written canonical
  text by `scripts/gen-invite-escape-vectors.mjs`.
- **README/llms.txt** show the current `disclosureFor(filter)` and
  `buildBondRevocation({ subjectPubHex, reason? })` signatures.

### Notes

- No stored-entry migration is required for this release. Parse and import stay
  tolerant of what 0.1.x wrote: over-length strings, a permissive `nip05`, a
  malformed `bondAssertion` (dropped) and a `previousPubkeys` holding the current
  key (normalised) all still restore. **BREAKING:** two shapes are now rejected
  at parse/import — a self-entry (`pubkey === ownerPubkey`) and a pending
  rotation whose `newPubkey` equals `pubkey` — and because `importEntries` is
  all-or-nothing, a backup holding either fails to restore as a whole.
- Existing encrypted backups remain readable. Invites built by 0.1.x (v1) are no
  longer accepted and must be re-issued.
- Resolved (core-M4): PROTOCOL.md called the handshake nonce a "ceremony counter
  seed" but specified no derivation from the two nonces to a spoken-word counter.
  This is now `deriveCeremonyCounter` (see Added, above, and PROTOCOL.md §7.1);
  a consumer doing an in-person ceremony should use it instead of picking its
  own counter.

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

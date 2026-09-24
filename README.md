# @forgesworn/kenspeckle

**Verified relationships across three social distances — `kin` (family), `kith` (mutually verified), `ken` (one-way recognised) — with the handshake, bond ceremony, ken trust-store, local presence discovery, and invite flows. Protocol-neutral, pure functions, no storage, no graph traversal.**

[![npm](https://img.shields.io/npm/v/%40forgesworn%2Fkenspeckle)](https://www.npmjs.com/package/%40forgesworn%2Fkenspeckle)
[![licence](https://img.shields.io/npm/l/%40forgesworn%2Fkenspeckle)](https://github.com/forgesworn/kenspeckle/blob/main/LICENSE)
![TypeScript](https://img.shields.io/badge/TypeScript-native-blue)
![ESM only](https://img.shields.io/badge/module-ESM--only-informational)

## The problem

An app wants to hold a user's relationships — family, people they've met and
verified, public keys they recognise — **without** becoming a social network: no
feed, no follower count, no central social graph, no shadow profiles. It also wants
two ceremonies most contact systems lack: a **bond** (two people mutually verify
each other out-of-band by speaking short rotating words from a shared secret) and a
**live key-control challenge** (a public figure proves an in-game account really
holds the key you pinned).

kenspeckle is those primitives as plain data + pure functions. It does **not** store
anything, render anything, or traverse a graph (those are explicit non-goals). It
holds relationships, derives ceremony words, pins and challenges recognised keys,
and tests a user's own contacts against a server's published presence filter
(via the sibling [`@forgesworn/tessera-kit`](https://github.com/forgesworn/tessera-kit)) —
**locally**, never uploading contacts.

> **Naming.** *kenspeckle* (Scots: **easily recognised, known by sight**) was
> developed as `@forgesworn/kindred` and renamed before first publish — "Kindred"
> is now the ForgeSworn app-suite brand. The **wire protocol keeps the historical
> `kindred` naming, frozen**: `'kindred:bond'`, `'kindred:members:'`,
> `'kindred-bond'`, kinds 30444/30445, and the `KINDRED_*` / `KindredEntry` /
> `KindredTier` identifiers are unchanged — renaming them would change every
> deployed bond word and published filter.

> **Honest scope (read [SECURITY.md](./SECURITY.md)):** persona-scoping is a
> consumer obligation kenspeckle *assists but cannot guarantee* (no storage). NIP-05 is
> a DNS/TLS/HTTP **TOFU** anchor, **not** key-continuity. `attributeSignature` alone
> is **replayable** — impersonation resistance needs `verifyKeyControl` against a
> fresh nonce. Private annotations are **never** serialised. A forged presence filter
> is a doxxing primitive — verify it against a **pinned** server key.

## Install

```bash
npm i @forgesworn/kenspeckle
```

ESM-only, Node ≥ 22. `nostr-tools` is a **peer** dependency (so you and kenspeckle
share one event type) — install it alongside.

### The `@forgesworn/tessera-kit` sibling dependency

kenspeckle depends on [`@forgesworn/tessera-kit`](https://github.com/forgesworn/tessera-kit), a
sibling that is **not yet on npm**. `package.json` currently resolves it as a
**pinned git dependency** (a `git+https://github.com/forgesworn/tessera-kit.git#<commit>`
spec — a specific commit, not a moving branch/tag), which `npm ci`/`npm install`
clone directly; nothing to pack or symlink locally. Cloning that private repo needs
read access — CI authenticates via a short-lived, install-scoped PAT (see
`.github/workflows/ci.yml`); an external installer needs their own read access to
`forgesworn/tessera-kit` (or the maintainers to publish it to npm) for `npm i
@forgesworn/kenspeckle` to succeed. A `scripts/check-publishable-deps.mjs` guard
runs in `prepack` and CI and **refuses to publish** while any `dependencies` /
`optionalDependencies` / `peerDependencies` entry is a git/file/http(s) spec — so kenspeckle cannot ship to
npm with this dependency unresolved to a registry version. Once
`@forgesworn/tessera-kit` is published, repoint this dependency to a plain npm
semver range before the next `kenspeckle` publish.

## Quick start

### kith — handshake → ECDH bond → spoken-word ceremony

Two people exchange a handshake, derive the **byte-exact** shared secret, then read
each other short rotating words. The word I *speak* differs from the word I *expect*
(directional — the listener can't parrot it back).

```typescript
import { buildHandshakePayload, parseHandshakePayload } from '@forgesworn/kenspeckle/handshake'
import { deriveBondSecret, bondWords, verifyBondWord } from '@forgesworn/kenspeckle/bond'

// (1) I present my persona + a fresh nonce over QR/NFC/relay; they parse it.
const blob = buildHandshakePayload({ pubkey: myPubHex, nonce: my16ByteHexNonce })
const theirs = parseHandshakePayload(receivedBytes) // validates; displayName is VERBATIM

// (2) Each side derives the SAME ECDH secret. (myPriv × their x-only pubkey, hash x.)
const secret = deriveBondSecret(myPrivHex, theirs.pubkey)

// (3) Read words for an agreed counter. I say `mine`; I expect to hear `theirs`.
const { mine } = bondWords(secret, myPubHex, theirs.pubkey, counter)
speakAloud(mine)

// (4) Verify what THEY spoke (constant-time compare under the hood).
const result = verifyBondWord(secret, myPubHex, theirs.pubkey, counter, whatTheySaid)
if (result.ok) { /* bonded — persist a KithEntry, encrypt sharedSecret at rest */ }
```

> **Migrating from signet-app's `signet-me`?** By DEFAULT `bondWords` uses namespace `'kindred:bond'`,
> so its words **differ** from `signet-me`'s (`'signet:me'`) — a naive migration changes the words.
> To cross-verify with a peer who hasn't migrated yet, reproduce `signet-me`'s words by passing
> `bondWords(secret, myPub, theirPub, counter, { namespace: 'signet:me' })` and
> `verifyBondWord(…, { namespace: 'signet:me', tolerance: 1 })` (each seat passes its OWN pubkey first).
> Both peers must either upgrade together or pass this signet-me namespace.

### ken — pin a public figure, then prove LIVE control

`attributeSignature` ("did the pinned key sign this old event?") is **replayable**.
To bind an in-game account to the real key, issue a **fresh nonce** and verify the
claimant signs it.

```typescript
import { pinKenFromNip05, buildKeyControlChallenge, verifyKeyControl } from '@forgesworn/kenspeckle/ken'

// Pin via NIP-05 — refuses to pin unless the name resolves (TOFU; HTTPS-only fetch).
const entry = await pinKenFromNip05('mrbeast@example.com', myGamingPersonaPubHex, fetch)

// Live challenge: the claimant signs an event whose `content` IS the nonce.
const { nonce } = buildKeyControlChallenge()
const signed = await askClaimantToSign(nonce) // their client builds + signs it
const proof = verifyKeyControl(entry, nonce, signed)
if (proof.ok) { /* the account in front of me holds the pinned key, live (no replay) */ }
```

### discovery — "which of my contacts are here?" (locally)

A server publishes a signed, non-enumerable presence filter (`@forgesworn/tessera-kit`). The
client parses it, **verifies it against a pinned server key**, then tests its own
contacts — scoped to one persona.

```typescript
// `parseFilter` is re-exported from `./discovery` (it delegates to `@forgesworn/tessera-kit`
// internally) so a consumer importing only kenspeckle's discovery subpath never has to reach past
// it into tessera-kit directly.
import { discoverPresent, parseFilter, parseFilterPublication } from '@forgesworn/kenspeckle/discovery'

// Pull the kind-30444 publication; verifies BOTH the Nostr event sig and the in-blob Schnorr sig,
// and — since 0.2.0 — that the event's signer IS the in-blob signer (`requireAuthorIsSigner`,
// default true), binding the namespace/serverId in the d-tag to what the server actually signed.
// Returns null on any failure.
const pub = parseFilterPublication(rawWireEvent) // pass the RAW event — not a spread-mutated one
if (!pub) throw new Error('untrusted publication')

// Provenance gate: the IN-BLOB signer must be a key you pinned out-of-band.
if (pub.signerPubkeyHex !== PINNED_SERVER_PUBKEY) throw new Error('unpinned server')

// Test MY contacts, scoped to one persona (throws on mixed-owner input — anti-correlation; also
// throws if a salt is passed to an OPEN filter, or omitted for a KEYED one — either mismatch
// silently matches nothing otherwise).
const filter = parseFilter(pub.blob)
const present = discoverPresent(filter, myEntries, myGamingPersonaPubHex /*, salt if keyed */)
// `present` is a CANDIDATE list — confirm-on-connect with a ken key-control challenge before acting.
```

## API by subpath

The `.` entry carries the model + local ops; the protocol ceremonies are **separate
subpaths** (so a consumer that only needs `./bond` doesn't pull the discovery /
@forgesworn/tessera-kit graph).

### `.` (model + local ops)

| Export | Purpose |
|--------|---------|
| types `KindredTier`, `KindredEntry` (`KinEntry`/`KithEntry`/`KenEntry`), `MutualEntry`, `KenProvenance`, `KenRotation`, `PrivateAnnotations`, `WireEntry`, `SyncEntry`, `DistributiveOmit` | the relationship model — `KenEntry.corroborations?` records *additional independent* channels agreeing (`provenance` stays the required, singular primary). `WireEntry`/`SyncEntry` are built with `DistributiveOmit` so narrowing on `tier` still sees tier-specific fields (`sharedSecret`, `provenance`, `relationship`, …) |
| `EventTemplate`, `NostrEvent`, `NostrFilter` | re-exported `nostr-tools` aliases — **one** canonical event type |
| `hasSharedSecret(entry)` | type predicate — narrows to the kin/kith arms that carry a `sharedSecret` |
| `scopeToPersona(entry, personaPubkeyHex)` / `assertOwnedPersona(personaPubkeyHex, myLeaves)` | persona scoping (the latter throws unless owned) |
| `searchEntries(entries, query)` | local search over name / pubkey / **annotations** (searchable locally, never serialised) |
| `linkForRecall(entries, ids)` / `unlink(entries, pubkey)` | private "these pubkeys are one human" grouping (mutates in place) |
| `toWire(e)` / `serializeEntry(e)` | **true wire-safe** view + **byte-stable** canonical JSON — strips **both** `annotations` **and** `sharedSecret` (0.2.0: previously only `annotations`). Safe to hand to any third party. A kin/kith `WireEntry` therefore does **not** round-trip through `parseEntry` — the secret's absence is intentional, not a bug |
| `toSyncForm(e)` / `serializeEntryForSync(e)` | KEEPS `sharedSecret` (strips only `annotations`) — for the ONE legitimate case that needs the secret to travel: syncing a roster across the user's OWN devices over an already-private/authenticated transport. **Never** publish this output |
| `parseEntry(s)` | hardened parse; reconstructs `serializeEntryForSync`'s output (requires `sharedSecret` for kin/kith either way) |
| `exportEntriesEncrypted(entries, key)` / `importEntries(blob, key)` | XChaCha20-Poly1305 self-backup — **includes** annotations (the user's own sealed copy, not a graph disclosure). Backups now carry a `KSBK` version header; older (pre-header) backups are still readable by `importEntries` |
| `toGrantView(entry)` / `buildGrantEnvelope(scope, views, publishedAt, opts?)` / `parseGrantEnvelope(s)` | companion data-rail envelope: a secret-stripped "read & pick" contact view (`GrantContactView` — structurally omits `sharedSecret`/`annotations`/`bondAssertion`/`provenance`) a companion app can be granted, scoped by tier/persona (`GrantScope`) |

### `./companion-rail`

Pure wire ownership shared by Signet producers and companion consumers:
`buildPairingUri` / `parsePairingRequest`, `buildPairingAck` /
`parsePairingAck`, `applyCompanionSnapshot`, the pairing/snapshot types, and
the frozen `ACK_KIND`, `SNAPSHOT_KIND`, and `SNAPSHOT_D_TAG` constants. Relay
subscriptions, encryption, device keys, clocks, storage, retry policy and UI
remain in the consuming app.

**Return rail** — `WireKen`, `buildReturnEnvelope` / `parseReturnEnvelope`,
`landReturnedKen`, and the `RETURN_D_TAG` / `RETURN_ADDITIONS_CAP` /
`RETURN_CORROBORATIONS_CAP` constants. A companion app holds no identity keys, so
it can never mint a kith/kin bond — it can only **propose a ken**. It *can*,
however, carry the provenance it **claims** (`claimedProvenance` /
`claimedCorroborations`): the companion is often where the evidence actually is,
and scanning someone's code while standing next to them is real `in-person`
provenance. `landReturnedKen` preserves that claim as a **corroboration**
namespaced `companion:<appName>:<locator>` (with `confirmedAt` clamped to now),
while the primary `provenance` stays `{ source:'manual',
locator:'companion:<appName>' }` — what Signet can attest itself. A claim is
preserved, never promoted: **no app but Signet is a source of identity truth.**

### `./handshake`

`buildHandshakePayload(p)` → bytes; `parseHandshakePayload(blob)` (8192-byte cap,
all fields validated, `displayName` returned **verbatim**). Type `HandshakePayload`.

### `./bond`

`deriveBondSecret(myPrivHex, theirPubHex)` (byte-exact ECDH); `bondWords(secret,
aPub, bPub, counter, opts?)` → `{ mine, theirs }`; `verifyBondWord(…, spoken, opts?)`
→ `{ ok }`; `buildBondAttestation({ subjectPubHex, summary? })` → kind-31000
`EventTemplate` (`type:'kindred-bond'`).

Retracting a bond: `buildBondRevocation({ subjectPubHex, reason? })` is now the
**primary** way to retract — it emits a kind-31000 `["status","revoked"]` event
(nostr-attestations `createRevocation`) at the SAME addressable slot, so it
replaces the attestation and `verifyBondAttestation` rejects it as `revoked`. Sign
it with the key that signed the attestation.
`retractBondAssertion(assertion, { attesterPubHex, subjectPubHex })` remains as a
supplement: a kind-5 NIP-09 deletion carrying `e` (the attestation event id), `a`
(its addressable coordinate) and `k` (kind `31000`) tags.
Const `KINDRED_BOND_NAMESPACE`. The optional `opts`
(`{ namespace? }`, plus `tolerance?` on `verifyBondWord`)
exist for **signet-me migration compatibility** — `{ namespace: 'signet:me',
tolerance: N }` reproduces signet-app's `signet-me` words so a
migrated contact can cross-verify with an un-migrated peer; defaults
(`'kindred:bond'` + `tolerance 0`) keep the existing behaviour but
**differ** from signet-me's words.

### `./ken`

`pinKen(p)` / `pinKenFromNip05(nip05, ownerPubkeyHex, fetch)` (refuse-on-mismatch
TOFU); `buildKeyControlChallenge()`; `verifyKeyControl(entry, nonce, signedEvent,
opts?)` (**live**, fail-closed; `opts.expectedCreatedAt`/`maxAgeSec`/`verifierTag`
are an OPT-IN, backward-compatible partial mitigation for a verifier-relay attack —
see the doc comment); `attributeSignature(entry, event)` (**replayable** — credit,
don't authenticate); `resolveKen` (propose-not-flip; a NIP-05 resolving to a key
already in `previousPubkeys` is flagged `rotation.rollback: true` rather than
proposed as an ordinary rotation) / `acceptKenRotation(entry, opts?)` (throws if
already accepted, if `newPubkey` equals the current pin, or — unless `opts:
{ allowRevert: true }` — if the rotation is a flagged rollback) / `revokeKen` /
`dropKen` (consumer deletes).

Both `pinKen` and `addCorroboration(entry, provenance)` run the SAME provenance
validation, the same `MAX_CORROBORATIONS` (64) cap, and reject the reserved
`companion:` locator prefix — a builder can no longer mint an entry the parser
would then refuse.

`addCorroboration(entry, provenance)` records **another independent channel**
agreeing this key is this person — pure, appends in observation order, never
touches the primary `provenance`, and deliberately does **not** de-duplicate (a
re-check a year later is new recency evidence). `summarizeKenProvenance(entry)`
reports `{ confirmations, claimed, distinctSources, distinctLocators, sources,
mostRecentAt, oldestAt }`.

**NIP-05 handling.** Every entry point that can fetch a `nip05` (`pinKen`,
`pinKenFromNip05`, `resolveKen`) validates a STRICT `local@domain` shape — no
port, no userinfo, no path/query/fragment, and a last label that is alphabetic or
`xn--`, so no IP literal in any form (`127.1`, `0x7f.1` included). The parser keeps
a stored `nip05` that 0.1.x accepted; `resolveKen` treats one that fails the strict
check as unresolvable and never fetches it. The fetch is
hardened: `redirect:'error'` (NIP-05 requires ignoring redirects), a bounded
timeout, a size-capped body read before `JSON.parse`, and both halves lowercased
before querying/looking up (NIP-05 names are case-insensitive).

`claimed` is the one to render alongside any total. A ken landed from a companion
app can show **six confirmations across six distinct sources with nothing verified
first-hand** — every record is a relayed claim. `claimed` counts the records in the
reserved `companion:` locator namespace, so `confirmations - claimed` is what was
actually confirmed first-hand. Show a total without it and you present relayed
claims as verification.

It returns **facts, not a trust score** — on purpose. A scalar "strength" invites
false precision and invites being used as an authorization input
(`if (strength > 0.7) allow`), which is a security decision this primitive cannot
underwrite; and weighting channels against each other (is one `in-person` worth
two `nip05`?) is *consumer policy*, not a property of the data. It is also honest
about its limits: `distinctSources` can **understate** independence (two different
websites are both `web`) and `distinctLocators` can **overstate** it (one operator
can serve two locators; DNS and the site behind it often share one point of
compromise). Signals, not guarantees.

### `./discovery`

`discoverPresent(filter, entries, ownerPubkey, saltHex?)` (throws on mixed persona;
**also** throws if `saltHex` is given for an OPEN filter or omitted for a KEYED
one — either mismatch would otherwise silently match nothing, a false "no friends
here"); `disclosureFor(filter: MembershipFilter)` → `DiscoveryDisclosure` (pass the filter `parseFilter` returned); `buildFilterPublication(p)`
/ `parseFilterPublication(event, opts?)` (verifies the Nostr event sig, the in-blob
Schnorr sig, **and** — `opts.requireAuthorIsSigner`, default `true`, since 0.2.0 —
that the event's signer IS the in-blob signer, so the namespace/serverId the event
asserts are transitively bound to what the server signed; pass `{
requireAuthorIsSigner: false }` to opt out for a different trust model. Returns
`null`, never throws); `aggregatorQuery(namespace)`; `buildOptOutRequest(p,
memberPrivHex)`. Re-exports `parseFilter` from `@forgesworn/tessera-kit`. Consts
`KINDRED_FILTER_KIND = 30444`, `KINDRED_OPTOUT_KIND = 30445`.

### `./invite`

`buildJoinInvite(p, inviterPrivHex)` → `JoinInvite` **object**;
`parseJoinInvite(blob, now?)` (verifies sig + expiry); `verifyBondAttestation(event,
now?)` → `{ ok, reason?, attesterPubHex?, subjectPubHex? }` (single-attestation
only — **no** counting/graph; fails with a `reason` for a revoked, expired,
not-yet-active, or self-attestation). Type `JoinInvite`.

**Invites are v2 only.** Every `JoinInvite` carries `v: 2`. The signed digest is
`sha256(JSON.stringify(['kenspeckle-invite', 2, namespace, serverId,
inviterPubkey, nonce, expiresAt ?? null]))`. `nonce` must be at least 16 bytes of
hex; `expiresAt`, when present, must be a non-negative safe integer; and a lone
UTF-16 surrogate anywhere in the invite's string fields is rejected (it would
serialise to different bytes depending on the JSON encoder / platform, breaking
the byte-exact digest).

Exact byte layouts (the ECDH construction + frozen vector, invite canonical bytes,
kind/tag shapes, build/parse asymmetry) are in **[PROTOCOL.md](./PROTOCOL.md)**.

## Security

kenspeckle makes **narrow, honest** claims — read **[SECURITY.md](./SECURITY.md)**. The
short version:

- **Persona-scoping is a consumer obligation** kenspeckle assists (`discoverPresent`
  enforces single-owner input) but **cannot guarantee** (no storage).
- **Private annotations are never serialised** (type-level + runtime); they ARE in
  the user's own encrypted backup (allowed — not a graph disclosure).
- **kith/kin shared secrets are never published** — `toWire`/`serializeEntry` strip
  `sharedSecret` structurally (0.2.0; previously only `annotations` was excluded).
  Cross-device sync of your OWN devices, which genuinely needs the secret to
  travel, uses the separately-named `toSyncForm`/`serializeEntryForSync` instead —
  never publish that output.
- **NIP-05 is TOFU, not key-continuity** — a key-change is propose-only, never
  auto-accept; require user confirmation. A rollback to a key already in
  `previousPubkeys` (a compromised/reverted domain re-serving an old key) is
  flagged distinctly and `acceptKenRotation` refuses it without an explicit
  `{ allowRevert: true }`. `acceptKenRotation` also refuses an already-accepted
  rotation, so it can never double-append the current key into its own history.
- **`attributeSignature` is replayable** — use `verifyKeyControl` (fresh nonce) for
  impersonation resistance.
- **Verify filter publications against a pinned key** — check the Nostr sig AND the
  in-blob Schnorr sig; pass the **raw** wire event (a spread-mutated one carries a
  stale `Symbol(verified)` false-green). Since 0.2.0, `parseFilterPublication` also
  requires the event's signer to equal the in-blob signer by default
  (`requireAuthorIsSigner`), binding the namespace/serverId the event asserts to
  what the server actually signed.
- **Discovery is opt-in + exit-able, but you cannot cryptographically verify
  removal** from a pool you left. Real member privacy = per-context personas.
- **`tier:'kith'` is a shape, not proof a bond happened.** `parseEntry`/
  `importEntries` accept any syntactically-valid 64-hex `sharedSecret` — kenspeckle
  cannot itself confirm a real `deriveBondSecret` ceremony occurred.
  **Authenticate/encrypt whatever channel feeds `parseEntry`/`importEntries`**; an
  unauthenticated sync source could otherwise escalate a one-way `ken` into a
  mutually-trusted-looking `kith`.

## Toolkit

kenspeckle is the relationships brick of the **Forgesworn / Signet** ecosystem. It
composes:

- [`@forgesworn/tessera-kit`](https://github.com/forgesworn/tessera-kit) — the non-enumerable
  membership-presence filter `kenspeckle/discovery` is a thin layer over.
- [`spoken-token`](https://github.com/forgesworn/spoken-token) — the directional
  verification words the bond ceremony speaks.
- [`nostr-attestations`](https://github.com/forgesworn/nostr-attestations) — the
  co-signed bond assertions (kind-31000).
- [`nsec-tree`](https://github.com/forgesworn/nsec-tree) — hierarchical persona key
  derivation (the `ownerPubkey` scoping; kenspeckle needs only the type relationship).

Consumed by **signet-app** (the user-facing identity app): it maps its `Contact`
record onto `KinEntry`/`KithEntry`/`ken`, persists `KindredEntry` in IndexedDB, and
keeps tier/badge enrichment app-side. The byte-exact ECDH (PROTOCOL.md §1) is what
makes that migration lossless.

## Licence

MIT.

# @forgesworn/kindred

**Verified relationships across three social distances — `kin` (family), `kith` (mutually verified), `ken` (one-way recognised) — with the handshake, bond ceremony, ken trust-store, local presence discovery, and invite flows. Protocol-neutral, pure functions, no storage, no graph traversal.**

[![npm](https://img.shields.io/npm/v/%40forgesworn%2Fkindred)](https://www.npmjs.com/package/%40forgesworn%2Fkindred)
[![licence](https://img.shields.io/npm/l/%40forgesworn%2Fkindred)](https://github.com/forgesworn/kindred/blob/main/LICENSE)
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

kindred is those primitives as plain data + pure functions. It does **not** store
anything, render anything, or traverse a graph (those are explicit non-goals). It
holds relationships, derives ceremony words, pins and challenges recognised keys,
and tests a user's own contacts against a server's published presence filter
(via the sibling [`@forgesworn/tessera-kit`](https://github.com/forgesworn/tessera-kit)) —
**locally**, never uploading contacts.

> **Honest scope (read [SECURITY.md](./SECURITY.md)):** persona-scoping is a
> consumer obligation kindred *assists but cannot guarantee* (no storage). NIP-05 is
> a DNS/TLS/HTTP **TOFU** anchor, **not** key-continuity. `attributeSignature` alone
> is **replayable** — impersonation resistance needs `verifyKeyControl` against a
> fresh nonce. Private annotations are **never** serialised. A forged presence filter
> is a doxxing primitive — verify it against a **pinned** server key.

## Install

```bash
npm i @forgesworn/kindred
```

ESM-only, Node ≥ 22. `nostr-tools` is a **peer** dependency (so you and kindred
share one event type) — install it alongside.

### The `@forgesworn/tessera-kit` sibling constraint (read this before publishing)

kindred depends on [`@forgesworn/tessera-kit`](https://github.com/forgesworn/tessera-kit), a
sibling that **is not yet on npm**. For **local development**, build and pack it,
then install the tarball:

```bash
cd ../tessera-kit && npm pack          # produces forgesworn-tessera-kit-0.1.0.tgz
cd ../kindred && npm install ../tessera-kit/forgesworn-tessera-kit-0.1.0.tgz
```

The lockfile then carries a `file:` path to the sibling. **To publish kindred,
`@forgesworn/tessera-kit` must be published to npm first — do NOT ship a `file:` dep.** A
`file:` link in a published package masks unpublished sibling changes and breaks
external installs (a hard-won signet-app lesson). Publish the sibling, repoint the
dependency to the npm version, then publish kindred.

## Quick start

### kith — handshake → ECDH bond → spoken-word ceremony

Two people exchange a handshake, derive the **byte-exact** shared secret, then read
each other short rotating words. The word I *speak* differs from the word I *expect*
(directional — the listener can't parrot it back).

```typescript
import { buildHandshakePayload, parseHandshakePayload } from '@forgesworn/kindred/handshake'
import { deriveBondSecret, bondWords, verifyBondWord } from '@forgesworn/kindred/bond'

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
import { pinKenFromNip05, buildKeyControlChallenge, verifyKeyControl } from '@forgesworn/kindred/ken'

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
import { parseFilter, verifyFilterBlob } from '@forgesworn/tessera-kit'
import { discoverPresent, parseFilterPublication } from '@forgesworn/kindred/discovery'

// Pull the kind-30444 publication; verify the Nostr sig + decode (returns null on any failure).
const pub = parseFilterPublication(rawWireEvent) // pass the RAW event — not a spread-mutated one
if (!pub) throw new Error('untrusted publication')

// Provenance gate: the IN-BLOB signer must be a key you pinned out-of-band.
if (pub.signerPubkeyHex !== PINNED_SERVER_PUBKEY) throw new Error('unpinned server')

// Test MY contacts, scoped to one persona (throws on mixed-owner input — anti-correlation).
const filter = parseFilter(pub.blob)
const present = discoverPresent(filter, myEntries, myGamingPersonaPubHex /*, salt if keyed */)
// `present` is a CANDIDATE list — confirm-on-connect with a ken key-control challenge before acting.
```

## API by subpath

The `.` entry carries the model + local ops; the five ceremonies are **separate
subpaths** (so a consumer that only needs `./bond` doesn't pull the discovery /
@forgesworn/tessera-kit graph).

### `.` (model + local ops)

| Export | Purpose |
|--------|---------|
| types `KindredTier`, `KindredEntry` (`KinEntry`/`KithEntry`/`KenEntry`), `MutualEntry`, `KenProvenance`, `KenRotation`, `PrivateAnnotations`, `WireEntry` | the relationship model |
| `EventTemplate`, `NostrEvent`, `NostrFilter` | re-exported `nostr-tools` aliases — **one** canonical event type |
| `hasSharedSecret(entry)` | type predicate — narrows to the kin/kith arms that carry a `sharedSecret` |
| `scopeToPersona(entry, personaPubkeyHex)` / `assertOwnedPersona(personaPubkeyHex, myLeaves)` | persona scoping (the latter throws unless owned) |
| `searchEntries(entries, query)` | local search over name / pubkey / **annotations** (searchable locally, never serialised) |
| `linkForRecall(entries, ids)` / `unlink(entries, pubkey)` | private "these pubkeys are one human" grouping (mutates in place) |
| `toWire(e)` / `serializeEntry(e)` / `parseEntry(s)` | wire view + **byte-stable** canonical JSON (annotations **excluded**) + hardened parse |
| `exportEntriesEncrypted(entries, key)` / `importEntries(blob, key)` | XChaCha20-Poly1305 self-backup — **includes** annotations (the user's own sealed copy, not a graph disclosure) |

### `./handshake`

`buildHandshakePayload(p)` → bytes; `parseHandshakePayload(blob)` (8192-byte cap,
all fields validated, `displayName` returned **verbatim**). Type `HandshakePayload`.

### `./bond`

`deriveBondSecret(myPrivHex, theirPubHex)` (byte-exact ECDH); `bondWords(secret,
aPub, bPub, counter, opts?)` → `{ mine, theirs }`; `verifyBondWord(…, spoken, opts?)`
→ `{ ok }`; `buildBondAttestation({ subjectPubHex, summary? })` → kind-31000
`EventTemplate` (`type:'kindred-bond'`); `retractBondAssertion(assertion)` → kind-5.
Const `KINDRED_BOND_NAMESPACE`. The optional `opts`
(`{ namespace? }`, plus `tolerance?` on `verifyBondWord`)
exist for **signet-me migration compatibility** — `{ namespace: 'signet:me',
tolerance: N }` reproduces signet-app's `signet-me` words so a
migrated contact can cross-verify with an un-migrated peer; defaults
(`'kindred:bond'` + `tolerance 0`) keep the existing behaviour but
**differ** from signet-me's words.

### `./ken`

`pinKen(p)` / `pinKenFromNip05(nip05, ownerPubkeyHex, fetch)` (refuse-on-mismatch
TOFU); `buildKeyControlChallenge()`; `verifyKeyControl(entry, nonce, signedEvent)`
(**live**, fail-closed); `attributeSignature(entry, event)` (**replayable** — credit,
don't authenticate); `resolveKen` (propose-not-flip) / `acceptKenRotation` /
`revokeKen` / `dropKen` (consumer deletes).

### `./discovery`

`discoverPresent(filter, entries, ownerPubkey, saltHex?)` (throws on mixed persona);
`disclosureFor({ salt? })` → `DiscoveryDisclosure`; `buildFilterPublication(p)` /
`parseFilterPublication(event, opts?)` (verifies **both** signatures — returns
`null`, never throws); `aggregatorQuery(namespace)`; `buildOptOutRequest(p,
memberPrivHex)`. Re-exports `parseFilter` from `@forgesworn/tessera-kit`. Consts
`KINDRED_FILTER_KIND = 30444`, `KINDRED_OPTOUT_KIND = 30445`.

### `./invite`

`buildJoinInvite(p, inviterPrivHex)` → `JoinInvite` **object**;
`parseJoinInvite(blob, now?)` (verifies sig + expiry); `verifyBondAttestation(event)`
→ `{ ok, attesterPubHex?, subjectPubHex? }` (single-attestation only — **no**
counting/graph). Type `JoinInvite`.

Exact byte layouts (the ECDH construction + frozen vector, invite canonical bytes,
kind/tag shapes, build/parse asymmetry) are in **[PROTOCOL.md](./PROTOCOL.md)**.

## Security

kindred makes **narrow, honest** claims — read **[SECURITY.md](./SECURITY.md)**. The
short version:

- **Persona-scoping is a consumer obligation** kindred assists (`discoverPresent`
  enforces single-owner input) but **cannot guarantee** (no storage).
- **Private annotations are never serialised** (type-level + runtime); they ARE in
  the user's own encrypted backup (allowed — not a graph disclosure).
- **kith shared secrets are never published** (only co-signed assertions).
- **NIP-05 is TOFU, not key-continuity** — a key-change is propose-only, never
  auto-accept; require user confirmation.
- **`attributeSignature` is replayable** — use `verifyKeyControl` (fresh nonce) for
  impersonation resistance.
- **Verify filter publications against a pinned key** — check the Nostr sig AND the
  in-blob Schnorr sig; pass the **raw** wire event (a spread-mutated one carries a
  stale `Symbol(verified)` false-green).
- **Discovery is opt-in + exit-able, but you cannot cryptographically verify
  removal** from a pool you left. Real member privacy = per-context personas.

## Toolkit

kindred is the relationships brick of the **Forgesworn / Signet** ecosystem. It
composes:

- [`@forgesworn/tessera-kit`](https://github.com/forgesworn/tessera-kit) — the non-enumerable
  membership-presence filter `kindred/discovery` is a thin layer over.
- [`spoken-token`](https://github.com/forgesworn/spoken-token) — the directional
  verification words the bond ceremony speaks.
- [`nostr-attestations`](https://github.com/forgesworn/nostr-attestations) — the
  co-signed bond assertions (kind-31000).
- [`nsec-tree`](https://github.com/forgesworn/nsec-tree) — hierarchical persona key
  derivation (the `ownerPubkey` scoping; kindred needs only the type relationship).

Consumed by **signet-app** (the user-facing identity app): it maps its `Contact`
record onto `KinEntry`/`KithEntry`/`ken`, persists `KindredEntry` in IndexedDB, and
keeps tier/badge enrichment app-side. The byte-exact ECDH (PROTOCOL.md §1) is what
makes that migration lossless.

## Licence

MIT.

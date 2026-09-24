# Security Policy

kenspeckle makes **narrow, precise** claims and refuses the broad ones. This document
is the honest posture (spec §4, §6, §9, §10). Read it before building on the
library — several intuitive-sounding guarantees are **deliberately not made**, and
treating the kit as if they were would create real harm (a doxxing primitive in
discovery, an impersonation hole in ken).

kenspeckle is a pure-computation library: no storage, no UI, no graph traversal. Its
only network touch is `pinKenFromNip05` / `resolveKen` fetching a `.well-known`
file over HTTPS via an **injected** `fetch`.

## The posture, stated honestly

### 1. Persona-scoping is a consumer obligation kenspeckle ASSISTS but cannot guarantee

Every entry carries an `ownerPubkey` — one of MY `nsec-tree` persona keys — so a
contact is recorded under a specific persona of mine, never globally. This is the
anti-correlation invariant ("your work contact must not surface on your gaming
server"). kenspeckle enforces it **where it can**:

- `discoverPresent` requires an explicit `ownerPubkey` and **throws on
  mixed-persona input** — every entry must share the declared owner. Mixing
  personas into one presence query would let a server correlate two of your
  personas via a single lookup, so it is a bug and is rejected, not silently
  filtered.
- `PrivateAnnotations` is structurally excluded from every `serialize*` / wire
  input type (see §2).

But kenspeckle **owns no storage**, so it **cannot fully guarantee** that the consumer
keeps personas separated at rest, scopes its IndexedDB correctly, or never mixes
owners upstream of a call. **Persona-scoping is ultimately a consumer obligation
the primitive assists with — not a guarantee kenspeckle can make.**

### 2. Private annotations are NEVER serialised onto a wire

`PrivateAnnotations` (`groupId`, `label`, `note`, `blocked`) are local-only recall
aids. They are **searchable in memory** (`searchEntries`) but MUST NEVER reach a
wire. This is enforced two ways:

- **Structurally (type level):** `WireEntry = DistributiveOmit<KindredEntry,
  'annotations' | 'sharedSecret'>` (and `SyncEntry` omits `annotations`), and a
  compile-time assertion (`_WireAnnotationsExclusionCheck`) fails the build if
  `WireEntry` ever re-admits `annotations`. `serializeEntry` is typed through
  `toWire`, and `serializeEntryForSync` through `toSyncForm`, so neither canonical
  JSON can carry an `annotations` key.
- **At runtime:** `toWire` strips `annotations`, and the canonical key-sort emits
  only present keys — so `serializeEntry(entryWithAnnotations)` produces JSON with
  **no** `annotations` key (asserted in `model.test.ts`).

**The one allowed exception is the user's own encrypted self-backup**
(`exportEntriesEncrypted`), which **includes** annotations because it is the
holder's sealed copy, encrypted with XChaCha20-Poly1305 under a 32-byte key the
consumer supplies. Only a holder of that key can read the blob (managing the key's
lifecycle is the consumer's job — kenspeckle only takes it as a parameter). Per spec §2
/ §12.1 this is explicitly **not a graph disclosure** — it is the user backing up
their own roster, not exporting edges to a third party. Decryption is authenticated:
a wrong key or any tampered byte throws (Poly1305 tag failure), never silently
returns garbage.

### 3. kith shared secrets are never published

A bond's ECDH `sharedSecret` is **never** put on any wire. `toWire` /
`serializeEntry` strip it (as well as `annotations`), so the "wire-safe" form really
is safe to hand to a third party. The one form that keeps it is
`toSyncForm` / `serializeEntryForSync`, for syncing a roster between the **user's
own devices** over a channel that is already private — never publish that output.
(The encrypted self-backup also keeps it.) The optional, consensual
"prove we're verified contacts" surface publishes only **co-signed assertions**
(kind-31000, subject = counterparty pubkey) — **no secret-derived value**. The v1
`hash(sharedSecret‖counter)` idea is deliberately absent: it was brute-forceable and
a bond-existence oracle. A pair of plain attestations (one each way) proves mutual
verification without leaking anything derived from the secret.

### 4. NIP-05 is a DNS/TLS/HTTP-TOFU anchor, NOT cryptographic key-continuity

`pinKenFromNip05` resolves `https://<domain>/.well-known/nostr.json?name=<local>`
(**HTTPS only**; no redirects, a timeout, a capped body, parsed with a strict runtime
type guard). Every path that can reach that fetch — `pinKen`, `pinKenFromNip05`,
`resolveKen` and `resolveNip05` itself — validates the identifier with the strict
`validateNip05`: a plain `local@hostname` of at least two labels whose last label is
alphabetic or punycode (`xn--`), with no port, userinfo, path, query, fragment or IP
literal (including shorthand such as `127.1` or `0x7f.1`), so a crafted `nip05`
cannot turn resolution into an arbitrary-URL fetch. `parseEntry` / `importEntries`
keep a stored `nip05` that 0.1.x accepted, but `resolveKen` treats one that fails
`validateNip05` as unresolvable and never fetches it. The companion return rail uses the same validator for claimed
identifiers. NIP-05 proves only
that whoever controls that file **says** a name maps to a key. It is a DNS + TLS +
HTTP **trust-on-first-use (TOFU)** anchor — **not** a cryptographic key-**continuity**
anchor. The domain operator, or anyone who later compromises DNS/TLS or the host,
can silently swap the published key. Therefore:

- `pinKenFromNip05` **refuses to pin** unless the name resolves to a valid key
  (refuse-on-mismatch TOFU — you decide to trust the first observation).
- A later NIP-05 key **change is an untrusted signal**: `resolveKen` **proposes** a
  rotation (`accepted:false`) and **never auto-flips** `pubkey`. Accepting it
  (`acceptKenRotation`) is an explicit, user-confirmed act, and accepting the same
  rotation twice throws. It also throws on a revoked entry: a revoked ken cannot be
  re-pinned to a new key.
- A change **back** to a key the entry already rotated away from is flagged
  `rotation.rollback: true` — the signature of a reverted or compromised domain.
  `acceptKenRotation` refuses it unless called with `{ allowRevert: true }`; a UI
  should show that case as a warning, not as an ordinary key update.
- For high-value ken, prefer an **old-key-signed rotation announcement**
  (`KenRotation.announcementEventId`) over a bare NIP-05 change, and **always**
  require user confirmation.

### 5. `attributeSignature` alone is REPLAYABLE — use `verifyKeyControl` for impersonation resistance

These two functions answer **different** questions:

- **`attributeSignature(entry, event)`** — "did the key I currently recognise sign
  this artifact?" This is **REPLAYABLE by design**: a genuinely-old signature still
  verifies, and **anyone can re-present it**. There is no freshness. An impostor can
  show you a real, old, signed event by the figure — attribution alone does not
  prove the party in front of you controls the key.
- **`verifyKeyControl(entry, nonce, signedEvent)`** — "is the party here, **right
  now**, in control of the pinned key?" The claimant must sign a **fresh random
  nonce** (`buildKeyControlChallenge`, as the event `content`). A replayed old
  signature can **never** satisfy it. **Impersonation resistance requires
  `verifyKeyControl` against a fresh nonce — not `attributeSignature`.**

  What makes "**never**" literally true is a **nonce-strength gate**: `verifyKeyControl`
  requires the challenge nonce to be exactly the **64 lowercase-hex** shape
  `buildKeyControlChallenge` emits (32 random bytes), rejecting anything else with
  `reason:'bad-nonce'` — checked **early**, right after `revoked`, before the
  `content === nonce` comparison is ever trusted. Without it, a weak/empty nonce
  (`''`) would be satisfied by a **replayed, genuinely-signed empty-content event**
  (kind-3 contact lists, reactions — common on Nostr), since `content === nonce`
  reduces to `'' === ''`. The gate closes that replay hole; the caller cannot
  weaken the challenge to reopen it.

Both fail closed on `revoked` (checked first) and on a `previousPubkeys` (rotated-away)
key. Use attribution to credit an artifact; use key-control to authenticate a live
party.

### 6. Filter publications: verify BOTH signatures against a PINNED key

A published presence filter is just bytes a stranger served you. A **forged** filter
is a **doxxing primitive** — an attacker who makes you trust an arbitrary membership
set can make `discoverPresent` report a friend as "present" on a server they never
joined (or hide a real member). So a publication carries **two distinct signatures**,
and a consumer **MUST** check **both** before trusting any hit:

1. the **Nostr event signature** (NIP-01 transport integrity), via `verifyEvent`
   inside `parseFilterPublication`; and
2. the **in-blob Schnorr provenance signature** (`verifyFilterBlob` from
   @forgesworn/tessera-kit), whose `signerPubkeyHex` the consumer **MUST compare against a
   pinned / out-of-band-known server key**.

By default (`requireAuthorIsSigner: true`) `parseFilterPublication` also requires the
Nostr event author to **be** the in-blob signer, and the `n` tag to match the d-tag's
namespace. The in-blob signature does not cover `namespace` / `serverId`; without the
author check, anyone could re-wrap a genuine server-signed blob under a different
`serverId` and still get the real server back as `signerPubkeyHex` — showing that
server at a pool it never published to. Pass `{ requireAuthorIsSigner: false }` only
if you deliberately trust a republisher.

`parseFilterPublication` returning a non-null result means only that both signatures
are **internally consistent** — it is **not** trust. Anyone can mint a validly
self-signed blob under their own key; the **pinned-key comparison** is what defeats
forged-filter doxxing. (Cross-ref: @forgesworn/tessera-kit SECURITY.md §3.)

> **`Symbol(verified)` footgun.** `nostr-tools`' `verifyEvent` caches its result in
> an enumerable `Symbol(verified)`. An object-spread (`{...ev}`) copies that cache,
> so a **verified-then-mutated** event short-circuits `verifyEvent` on a **stale
> `true`** — a false-green. **Pass the raw wire event** (or a
> `JSON.parse(JSON.stringify(ev))` wire-clone) to `parseFilterPublication` and
> `verifyBondAttestation`, never a spread-mutated object.

### 7. Discovery is opt-in and exit-able, but removal is not cryptographically verifiable

Discovery is **always opt-in** (a server only lists members who consented to be
tested) and **exit is always requestable** (`buildOptOutRequest`, honoured on the
server's next rebuild). The honest limits:

- A member **cannot cryptographically verify their removal** from a keyed pool they
  have left — they can only assert the opt-out and trust the next rebuild (the
  server cannot retroactively edit an already-published immutable blob).
  `DiscoveryDisclosure.canExit` surfaces this (exit is requestable, never
  cryptographically confirmable).
- **Open (unsalted) pools test the raw pubkey**, so an **included** member is
  **cross-server locatable** by anyone holding their candidate pubkey — an opt-in,
  un-consented-by-*others* presence locator for the members included in them.
  `disclosureFor` reports `crossServerDiscoverable` for open pools.
- **Keying is a speed-bump, not a member-privacy boundary** (cross-ref:
  @forgesworn/tessera-kit SECURITY.md §1). It restricts probing to salt-holders; it does **not**
  confine probing to current members and does **not** survive a salt leak.

**Real member privacy comes from per-context personas** (a different key per server,
via `nsec-tree`) and not joining open servers — not from keying. kenspeckle provides
the persona escape hatch; it does not make discovery anonymous.

### 8. Zeroization honesty

Where kenspeckle hands `@noble` a private-key **byte copy** (`buildJoinInvite`,
`buildOptOutRequest`), that copy is wiped with `.fill(0)` in a `finally`.
`deriveBondSecret` makes **no** zeroization claim at all: it never makes a byte
copy of the key (an earlier version made one, never used it and wiped it, which
protected nothing — it was removed). **In every case** the `BigInt` scalar and the
ECDH point limbs that `@noble` derives internally are **immutable / not reachable**
from the call site and **cannot be zeroized** here. A private key passed in as a JS **string** is likewise immutable
and persists until garbage-collected. So zeroization is **best-effort on the byte
copies only** — kenspeckle does **not** claim full zeroization. A future Rust/WASM port
should take secrets as **bytes** and wipe the scalar and point deterministically.

### 9. Input-validation discipline

Every wire parser guards untrusted input before trusting it (signet-app
convention): size caps **before** decode (`8192` bytes for handshake/invite; the
64 MiB blob cap for filter publications, checked on the encoded length before
base64-decode); hex/length checks; HTTPS-only NIP-05; allow-listed enums (tier, ken
source, rotation `via`); finite-number timestamps; bounded arrays (`personas ≤ 16`).
A non-JSON blob surfaces a clear `Error`, never a raw `SyntaxError`.

**Attacker-controlled display strings are returned VERBATIM** — `displayName`
(handshake, entries) and any site/persona label are **not** sanitized or truncated
by kenspeckle. Sanitizing at the parse boundary would mangle legitimate names and give
a false sense of safety. **The consumer truncates/escapes at the point of display.**
The companion rail is the exception: its display text (pairing `appName`, grant
envelope `displayName` / `nip05`, returned kens) is control/bidi-stripped and
code-point-truncated at the boundary, because it crosses from another app.

**Builders serialise an allowlist, never the caller's object.** TypeScript's
excess-property check does not apply to a non-literal argument, so
`build(entry)` with an object that also carries `privkey` / `sharedSecret` would
otherwise put it on the wire. `buildHandshakePayload`, `buildPairingAck`,
`buildGrantEnvelope`, `buildReturnEnvelope` and `serializeJoinInvite` copy only
their declared fields.

### 10. Spoken-word guessing odds

A bond word is **one word from a 2048-word list — 11 bits**. `verifyBondWord` with
`tolerance` `t` accepts any of `2t + 1` counterparty words (one per counter in the
window), so a blind guess succeeds with probability about `(2t + 1) / 2048`:

| `tolerance` | accepted words | chance per guess |
|-------------|----------------|------------------|
| 0 | 1 | ≈ 0.05% |
| 1 (signet-me) | 3 | ≈ 0.15% |
| 10 (the cap) | 21 | ≈ 1% |

The library has **no rate limit** and no lockout. The protection is the human in
the loop: two people saying a word to each other, once. A consumer that lets an
attacker submit many guesses (an automated channel, a retry loop) MUST add its own
limit, and SHOULD keep `tolerance` at 0–1 outside signet-me migration.

**Replay.** The words depend only on the bond secret, the two pubkeys and the
counter, so a word overheard once is valid again whenever the same counter is
reused. A fixed counter is therefore NOT RECOMMENDED. An in-person ceremony SHOULD
use `deriveCeremonyCounter` over both parties' handshake nonces (fresh per ceremony,
tolerance 0); a later re-verification MAY use `timeCounter`. See PROTOCOL.md §2.

### 11. Bond attestations: revocation is only visible on the latest version

`verifyBondAttestation` rejects revoked (`["status","revoked"]`), expired (NIP-40
`expiration`, `valid_to`), not-yet-active and self-attestations, and requires the
`d` tag to be the one a revocation targets. But it judges **only the event it is
given**. A revocation replaces the attestation at its address; an older copy of the
attestation, served by a relay that missed the revocation, still verifies on its
own. A consumer counting attestations MUST fetch the latest event at
`(attester, 31000, kindred-bond:<subject>)` first. Retract with
`buildBondRevocation` (a signed, visible statement); the kind-5
`retractBondAssertion` is only a request to forget.

### 12. Invites are bearer tokens until the consumer dedupes them

A `JoinInvite` signature proves the inviter vouched for `(namespace, serverId)`;
it does not make the invite single-use. Anyone holding the bytes can present them
until `expiresAt` (if set). Dedupe on `(inviterPubkey, nonce)` where one-time use
matters; the 16-byte nonce minimum makes accidental collisions negligible. (The v1
invite encoding let a signature be re-targeted to a different
`(namespace, serverId)` split; v2 fixed that and v1 is no longer accepted — see
PROTOCOL.md §6.2.)

### 13. Backup key: do not reuse it

The self-backup (`exportEntriesEncrypted`) binds a `"KSBK" ‖ version` header as AAD,
so a v1 backup cannot be confused with another ciphertext made under the same key.
`importEntries` still reads **legacy** header-less backups (`nonce ‖ ciphertext`,
no AAD) so existing backups stay restorable. That keeps the old weakness on the
read side: a header-less XChaCha20-Poly1305 ciphertext produced by some **other**
scheme under the same 32-byte key would be decrypted and (if it parses as a
roster) imported. Use a key dedicated to backups.

## What is genuinely removed (the honest upside)

The **central-graph-ownership** harm — one party owning and monetising the whole
social graph — **is** removed: no party holds the edges, discovery is local, there
are no shadow profiles, and there is no who's-here query API to log interest. **But**
open filters create an opt-in, un-consented-by-others cross-server presence locator
for the members *included in them*, and an aggregator plus a reused pubkey can
reconstruct venue-presence for those members. So the residual harm is **reduced and
opt-out-able**, defeated in practice by per-context personas — **not eliminated**.
We do not claim otherwise.

---

## Reporting a vulnerability

If you discover a security vulnerability in kenspeckle, please report it responsibly:

1. **Do not** open a public GitHub issue.
2. Email **thecryptodonkey@proton.me** with a description, steps to reproduce, and
   any proof-of-concept code.
3. You will receive an acknowledgement within 48 hours.
4. A fix will be developed privately and released as a patch version. You will be
   credited in the release notes unless you prefer otherwise.

## Scope

In scope:

- **Input-validation bypass / unbounded allocation** in any wire parser
  (`parseHandshakePayload`, `parseJoinInvite`, `parseEntry`, `parseFilterPublication`,
  `importEntries`, `parseGrantEnvelope`, `parsePairingRequest`, `parsePairingAck`) — a malformed blob that reads past its bounds or triggers an
  attacker-sized allocation.
- **Migration-vector drift** — any way `deriveBondSecret` stops reproducing the
  frozen `fd2644…26f9` vector (that breaks every migrated contact's verification
  words).
- **ken impersonation** — any way to make `verifyKeyControl` accept a replayed or
  wrong-key signature, or `attributeSignature` accept a rotated-away/revoked key.
- **Forged-filter acceptance** — any way `parseFilterPublication` returns a result
  for a blob whose Nostr signature or in-blob Schnorr signature was tampered.
- **Annotations leak** — any path that serialises `PrivateAnnotations` onto a wire.
- **Invite re-targeting** — any way to make `parseJoinInvite` accept a signature for a
  different field tuple than the inviter signed.
- **Revocation bypass** — any way to make `verifyBondAttestation` return `ok` for a
  revoked, expired or self-attestation, or to make `applyCompanionSnapshot` restore
  contacts after a revocation.

Out of scope (by design, documented above):

- Confirming presence of a **held specific key** in a pool (§7) — that is the
  function of a membership filter (see @forgesworn/tessera-kit SECURITY.md §2).
- Probing a keyed pool by a **salt-holder** (§7) — keying is a speed-bump.
- Inability to cryptographically verify **removal** from a pool you left (§7).
- Inability to zeroize the immutable bigint scalar / a key passed as a **string**
  (§8) — a JS-runtime limitation.
- Attacker-controlled display strings returned **verbatim** (§9) — truncation is the
  consumer's responsibility by design.
- Brute-forcing a spoken word through an unlimited-retry channel the consumer built
  (§10) — the odds are documented; rate limiting is the consumer's.
- Accepting a stale, un-revoked copy of an attestation the consumer did not refresh
  (§11), or replay of an invite the consumer did not dedupe (§12).
- Legacy (header-less) backup reading under a key reused elsewhere (§13).

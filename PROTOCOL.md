kindred Protocol — verified-relationship wire formats & ceremonies
==================================================================

For a clean-room re-implementer. This document specifies the byte-exact ECDH bond
secret (with a **frozen migration vector**), the spoken-token directional usage,
the Nostr kind allocation + tag shapes for discovery, the invite canonical bytes,
and the build/parse asymmetry. `README.md` is the usage guide; `SECURITY.md` is the
honest privacy posture (read it — several intuitive guarantees are deliberately
**not** made).

`v1` for every wire format below (`HandshakePayload.v = 1`, `JoinInvite.v = 1`,
`KFLT format_version = 1` in the sibling @forgesworn/tessera-kit).

## Notation

| Symbol | Meaning |
|--------|---------|
| `sha256(b)` | SHA-256 of byte string `b` (32-byte output) |
| `schnorr.sign(m32, sk)` | BIP340 Schnorr signature of the 32-byte message `m32` → 64-byte compact sig |
| `schnorr.verify(sig, m32, pk)` | BIP340 verification, `pk` = 32-byte x-only |
| `utf8(s)` | UTF-8 encoding of string `s` |
| `‖` | byte concatenation |
| `bytesToHex` / `hexToBytes` | 32-byte ⇄ 64-lowercase-hex conversion |
| `P · k` | scalar multiplication of point `P` by scalar `k` |
| `lift_x_even(x)` | the secp256k1 point with x-coordinate `x` and **even** y (the BIP340 `02`-prefix lift) |

All hex on the wire is **lowercase**. Every parser lowercase-normalizes hex fields
on output so two independent callers agree byte-for-byte.

---

## 1. The ECDH bond secret (migration-critical — `./bond`)

A kith **bond** is established when two personas mutually verify out-of-band by
speaking short, time-rotating words derived from a shared ECDH secret. The secret
MUST reproduce signet-protocol's construction **byte-for-byte**, or every contact
migrated out of signet-app gets a different secret → different words → broken
verification for both parties.

### 1.1 Construction (verbatim)

```
secret = bytesToHex( sha256( x ) )
where  x = the 32-byte big-endian (left-zero-padded) x-coordinate of:
           lift_x_even( '02' ‖ theirXOnlyPubkey )  ·  myPrivScalar
```

In `@noble/curves@2` terms (the v1 `getSharedSecret` helper is gone):

```typescript
const theirPoint = secp256k1.Point.fromHex('02' + theirXOnlyHex)   // even-y lift
const scalar     = BigInt('0x' + myPrivHex)
const xHex       = theirPoint.multiply(scalar).toAffine().x.toString(16).padStart(64, '0')
const secret     = bytesToHex(sha256(hexToBytes(xHex)))
```

### 1.2 The `02` even-y wire rule

x-only (BIP340) pubkeys drop the y parity. Both seats lift the counterparty's
x-only key with the **even-y `02` prefix** — a hard wire rule. The lifted point may
therefore be the **opposite** point (−P) from the one the counterparty actually
holds.

### 1.3 Why agreement holds — and why it is NOT "because `02` is correct"

This is the subtle, load-bearing point. ECDH with −P yields −(shared point). But
**−Q and Q share the same x-coordinate** (negation flips only y). Because this
construction hashes **only the x-coordinate**, both seats land on the identical
secret **regardless of which y-parity each side lifted**. The shared x is the
invariant; the chosen sign is irrelevant.

> Agreement comes from **hashing only x** (±P share an x), **NOT** from the `02`
> even-y assumption being "correct." This is exactly why migrating from
> signet-protocol is byte-safe: the protocol made the same `02`-lift-and-hash-x
> choice, so the secrets coincide.

### 1.4 The frozen migration vector (enshrined in `bond.test.ts`)

Generated under `@noble/curves@2.2.0`. The test self-validates that the two
pubkeys derive from the two private keys, then asserts both ECDH directions:

```
privA          = '11' × 32   (i.e. "1111…11", 64 hex chars)
privB          = '22' × 32
pubA (x-only)  = 4f355bdcb7cc0af728ef3cceb9615d90684bb5b2ca5f859ab0f0b704075871aa
pubB (x-only)  = 466d7fcae563e5cb09a0d1870bb580344804617879a14949cf22285f1bae3f27

deriveBondSecret(privA, pubB)
  === deriveBondSecret(privB, pubA)
  === fd264454c8f37c9c4b000f0672399b9c76011de71f489fd8a043e25e558226f9
```

If a re-implementation does not reproduce `fd2644…26f9` in **both** directions, the
construction is wrong — the value is frozen; debug the construction, never the
expectation.

### 1.5 Point + scalar validation

`deriveBondSecret` rejects, before any curve operation:

- priv / pub not exactly 64 hex chars;
- a pubkey x that is **not** a valid curve x-coordinate (`Point.fromHex('02'+x)`
  throws → `invalid curve point`);
- a **non-canonical scalar**: the private scalar must be in `[1, N-1]` (`0` is the
  identity; `≥ N` is reduced-equivalent). `N = secp256k1.Point.Fn.ORDER`.

### 1.6 Zeroization contract (stated honestly)

`deriveBondSecret` zeroizes the `privBytes` byte copy in a `finally`. It does
**not** — and **cannot** — wipe:

- the `scalar` (`BigInt`s are immutable in JS; there is no in-place clear);
- the intermediate ECDH point's internal limbs.

So this is **best-effort zeroization of the byte copy only**. A future Rust/WASM
port MUST zeroize the scalar and the ECDH point. We do not claim full
zeroization. The same honest limitation applies everywhere kindred handles a
private key as a JS value (`buildJoinInvite`, `buildOptOutRequest`): the byte copy
is wiped; the immutable bigint inside `@noble` is not wipeable from the call site.

---

## 2. Spoken-token directional words (`./bond`)

Words are derived with `spoken-token`'s `deriveDirectionalPair`, namespace
`KINDRED_BOND_NAMESPACE = 'kindred:bond'`.

```
// DEFAULT parameterisation (namespace 'kindred:bond'):
roles = [aPubHex, bPubHex] sorted lexicographically → [lo, hi]   (order-independent)
pair  = deriveDirectionalPair(secretHex, 'kindred:bond', [lo, hi], counter)
mine   = pair[myOwnPubHex]      // the word I speak
theirs = pair[counterpartyPub]  // the word I expect to hear
```

The namespace is overridable via an optional `opts` argument for
**signet-me migration compatibility** — see §2.1.

- **Roles are the two pubkeys sorted** to a canonical `[lo, hi]` (by default), so both seats
  feed `deriveDirectionalPair` the identical `(secret, namespace, roles, counter)`
  and therefore agree on the pair. Each seat's own pubkey selects which role token
  is "mine" vs "theirs."
- **Directional ⇒ `mine !== theirs`.** The listener cannot parrot the speaker's
  word back (spoken-token's echo defence) — each direction is an independent HMAC
  output.
- **The `counter` is the consumer's choice** (time-bucketed or event-based);
  kindred exposes pure functions and takes the counter as a parameter.
- **Verification re-derives, it does not `verifyToken`.** The directional
  `pair\0`-prefixed context inside spoken-token is reachable **only** via
  `deriveDirectionalPair`. So `verifyBondWord` re-derives the expected counterparty
  word via `bondWords` and **constant-time-compares** it (`timingSafeStringEqual`
  from `spoken-token/crypto`) against what was spoken — a constant-time compare so
  early-exit timing can't leak how many leading characters of a guess were right.
- **`verifyBondWord` returns `{ ok }`** (a bare boolean verdict — `ok:true` iff the
  spoken word matched). It accepts an optional `tolerance` (below) that widens the
  match to a counter window; with `tolerance > 0` every candidate counter is checked
  with a constant-time compare and the verdicts are OR-accumulated **without
  early-return**, so timing does not leak **which** counter matched beyond `ok`.

### 2.1 signet-me compatibility (migration continuity)

signet-app's pre-migration `signet-me` derives its directional words with the SAME
`deriveDirectionalPair` primitive but **different parameters**:

| Parameter | `signet-me` (signet-protocol) | kindred default |
|-----------|-------------------------------|-----------------|
| namespace | `'signet:me'` | `'kindred:bond'` (`KINDRED_BOND_NAMESPACE`) |
| counter | `getCounter(now, 30)` (30 s rotation) | the consumer's chosen `counter` arg |
| tolerance | `±1` epoch (clock-skew window) | `0` (exact counter) |

So **with kindred's DEFAULT opts the words DIFFER from `signet-me`'s** — a naive
migration silently changes a contact's verification words. To let a migrated contact
cross-verify with a peer who has **not** migrated yet, `bondWords` / `verifyBondWord`
take an optional final `opts` that reproduce `signet-me`'s parameterisation
**exactly** (the mapping was confirmed by reading `signet/src/signet-me.ts`):

```typescript
// Reproduce signet-me's words (each seat passes its OWN pubkey first — the [myPub, theirPub] order):
bondWords(secret, myPub, theirPub, counter, { namespace: 'signet:me' })
verifyBondWord(secret, myPub, theirPub, counter, spoken,
               { namespace: 'signet:me', tolerance: 1 })
```

- `namespace` — default `'kindred:bond'`; `'signet:me'` for compat. **This is the
  load-bearing knob**: changing the namespace changes the derived words. signet-me uses
  caller-order roles `[myPubkey, theirPubkey]` while kindred sorts to `[lo, hi]`, but
  **that ordering difference is immaterial** — and that is why there is no role-order
  knob. **Empirical note (verified against the installed `spoken-token`):**
  `deriveDirectionalPair` derives each word from `namespace + '\0' + role` — i.e. from
  the role **string**, *independent of its position in the tuple*. So `pair[X]` is the
  same whether roles are `[X,Y]` or `[Y,X]`, and `mine = pair[aPubHex]` either way. Each
  seat still passes its own pubkey as `aPubHex`, so it picks its own role's word, and
  cross-agreement holds under the default sort. The `namespace` alone reproduces
  `signet-me`.
- `tolerance` (`verifyBondWord` only) — default `0`; `t` accepts `spoken` if it matches
  the counterparty word at any counter in `[counter-t, counter+t]`, mirroring
  `signet-me`'s ±1 clock-skew window. kindred reproduces the words **via params** (it
  takes `counter` as an argument rather than deriving it from wall-clock).
  **Fail-soft clamping (the `{ ok }` contract — `verifyBondWord` MUST NOT throw on a
  valid-shaped call):** `t` is coerced to an integer in `[0, MAX_BOND_TOLERANCE]`
  (= 10, matching spoken-token's `MAX_TOLERANCE`; a negative/NaN `t` → `0`, a larger one
  → `10`), and the candidate counter window is clamped to the valid uint32 span
  `[0, 0xFFFFFFFF]`. Without the latter, a boundary `counter` (e.g. `counter = 0,
  tolerance = 1` → counter `-1`, or `counter = 0xFFFFFFFF, tolerance = 1` →
  `0x100000000`) would feed `spoken-token`'s `counterBe32` an out-of-range counter and
  throw a `RangeError`. The clamp skips only the out-of-range counters; the in-range
  ones are still checked.

The opts are **additive and backward-compatible**: every existing call with no `opts`
keeps the original `'kindred:bond'` + exact-counter behaviour. **Both peers must either
upgrade together or pass the `signet-me` opts** during rollout (in practice: the
`signet:me` namespace, plus a `tolerance` for the clock-skew window).

---

## 3. Co-signed bond assertion + revoke (`./bond`)

Default kith is **private, zero relay footprint**. The optional, consensual "prove
we're verified contacts" case is a co-signed assertion — **no secret-derived value
is ever published** (a `hash(sharedSecret‖counter)` would be a brute-forceable
bond-existence oracle and is deliberately absent).

- **`buildBondAttestation({ subjectPubHex, summary? })`** → unsigned kind-31000
  `EventTemplate` via `nostr-attestations`' `createAttestation`. `type` is the
  literal **`'kindred-bond'`** (the literal `'assertion'` is RESERVED by
  nostr-attestations and throws). `subject` = the counterparty pubkey. The real
  emitted tags are: `["d", …]`, `["type", "kindred-bond"]`, `["p", <subject>]`,
  optional `["summary", …]`, `["L", "nip-va"]`, `["l", "kindred-bond", "nip-va"]`.
  The caller signs the template; "I verified them" via MY signature alone — a pair
  of these (one each way) proves mutual verification without a shared-secret leak.
- **`retractBondAssertion(assertion)`** → unsigned kind-5 NIP-09 deletion with
  `["e", assertion.mineId]`. Signed by the SAME key that signed the original (only
  the author may delete their event). A network-wide retraction can never be
  cryptographically guaranteed — NIP-09 is a request.

`created_at`: `createAttestation` returns an optional `created_at`; kindred stamps
one if absent so the result satisfies the canonical (nostr-tools) `EventTemplate`
where `created_at` is required. A caller may override before signing.

---

## 4. ken — key-control & attribution (`./ken`)

`ken` is one-way recognition of a key you did **not** bond with (a public figure, a
NIP-05 handle). No shared secret, no mutual ceremony.

### 4.1 NIP-05 is a TOFU anchor, NOT key-continuity

NIP-05 resolution fetches `https://<domain>/.well-known/nostr.json?name=<local>`
(**HTTPS only**; the URL is constructed from validated parts, never reflected from
input). The response body is attacker-influenced (the domain operator controls
it), so it is parsed with a runtime type guard: body must be an object,
`body.names` an object, `body.names[local]` a 64-hex string — anything else throws.

NIP-05 proves only that whoever controls the well-known file **says** a name maps
to a key. It is a DNS + TLS + HTTP **trust-on-first-use** anchor, **not** a
cryptographic key-**continuity** anchor: the domain operator (or anyone who later
compromises DNS/TLS or the host) can silently swap the published key. Therefore:

- `pinKenFromNip05` **refuses to pin** (throws) unless the name resolves to a valid
  key — a refuse-on-mismatch TOFU pin (you decide to trust the first observation).
- `resolveKen` treats a later key **change** as an **untrusted signal**: it
  **proposes** a `KenRotation{ accepted:false }` and **never auto-flips** `pubkey`.
- For high-value ken, prefer an **old-key-signed rotation announcement**
  (`KenRotation.announcementEventId`) over a bare NIP-05 change; **always** require
  user confirmation. `acceptKenRotation` is the explicit, user-driven move.

### 4.2 Live key-control vs replayable attribution

The nonce-binding convention: the claimant signs a Nostr event whose **`content` is
exactly the challenge nonce** (the consumer builds the event that way; any `kind`
works — only `content` + sig + pubkey are inspected).

- **`buildKeyControlChallenge()`** → `{ nonce: 64-hex (32 random bytes), createdAt }`.
- **`verifyKeyControl(entry, nonce, signedEvent)`** — fail-closed, in order:
  `revoked` → **nonce strength** (`nonce` MUST match `/^[0-9a-f]{64}$/`, else
  `reason:'bad-nonce'`) → `pubkey === current pin` (a `previousPubkeys` key is
  rejected) → `content === nonce` → `verifyEvent` (sig + id). Because the nonce is
  freshly random per challenge, a replayed old signature can **never** satisfy this
  — this is what makes recognition impersonation-resistant **live**. The
  nonce-strength gate is **load-bearing** for that "never": without it an empty
  nonce (`''`) would be satisfied by a replayed, genuinely-signed **empty-content**
  event (kind-3 lists, reactions), because `content === nonce` collapses to
  `'' === ''`. Checking the nonce shape **before** trusting that comparison is what
  closes the hole — and the gate is deliberately case-sensitive (only the lowercase
  shape we emit is accepted).
- **`attributeSignature(entry, event)`** — "did the current pin sign this
  artifact?" Fail-closed: `revoked` → pubkey ∈ `previousPubkeys` (`rotated-away-key`)
  → `event.pubkey === current pin` → `verifyEvent`. This is **REPLAYABLE by
  design**: a genuinely-old signature still verifies and anyone can re-present it.
  That replayability is precisely **why `verifyKeyControl` exists** — attribution
  credits an artifact; key-control authenticates a live party.

### 4.3 Rotation, revoke, drop

- `acceptKenRotation` moves the current `pubkey` into `previousPubkeys`, adopts
  `rotation.newPubkey`, sets `rotation.accepted = true`. **No dual-accept window** —
  the moment it runs, `attributeSignature` rejects the old key.
- `revokeKen` sets `revoked = true` (compromise with no successor); both
  `attributeSignature` and `verifyKeyControl` then fail closed (`reason:'revoked'`,
  checked first).
- `dropKen` is a documented **no-op** — kindred owns no storage, so deleting the
  record is the consumer's responsibility.

---

## 5. Discovery — kind allocation & publication shape (`./discovery`)

Discovery is a thin layer over the sibling **@forgesworn/tessera-kit** membership filter: a
server publishes a signed, non-enumerable presence filter; a client tests its own
contacts locally (presence, not a member list). kindred holds no state, opens no
sockets, and never enumerates a server's membership.

### 5.1 Kind allocation (provisional — NOT NIP-registered)

```
KINDRED_FILTER_KIND  = 30444   // addressable filter publication
KINDRED_OPTOUT_KIND  = 30445   // a member's opt-out request
```

Both are **provisional and not yet NIP-registered**. `30444` **matches
@forgesworn/tessera-kit PROTOCOL.md §6 byte-for-byte** — the publication shape is shared so a
@forgesworn/tessera-kit-only server (no `kindred` dependency) can emit an identical event. It
supersedes the `30078` placeholder from early design (`30078` is signet-app's
contact-sync kind; reused here only as a historical note, never the recommended
value).

### 5.2 Filter publication (`buildFilterPublication` / `parseFilterPublication`)

Addressable event, `kind 30444`:

| Tag / field | Value |
|-------------|-------|
| `["d", …]` | `kindred:members:<namespace>:<serverId>` — the **addressable identity** (one filter per `(namespace, serverId)`; a newer epoch replaces the older addressable event). `namespace` = the game/app (aggregator unit), `serverId` = the instance |
| `["n", "<namespace>"]` | the single-letter **relay-indexable** namespace tag the aggregator queries via `#n` (so it can collect every `serverId` in a namespace) |
| `["epoch", "<n>"]` | the filter epoch (unix seconds) |
| `["keyed", "0"\|"1"]` | whether the pool is keyed (salted) |
| `content` | **base64 of the raw @forgesworn/tessera-kit `KFLT` blob** |

**`parseFilterPublication`** returns `null` (never throws) on any failure, in order:
(1) bad Nostr event signature (`verifyEvent`); (2) wrong kind; (3) missing/undecodable
base64 content, or a blob over @forgesworn/tessera-kit's 64 MiB cap (the encoded length is
capped **before** decode so an oversized payload can't be expanded into memory);
(4) bad **in-blob Schnorr** provenance signature (`verifyFilterBlob` — the §10
invariant); (5) d-tag not in `kindred:members:<ns>:<server>` shape; (6) if
`opts.minEpoch` is set, `epoch <= minEpoch` (monotonicity — replay/rollback
defence). On success it returns `{ namespace, serverId, blob, keyed, epoch,
signerPubkeyHex }`, where **`signerPubkeyHex` is the in-blob provenance signer (the
server's key), NOT the Nostr event author** — the consumer pins/extends-trust on
that value.

> Two **distinct** signatures gate a publication: the Nostr event signature (NIP-01
> transport integrity) **and** the in-blob Schnorr provenance signature. A consumer
> trusts a hit only after BOTH verify and `signerPubkeyHex` equals a pinned server
> key (see SECURITY.md — a forged filter is a doxxing primitive).

### 5.3 serverId-with-colons in the d-tag

The d-tag is `kindred:members:<namespace>:<serverId>`; the namespace is the segment
up to the **next** colon, and the serverId is the rest. So a `serverId` may itself
contain colons (e.g. a `wss://host:port/path` URL) — the parser splits only on the
first colon after the prefix and takes the remainder verbatim.

### 5.4 Opt-out request (`buildOptOutRequest`)

`kind 30445`, tags `["d", kindred:members:<ns>:<server>]` and
`["p", <memberPubkey>]` (the x-only pubkey derived from the member private key,
self-identifying the opter), `content = "opt-out"`. Returns an **unsigned**
`EventTemplate` the **member** signs. The server honours it on the **next rebuild**
(it cannot retroactively remove a member from an already-published immutable blob).
The member private-key byte copy and derived pubkey byte copy are both zeroized
after derivation (same best-effort caveat as §1.6).

### 5.5 Aggregator query

`aggregatorQuery(namespace)` → `{ kinds: [30444], '#n': [namespace] }` — the relay
filter an aggregator uses to collect every server's publication for one namespace
across all `serverId`s.

---

## 6. Invite canonical bytes (`./invite`)

A `JoinInvite` is the signed "come join this game" token (cold-start bootstrap). It
is **not** a Nostr event — it is a structured token (QR/URL) signed with a
**custom-payload** Schnorr signature, not `finalizeEvent`.

### 6.1 Canonical signing bytes (verbatim)

```
digest = sha256( utf8( "kindred-invite:v1:" + namespace + ":" + serverId
                       + ":" + inviterPubkey + ":" + nonce
                       + ":" + (expiresAt ?? '') ) )
sig    = bytesToHex( schnorr.sign(digest, hexToBytes(inviterPriv)) )
```

`expiresAt` renders as its decimal string, or `''` when absent — so an invite with
no expiry and one with `expiresAt: 0` produce **different** digests (`…:nonce:` vs
`…:nonce:0`), which is correct (they are different invites).

### 6.2 Why a colon in `serverId` is safe here

`serverId` is free-form and MAY contain colons. That is safe — **unlike**
@forgesworn/tessera-kit's capability token, whose canonical string was the **sole** wire carrier
(an embedded colon there could shift field boundaries, so it bans colons). Here the
invite is parsed from a structured **JSON object** and the signature binds the exact
field **values**; the canonical string is only ever **recomputed from the
already-parsed fields**, never re-split out of a flat string. So a colon in
`serverId` cannot create field-boundary ambiguity. (Every field is still validated —
defence in depth.)

### 6.3 Parse hardening

`parseJoinInvite(blob, now?)`: 8192-byte size cap **before** decode/parse; clear
`Error` for non-JSON (no raw `SyntaxError` leak); `v === 1`; hex-field + nonce
validation; **recompute** the canonical digest from the parsed fields and
`schnorr.verify` against the embedded `inviterPubkey`; reject when `now > expiresAt`
(expiry is **exclusive** — `now === expiresAt` is still valid; `now` is injectable
for deterministic tests). `buildJoinInvite` additionally asserts at build time that
`schnorr.getPublicKey(priv) === inviterPubkey`, so a caller cannot mint an invite
claiming a key it doesn't control.

### 6.4 Single-attestation verify (`verifyBondAttestation`)

`verifyBondAttestation(event)` is the anti-sybil **brick** (spec §9.2). Checks, in
order: (a) `verifyEvent` (sig + id); (b) kind `31000`; (c) a
`["type","kindred-bond"]` tag (the exact discriminator `nostr-attestations` emits —
verified against the real `buildBondAttestation` output, not guessed); (d) a subject
`["p", <64-hex>]` tag. Returns `{ ok, attesterPubHex: event.pubkey, subjectPubHex }`
(`ok:true` on success; `{ ok:false }` otherwise).

This is **per-attestation verification ONLY**. Counting a member's attestations into
a set of **distinct verified humans** (the collective/guild sybil-resistance of
§9.2) is the **consuming app's** job — kindred does **no graph traversal and no
counting** (that would breach the §2 non-goals).

> **`Symbol(verified)` footgun (also in SECURITY.md).** `nostr-tools`' `verifyEvent`
> caches its result in an enumerable `Symbol(verified)` on `finalizeEvent` output. An
> object-spread (`{...ev, ...}`) copies that cache, so a verified-then-mutated event
> would short-circuit `verifyEvent` on the **stale** `true` — a false-green. Pass the
> **raw wire event** (or a `JSON.parse(JSON.stringify(ev))` wire-clone) to
> `verifyBondAttestation` / `parseFilterPublication`, never a spread-mutated one.

---

## 7. Handshake (`./handshake`)

The first message of a kith bond — I present the persona pubkey I'm bonding as, a
fresh nonce, an optional display name, and optionally a consensually-disclosed list
of additional personas.

```typescript
interface HandshakePayload {
  v: 1
  pubkey: string                              // 64-hex persona pubkey I present
  displayName?: string                        // ATTACKER-CONTROLLED — consumer truncates on display
  nonce: string                               // 16-byte hex (exactly 32 chars) — ceremony counter seed
  personas?: { pubkey: string; label?: string }[]   // bounded to ≤16 on parse
}
```

`buildHandshakePayload` stamps `v:1` and UTF-8-encodes the JSON.
`parseHandshakePayload` enforces: 8192-byte cap **before** decode; `v === 1`;
`pubkey` 64-hex; `nonce` exactly 32-hex; `personas` a ≤16 array of
`{ pubkey: 64-hex, label? }`. `displayName` is validated as a string but returned
**verbatim** — sanitizing here would mangle legitimate names and give false safety;
the consumer truncates at the point of display.

---

## 8. The build(object) / parse(bytes) asymmetry

Both the handshake and the invite are **asymmetric** by design (matching the spec
signatures):

| Format | `build*` returns | `parse*` takes |
|--------|------------------|----------------|
| handshake | `Uint8Array` (UTF-8 JSON, ready for QR/NFC/relay) | `Uint8Array` |
| invite | a `JoinInvite` **object** (the caller serializes to whatever transport they like) | `Uint8Array` (the decoded bytes) |

So an invite round-trip is `build(object) → consumer serializes to bytes → parse`.
`buildJoinInvite` does **not** return bytes — the transport is the caller's choice;
the signature binds the field values, not a specific byte encoding.

---

## 9. Canonical entry serialization (`.` / `serializeEntry`)

`serializeEntry(entry)` produces **byte-stable** canonical JSON: it is built on
`toWire(entry)` (which structurally strips `annotations`) then a **recursive
key-sort** (lexicographic; arrays keep order; `undefined` optionals are dropped so
absent keys never materialise). Two devices therefore serialise **identical bytes**
for the same entry (cross-device sync, §12.1). The output **never** contains an
`annotations` key — both because `toWire` removes it and because the sort emits only
present keys. `parseEntry` runs full field guards (allow-listed tier, 64-hex
pubkeys, finite timestamps, mutual-tier shared-secret, ken provenance) and never
restores annotations (the wire form never carried them).

---

## 10. Companion data rail (`./companion-rail`)

The companion rail is a pure producer/consumer wire contract. A companion
builds `signet-grant://pair?...`; Signet parses it and returns an encrypted
kind-21237 acknowledgement; Signet then publishes encrypted kind-30078
replaceable snapshots under `d=signet:companion-rail`. The shared reducer
accepts only a strictly newer `publishedAt`; malformed and stale envelopes
return the exact input state, while a newer `revoked:true` tombstone clears
contacts and pairing state.

Kindred does not open relays, schedule timers, store keys, encrypt content or
render grant UI. Those are application lifecycle and policy concerns.

## 11. Constants summary

| Constant | Value | Where |
|----------|-------|-------|
| `KINDRED_BOND_NAMESPACE` | `"kindred:bond"` | `./bond` |
| `KINDRED_FILTER_KIND` | `30444` (provisional; matches @forgesworn/tessera-kit) | `./discovery` |
| `KINDRED_OPTOUT_KIND` | `30445` (provisional) | `./discovery` |
| bond attestation kind | `31000` (`nostr-attestations` `ATTESTATION_KIND`) | `./bond`, `./invite` |
| invite canonical prefix | `"kindred-invite:v1:"` | `./invite` |
| d-tag prefix | `"kindred:members:"` | `./discovery` |
| handshake / invite blob cap | `8192` bytes | `./handshake`, `./invite` |
| filter blob cap | `64 MiB` (@forgesworn/tessera-kit `KFLT_MAX_BLOB_BYTES`) | `./discovery` |
| handshake `personas` cap | `16` | `./handshake` |
| companion ack kind | `21237` | `./companion-rail` |
| companion snapshot kind | `30078` | `./companion-rail` |
| companion snapshot d-tag | `"signet:companion-rail"` | `./companion-rail` |

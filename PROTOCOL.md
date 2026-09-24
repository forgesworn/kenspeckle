kenspeckle Protocol — verified-relationship wire formats & ceremonies
==================================================================

For a clean-room re-implementer. This document specifies the byte-exact ECDH bond
secret (with a **frozen migration vector**), the spoken-token directional usage,
the Nostr kind allocation + tag shapes for discovery, the invite canonical bytes,
and the build/parse asymmetry. `README.md` is the usage guide; `SECURITY.md` is the
honest privacy posture (read it — several intuitive guarantees are deliberately
**not** made).

`v1` for every wire format below except the invite, which is `v2` since its
canonical encoding changed (`HandshakePayload.v = 1`, `JoinInvite.v = 2`,
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
on output so two independent callers agree byte-for-byte — except the invite
parser, which accepts **only** lowercase hex so each invite has exactly one wire
spelling (§6.3).

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

`deriveBondSecret` makes **no zeroization claim**. The private key arrives as an
immutable JS **string**, and the ECDH runs on a `BigInt` scalar and point limbs,
none of which can be wiped from JS. It makes no byte copy of the key. (An earlier
version made a byte copy, never used it, and wiped it; that protected nothing, so
it was removed.)

Where kenspeckle *does* hand a byte copy of a key to `@noble` (`buildJoinInvite`,
`buildOptOutRequest`), that copy is wiped with `.fill(0)` in a `finally`. The
bigint scalar `@noble` derives from it internally is still not wipeable from the
call site, so that too is best-effort. A future Rust/WASM port MUST take keys as
bytes and zeroize the scalar and the ECDH point.

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
  kenspeckle exposes pure functions and takes the counter as a parameter.
- **Inputs are validated.** `bondWords` throws a `bondWords:` error unless the
  secret and both pubkeys are 64-hex, the two pubkeys **differ** (a self-bond has
  no counterparty word) and the namespace is non-empty. `verifyBondWord` returns
  `{ ok: false }` for a bad pubkey, a self-bond or an empty namespace, and throws
  only for a malformed secret (a programmer error).
- **Guessing odds.** A word is one of 2048 (11 bits). With `tolerance` `t` there
  are `2t + 1` accepted words, so a blind guess succeeds with probability about
  `(2t + 1) / 2048`: ≈0.05% at `t = 0`, ≈0.15% at `t = 1`, ≈1% at `t = 10`. There is
  no rate limit in the library (see SECURITY.md).
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

| Parameter | `signet-me` (signet-protocol) | kenspeckle default |
|-----------|-------------------------------|-----------------|
| namespace | `'signet:me'` | `'kindred:bond'` (`KINDRED_BOND_NAMESPACE`) |
| counter | `getCounter(now, 30)` (30 s rotation) | the consumer's chosen `counter` arg |
| tolerance | `±1` epoch (clock-skew window) | `0` (exact counter) |

So **with kenspeckle's DEFAULT opts the words DIFFER from `signet-me`'s** — a naive
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
  caller-order roles `[myPubkey, theirPubkey]` while kenspeckle sorts to `[lo, hi]`, but
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
  `signet-me`'s ±1 clock-skew window. kenspeckle reproduces the words **via params** (it
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
- **`buildBondRevocation({ subjectPubHex, reason? })`** → unsigned kind-31000
  **revocation** via `nostr-attestations`' `createRevocation({ type: 'kindred-bond',
  identifier: subject, subject })`. This is the **primary** retraction: it
  republishes the same addressable slot (`d = kindred-bond:<subject>`) with
  `["status","revoked"]` (plus `["p", subject]`, optional `["reason", …]`), so it
  replaces the attestation wherever addressable semantics are honoured, and
  `verifyBondAttestation` rejects it (`reason: 'revoked'`, §6.4). Signed by the
  SAME key that signed the attestation.
- **`retractBondAssertion(assertion, { attesterPubHex, subjectPubHex })`** →
  unsigned kind-5 NIP-09 deletion request, a **supplement** to the revocation. Tags:
  `["e", mineId]`, `["a", "31000:<attester>:kindred-bond:<subject>"]`,
  `["k", "31000"]`. `mineId` and both pubkeys must be 64-hex (lowercased). The `a`
  tag matters: kind 31000 is addressable, and an `e` tag alone deletes one version
  while a republished version under the same `d` survives. Signed by the SAME key
  that signed the original. A network-wide retraction can never be
  cryptographically guaranteed — NIP-09 is a request, which is why the revocation
  comes first.

`created_at`: `createAttestation` returns an optional `created_at`; kenspeckle stamps
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
- `dropKen` is a documented **no-op** — kenspeckle owns no storage, so deleting the
  record is the consumer's responsibility.

---

## 5. Discovery — kind allocation & publication shape (`./discovery`)

Discovery is a thin layer over the sibling **@forgesworn/tessera-kit** membership filter: a
server publishes a signed, non-enumerable presence filter; a client tests its own
contacts locally (presence, not a member list). kenspeckle holds no state, opens no
sockets, and never enumerates a server's membership.

### 5.1 Kind allocation (provisional — NOT NIP-registered)

```
KINDRED_FILTER_KIND  = 30444   // addressable filter publication
KINDRED_OPTOUT_KIND  = 30445   // a member's opt-out request
```

Both are **provisional and not yet NIP-registered**. `30444` **matches
@forgesworn/tessera-kit PROTOCOL.md §6 byte-for-byte** — the publication shape is shared so a
@forgesworn/tessera-kit-only server (no `kenspeckle` dependency) can emit an identical event. It
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

```typescript
interface JoinInvite {
  v: 2
  namespace: string      // non-empty, well-formed UTF-16
  serverId: string       // non-empty, well-formed UTF-16; MAY contain ':'
  inviterPubkey: string  // 64 lowercase hex (x-only)
  nonce: string          // ≥ 16 bytes of lowercase hex (≥ 32 chars, even length)
  expiresAt?: number     // unix seconds, non-negative safe integer
  sig: string            // 128 lowercase hex (64-byte BIP-340 signature)
}
```

### 6.1 Canonical signing bytes, v2 (verbatim)

```
canonical = JSON.stringify(["kenspeckle-invite", 2, namespace, serverId,
                            inviterPubkey, nonce, expiresAt ?? null])
digest    = sha256( utf8(canonical) )
sig       = bytesToHex( schnorr.sign(digest, hexToBytes(inviterPriv)) )
```

`JSON.stringify` here is ECMAScript's: no whitespace, strings quoted with `"`,
`"` and `\` backslash-escaped, U+0000–U+001F escaped (`\b \f \n \r \t` or
`\u00XX`, lowercase hex), everything else emitted as the literal character. A
non-JS implementation must produce the same bytes. `expiresAt` is a safe integer,
so it always renders as plain decimal digits; an absent expiry renders `null`, so
an invite with no expiry and one with `expiresAt: 0` have **different** digests.

The frozen vector is `vectors/invite.v2.json` (checked by
`scripts/check-vectors.mjs`): it pins `canonical`, `digest`, a BIP-340 `sig` made
with fixed aux randomness, the wire bytes, and a set of inputs that MUST be
rejected, including the cross-field shift below.

### 6.2 Why the encoding is a JSON array (and why v1 was withdrawn)

v1 signed the colon-joined string
`"kenspeckle-invite:v1:" + namespace + ":" + serverId + ":" + …`. `namespace` and
`serverId` are free text that may contain `:`, so that string was **not
injective**: two different field tuples could flatten to the same bytes. An invite
signed for `{ namespace: "game", serverId: "eu:prod" }` verified as
`{ namespace: "game:eu", serverId: "prod" }`. Recomputing the string from the parsed
JSON fields does **not** help; the signature covers the flattened bytes, and both
tuples produce them. (Earlier versions of this document claimed a colon was safe
for that reason. That claim was wrong.)

A JSON array quotes and escapes every string, so distinct tuples always produce
distinct bytes and a `:` (or a `"`) in any field is harmless. One more collapse is
closed: `utf8()` maps a lone UTF-16 surrogate to U+FFFD, so `"\uD800"` and
`"\uFFFD"` would encode alike. Strings that are not well-formed UTF-16 are
therefore **rejected at build and at parse**.

**v1 invites are not accepted.** There is no fallback: nothing consumed invites
before v2, and a v1 verifier path would keep the forgery above alive.

### 6.3 Parse hardening

`parseJoinInvite(blob, now?)`: 8192-byte size cap **before** decode/parse; clear
`Error` for non-JSON (no raw `SyntaxError` leak); `v === 2`; `namespace` and
`serverId` non-empty and well-formed; `inviterPubkey`, `nonce` (≥ 16 bytes) and
`sig` **lowercase** hex (one wire spelling per invite); `expiresAt`, if present, a
non-negative safe integer; **recompute** the canonical digest from the parsed
fields and `schnorr.verify` against the embedded `inviterPubkey`; reject when
`now > expiresAt` (expiry is **exclusive** — `now === expiresAt` is still valid;
`now` is injectable for deterministic tests).

`buildJoinInvite(p, inviterPriv, now?)` applies the same field rules (hex input may
be any case and is lowercased), asserts `schnorr.getPublicKey(priv) ===
inviterPubkey` so a caller cannot mint an invite claiming a key it doesn't control,
and, when `now` is given, refuses an `expiresAt` already in the past.
`generateInviteNonce()` returns 16 fresh CSPRNG bytes as hex.

**Replay.** A valid signature does not make an invite single-use. An inviter or
server that wants one-time invites MUST remember redeemed `(inviterPubkey, nonce)`
pairs and refuse a repeat (until `expiresAt`, if set). The 16-byte nonce minimum
keeps those pairs from colliding by accident.

### 6.4 Single-attestation verify (`verifyBondAttestation`)

`verifyBondAttestation(event, now?)` is the anti-sybil **brick** (spec §9.2).
Checks, in order, returning `{ ok: false, reason }` on the first failure:

| # | check | `reason` |
|---|-------|----------|
| a | `verifyEvent` (sig + id) | `bad-signature` |
| b | kind `31000` | `wrong-kind` |
| c | a `["type","kindred-bond"]` tag | `not-kindred-bond` |
| d | **exactly one** `["p", <64-hex>]` tag | `bad-subject` |
| e | exactly one `d` tag, equal to `kindred-bond:<lowercase subject>` | `d-tag-mismatch` |
| f | subject ≠ attester | `self-attestation` |
| g | `nostr-attestations` `isValid(event, now)` | `revoked`, `expired`, `not-yet-active`, `claim-expired` |

(g) rejects a `["status","revoked"]` event, a passed NIP-40 `expiration`, a future
`valid_from` and a passed `valid_to`. `now` defaults to the wall clock (unix
seconds), the same convention as `parseJoinInvite`. On success it returns
`{ ok: true, attesterPubHex, subjectPubHex }`, **both lowercased**, so a
distinct-count over them cannot be inflated by case. Check (e) ties the event to
the address a `buildBondRevocation` for that subject overwrites; an attestation
parked at any other `d` could never be revoked.

**Fetch the latest version.** (g) only sees the event it is given. A revocation
*replaces* the attestation at `(attester, 31000, d)`; an older, non-revoked copy
still verifies on its own. A consumer MUST query the latest event at that address
(and SHOULD honour kind-5 deletions) before counting it.

This is **per-attestation verification ONLY**. Counting a member's attestations into
a set of **distinct verified humans** (the collective/guild sybil-resistance of
§9.2) is the **consuming app's** job — kenspeckle does **no graph traversal and no
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

`buildHandshakePayload` builds the object from an explicit **allowlist** —
`v: 1, pubkey, nonce, displayName?, personas?[{ pubkey, label? }]`, in exactly that
key order, hex lowercased — and UTF-8-encodes the JSON. Nothing else from the
caller's object reaches the wire (TypeScript's excess-property check does not apply
to non-literal arguments). It then runs `parseHandshakePayload` over its own output
and throws if the peer would reject it.

`parseHandshakePayload` enforces: 8192-byte cap **before** decode; `v === 1`;
`pubkey` 64-hex **and a valid curve x-coordinate** (liftable with even y);
`nonce` exactly 32-hex; `personas` a ≤16 array of `{ pubkey: 64-hex on-curve,
label? }`, with **no duplicates** and none equal to `pubkey`. `displayName` is
validated as a string but returned **verbatim** — sanitizing here would mangle
legitimate names and give false safety; the consumer truncates at the point of
display.

The frozen vector is `vectors/handshake.v1.json`: exact build bytes for given
inputs (including extra fields that must be dropped) and inputs that MUST be
rejected.

**Open question — the nonce.** This section calls the nonce the "ceremony counter
seed", but no derivation from the two peers' nonces to a spoken-word `counter` is
specified, and §2 says the counter is the consumer's choice. kenspeckle
implements no such derivation. Until one is specified, the nonce is only
freshness that a consumer may use; two consumers will not agree on a counter from
it without an out-of-band convention.

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
pubkeys, finite timestamps, mutual-tier shared-secret, ken provenance **and each
ken corroboration**, capped at 64) and never restores annotations (the wire form
never carried them).

**`corroborations` (optional, ken only).** An array of `KenProvenance` recording
*additional independent channels* that agree the key belongs to the person;
`provenance` remains the required, singular primary. Element order is observation
order and is preserved (the key-sort orders object keys, not array elements). Each
element is validated by the **same** allow-list as the primary, so the `source`
union is shared and cannot widen. The field is **purely additive**: an entry
without it serialises byte-identically to one produced before the field existed,
because the sort emits only present keys. Malformed corroborations are **rejected**
(the whole entry throws) rather than dropped — evidence that fails its guard must
not be quietly discarded into a valid-looking record.

Because `parseEntry` reconstructs from a whitelist, an **older** parser meeting a
newer entry silently drops `corroborations` on re-serialisation. That is round-trip
data loss through old code, not breakage; land kenspeckle and its consumers together.

---

## 10. Companion data rail (`./companion-rail`)

The companion rail is a pure producer/consumer wire contract. A companion
builds `signet-grant://pair?...`; Signet parses it and returns an encrypted
kind-21237 acknowledgement; Signet then publishes encrypted kind-30078
replaceable snapshots under `d=signet:companion-rail`.

**Pairing request.** `parsePairingRequest` accepts the native
`signet-grant:` URI, an `https:` carrier URL, or a bare query; anything else
before a `?` is rejected (`bad-scheme`). Input longer than 4096 characters is
rejected; a `#fragment` is ignored. `t` must be plain decimal digits (no `0x`,
exponent, sign or padding). `challenge` is 16–128 hex characters (build and
parse). The caller's `nowSec` / `freshnessSeconds` must be finite and
non-negative, or the call throws — a `NaN` window would silently disable the
freshness check.

**Ack.** `buildPairingAck` serialises the parsed projection (`v, railPubkey,
dTag, snapshotRelay, grantedScope, challenge`), never the caller's object, and
`parsePairingAck` requires a 16–128-hex challenge equal to the expected one.

**Snapshots.** The grant envelope is
`{ v: 1, scope: { tiers, personas }, contacts: GrantContactView[], publishedAt,
revoked?: true }`. `publishedAt` (and each contact's `addedAt`) MUST be a
non-negative safe integer; anything else (`1e400` parses as `Infinity`) makes the
envelope (or the contact) malformed. The parser lowercases hex, strips
control/bidi characters from display text, returns a projected `scope`, drops
contacts outside that scope (tier not listed, or an owner persona not listed),
and reads at most 5000 contacts; `buildGrantEnvelope` projects the same allowlist
and throws if a contact would not survive that parse.

**Reducer.** The consumer MUST check that a snapshot event is signed by
`pairing.railPubkey` before handing its decrypted content to
`applyCompanionSnapshot`. The reducer then:

1. returns the exact input state for a malformed envelope;
2. returns the exact input state for **anything** once `state.revoked === true`.
   **Revocation is terminal for the pairing** — a later non-revoked snapshot can
   never bring contacts back. Resuming needs a new pairing, after which the app
   starts from a fresh state (`revoked: false`, no `lastPublishedAt`);
3. applies a `revoked: true` tombstone **regardless of `publishedAt` order**
   (clearing contacts and pairing, `lastPublishedAt = max(old, new)`), so a
   producer clock error that published a far-future snapshot cannot block the
   owner's revocation;
4. otherwise accepts only a strictly newer `publishedAt`, returning the exact
   input state for a stale one.

Kenspeckle does not open relays, schedule timers, store keys, encrypt content or
render grant UI. Those are application lifecycle and policy concerns.

### 10.1 Return rail — proposing a ken

The return direction is **kens-only, by construction**. A kith/kin entry is a
bond carrying an ECDH `sharedSecret` minted by a ceremony between *identity*
keys; a companion app holds only its own device keypair, so it **cannot** mint
one. It can capture a name + pubkey, which is exactly a ken. The companion
publishes an encrypted kind-30078 replaceable event under
`d=signet:companion-return`, content
`{ v: 1, additions: WireKen[] }`:

```jsonc
{ "pubkey": "<64-hex>", "displayName": "Wren", "nip05": "wren@example.org",
  "claimedProvenance":     { "source": "in-person", "locator": "…", "confirmedAt": 1750000000 },
  "claimedCorroborations": [ { "source": "dns", "locator": "…", "confirmedAt": 1750000100 } ] }
```

`claimed*` fields use `KenProvenance` **verbatim** — the `source` union is
unchanged, and an unrecognised source drops that claim on parse. At most
`RETURN_ADDITIONS_CAP` (50) additions per envelope and
`RETURN_CORROBORATIONS_CAP` (8) claims per addition; `parseReturnEnvelope`
rejects a structurally-bad envelope (`null`) but drops only the offending
addition otherwise.

**A claim is not a confirmation.** `landReturnedKen` projects a `WireKen` into a
`KenEntry` under exactly two rules, applied in one place so they cannot drift:

| field | value |
|---|---|
| `provenance` | `{ source:'manual', locator:'companion:<appName>', confirmedAt: now }` — what Signet can attest from its own knowledge |
| `corroborations[]` | every claim, `source` preserved **verbatim**, locator rewritten `companion:<appName>:<claimed locator>`, `confirmedAt` clamped into `[0, now]` |
| `nip05` | **NOT set.** See below. |

**`entry.nip05` is never set from a claim.** It is not a label — it is the address
`resolveKen` re-fetches, and a key change observed there is surfaced to the user as
`via:'nip05'`, i.e. a DNS/TLS-anchored signal. Copying an app-supplied identifier
into it would let a paired companion *choose the re-resolution authority* for a ken
and have its own answer presented as an authoritative rotation proposal — the exact
inversion of "no app but Signet is a source of identity truth". A claimed `nip05` is
therefore shape-guarded (`local@domain`; it would otherwise be interpolated into a
fetch URL) and filed as a namespaced **corroboration**. Signet sets `entry.nip05`
only after resolving the identifier itself, which is the step that makes it a
confirmation.

**`companion:` is a RESERVED locator prefix.** Only `landReturnedKen` mints it; no
first-party flow may use it. That reservation is what lets
`summarizeKenProvenance().claimed` report how much of a ken's apparent corroboration
is merely relayed claim rather than first-hand verification.

**Locator grammar — `:` in `<appName>` is escaped as `%3A`.** This is load-bearing, not cosmetic. Without it the grammar is not injective and the namespace is **forgeable**: an app calling itself `Murmurate:trusted` and claiming locator `y` would emit `companion:Murmurate:trusted:y` — byte-identical to legitimate app `Murmurate` claiming locator `trusted:y`. Escaping the single delimiter character means splitting on the first two colons always recovers exactly `(appName, claimed locator)`. Only `:` is escaped, so ordinary names are unchanged. A claimed locator may itself contain `:` — everything after the second colon is the locator verbatim.

The `<appName>` segment is stripped of the same invisible characters as a claimed
locator (word joiner, BOM, U+E0000 tag characters …) and sliced by code point, so
`companion:Signet` followed by U+2060 cannot render as plain `companion:Signet`.

A non-finite claimed `confirmedAt` is rejected (`landReturnedKen` throws) rather than clamped, since `Math.min(NaN, now)` is `NaN` and would emit an entry that kenspeckle's own `validateProvenance` rejects.

So real `in-person` evidence survives the journey as `in-person` instead of being
flattened to "manual, via some app" — while the namespace makes it structurally
impossible to misread a claim as something Signet confirmed itself, and the clamp
stops an app claiming a future confirmation to poison recency reasoning.

## 11. Constants summary

| Constant | Value | Where |
|----------|-------|-------|
| `KINDRED_BOND_NAMESPACE` | `"kindred:bond"` | `./bond` |
| `KINDRED_FILTER_KIND` | `30444` (provisional; matches @forgesworn/tessera-kit) | `./discovery` |
| `KINDRED_OPTOUT_KIND` | `30445` (provisional) | `./discovery` |
| bond attestation kind | `31000` (`nostr-attestations` `ATTESTATION_KIND`) | `./bond`, `./invite` |
| invite canonical array | `["kenspeckle-invite", 2, …]` (`INVITE_DOMAIN`, `INVITE_VERSION`) | `./invite` |
| invite nonce minimum | `16` bytes (`INVITE_NONCE_MIN_BYTES`) | `./invite` |
| d-tag prefix | `"kindred:members:"` | `./discovery` |
| handshake / invite blob cap | `8192` bytes | `./handshake`, `./invite` |
| filter blob cap | `64 MiB` (@forgesworn/tessera-kit `KFLT_MAX_BLOB_BYTES`) | `./discovery` |
| handshake `personas` cap | `16` | `./handshake` |
| companion ack kind | `21237` | `./companion-rail` |
| companion snapshot kind | `30078` | `./companion-rail` |
| companion snapshot d-tag | `"signet:companion-rail"` | `./companion-rail` |
| companion return d-tag | `"signet:companion-return"` | `./companion-rail` |
| return additions cap | `50` | `./companion-rail` |
| return corroborations cap | `8` per addition | `./companion-rail` |
| pairing challenge length | `16`–`128` hex chars (`PAIRING_CHALLENGE_MAX`) | `./companion-rail` |
| pairing input cap | `4096` chars (`PAIRING_INPUT_MAX`) | `./companion-rail` |
| grant envelope contacts cap | `5000` (`GRANT_CONTACTS_CAP`) | `.` (grant envelope) |
| backup header | `"KSBK" ‖ 0x01` (`BACKUP_FORMAT_VERSION = 1`) | `.` (backup) |

## 12. Encrypted self-backup (`.` / `exportEntriesEncrypted`)

```
header = utf8("KSBK") ‖ 0x01                        // magic + format version (5 bytes)
blob   = header ‖ nonce(24) ‖ XChaCha20-Poly1305(key, nonce, aad = header)(utf8(JSON.stringify(entries)))
```

`key` is 32 bytes; the nonce is fresh CSPRNG output per export. The plaintext is
the roster **including** private annotations. Binding the header as AAD means a
flipped version byte or magic fails authentication, and a ciphertext sealed under
the same key by some other scheme is not accepted as a v1 backup.

`importEntries` reads v1 blobs and, for continuity, **legacy** blobs written
before the header existed: `nonce(24) ‖ ciphertext`, no AAD. If a blob starts
with the header but does not authenticate as v1, it is retried as legacy (a legacy
nonce begins with the header bytes with probability 2⁻⁴⁰). Legacy blobs are never
written. Because legacy reading is kept, the domain separation above is one-way:
a header-less ciphertext made by another scheme under the same key would still be
read as a legacy backup — do not reuse the backup key for anything else.

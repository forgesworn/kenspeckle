# kenspeckle roadmap

kenspeckle is the implementation of **kindred**: verified relationships across
three social distances — *kin* (family), *kith* (mutually verified), *ken*
(one-way recognised) — plus the bond ceremony, discovery and the companion rail.
Presence filters come from [tessera-kit](https://github.com/forgesworn/tessera-kit)
(see its [ROADMAP.md](https://github.com/forgesworn/tessera-kit/blob/main/ROADMAP.md)).

## Where it sits

- **Consumers:** signet-app (git pin `747b82a`, moving to `^0.2.0` from npm) and
  kindependence/app (git pin `d8d0d31`, not yet bumped). signet-contacts shares
  the wire formats but does not import the package.
- **Depends on:** `@forgesworn/tessera-kit` `^0.2.1`, `nostr-attestations` `^2.5.5`,
  `spoken-token` `^2.1.0`, `@noble/*`.
- **Spec:** [PROTOCOL.md](./PROTOCOL.md); security model in [SECURITY.md](./SECURITY.md);
  golden vectors in [`vectors/`](./vectors) (`npm run vectors:check`).

## Shipped

| Item | Version |
|------|---------|
| Two internal security audits (H/M/L findings) fixed; breaking changes marked in CHANGELOG | 0.2.0 |
| Invite v2 (injective encoding, mandatory 16-byte nonce), `buildBondRevocation`, `verifyBondAttestation` | 0.2.0 |
| `deriveCeremonyCounter` / `timeCounter` (handshake nonces → spoken-word counter; no replay), `normalizeSpokenWord` | 0.2.0 |
| Frozen vectors: ECDH, bond words (signet:me rows confirmed against signet-me), ceremony counter, invite, handshake, companion rail | 0.2.0 |
| tessera-kit 0.2.x context-bound filter signatures; `parseFilterPublication(Result)` requires `{ namespace, serverId }`; colon-free namespace rule | 0.2.0 |
| `parseFilterPublicationResult` reason codes; `acceptKenRotation` refuses revoked entries; `validateNip05` exported from `./ken` | 0.2.0 |
| Versioned encrypted backup (`KSBK` header as AAD) | 0.2.0 |
| Coverage, publint/attw, Node 22 + 24 CI, `./package.json` export | 0.2.0 |
| Published to npm with provenance | 0.2.0 (2026-09-26) |

## Open

Each item says why it is not done yet. **Blocked on** names what has to happen
first; if it's empty, the item can be picked up directly. Versioning while on
0.x: additive changes ship as a patch (0.2.x); anything breaking is 0.3.0 and
needs signet-app and kindependence to move in step.

### Next up (safe, additive)

| Item | Size | Why | Blocked on |
|------|------|-----|------------|
| Export `MAX_CORROBORATIONS` from `./ken` | S | Consumers building UI around corroborations hard-code 64 today; it lives in `src/validate.ts` but no public entry exports it | — |
| Export a public `validateEntry(entry)` pre-persist / pre-export check | S | Apps store ken entries raw (signet-app IndexedDB) and only find out an entry is invalid when ken-sync parses it on another device | — |
| Optional "drop and report" mode for `buildGrantEnvelope` | S–M | It throws if any one contact would not survive the wire; signet-app had to pre-sanitise `addedAt` and add per-grant try/catch so one bad contact didn't stop every snapshot. An opt-in `{ onInvalid: 'skip' }` returning the skipped contacts would make that the library's job | — |
| Remove the `0.0.0-seed.0` version's `seed` dist-tag on npm | S | Leftover from creating the package; harmless | npm owner access (`npm dist-tag rm @forgesworn/kenspeckle seed`) |

### Needs a design decision first

| Item | Size | Why | Blocked on |
|------|------|-----|------------|
| `promoteKenToKith` / `mergeEntries` / `upsert` with tier precedence | M | Tier changes should only happen through a ceremony artefact (bond proof); today a consumer can overwrite a ken with a kith entry itself. Mentioned in `src/validate.ts` but not built | Trust-model design: what counts as proof, how merges resolve conflicts |
| nostr-attestations 3.0.0 | M | 3.0.0 changes the wire format of kind-31000 attestations (bond records). Dependabot PR #31 was closed on purpose so it's done as one coordinated change | Coordinated upgrade across kenspeckle, signet-app and kindependence; breaking 0.3.0 |
| Filters larger than one relay event (Blossom pointer or chunking) | M–L | Around ~28k members a filter no longer fits a typical 64 KB relay event | Joint decision with tessera-kit (see its roadmap); only matters at that scale |
| Version tag on the kindred filter event | S | Lets a future KFLT v2 roll out cleanly | kindred convention change agreed with tessera-kit; breaking 0.3.0 |

### Outside this repo

| Item | Where |
|------|-------|
| Move off git pins to `"@forgesworn/kenspeckle": "^0.2.0"`, `"@forgesworn/tessera-kit": "^0.2.1"`; use `validateNip05` in `KenAdd.validateNip05Shape` | signet-app |
| Bump kenspeckle, and set `pairedAt` from the pairing request's `t` (`rail-live.ts:196`) instead of ack arrival time (`rail.ts:79`), or the first snapshot can be dropped by the new pairing floor | kindependence/app |
| Ship the kenspeckle bump to every device together: devices on the old pin drop `rotation.rollback` during ken-sync, so they won't see the rollback guard | signet-app / kindependence release planning |
| `FORGESWORN_READ_PAT` is still a secret in ~11 other forgesworn repos; kenspeckle no longer needs it | Org secrets housekeeping |

## Picking up an item (agents)

1. Read this file, then the relevant PROTOCOL.md section and the CHANGELOG's
   `[0.2.0]` entry (it explains every audit fix and breaking change).
2. For "Next up" items: branch, implement with tests, and run
   `npm run build && npm run typecheck && npm test && npm run vectors:check && npm run lint:package`.
   Never change a frozen vector to make a test pass; a changed vector means a
   wire change.
3. Anything touching bond words, ECDH, invites, handshake, discovery or the
   companion rail is a public contract: get an independent review of the diff
   even when tests pass.
4. Items under "Needs a design decision" need the owner's decision written down
   before any code. Record the decision here when it's made.
5. When an item ships, move it to **Shipped** with its version.

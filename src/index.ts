// kenspeckle — the `.` surface.
//
// The default entry ships the relationship MODEL and the LOCAL operations that act on it:
//   • the model types + the re-exported nostr-tools aliases (EventTemplate/NostrEvent/NostrFilter),
//     so a consumer has ONE canonical event type (`./types.js`);
//   • the local relationship ops — scope, search, private-link, canonical serialize/parse (`./model.js`);
//   • the encrypted self-backup export/import (`./backup.js`).
//
// The protocol subpaths — `./handshake`, `./bond`, `./ken`, `./discovery`, `./invite`, and
// `./companion-rail` — are
// DELIBERATELY NOT re-exported here. Each is imported via its own subpath
// (`import { deriveBondSecret } from '@forgesworn/kenspeckle/bond'`) so a consumer that only needs, say, the bond
// ceremony does not pull the discovery/tessera-kit graph. Keeping them off the `.` barrel is the
// load-bearing tree-shaking + dependency-isolation boundary, not an oversight.

// Model types + the canonical nostr-tools aliases (EventTemplate / NostrEvent / NostrFilter) +
// WireEntry + the hasSharedSecret predicate. `export *` carries the type-only aliases too.
export * from './types.js'

// Local relationship ops (spec §4, §12.1).
export {
  scopeToPersona,
  assertOwnedPersona,
  searchEntries,
  linkForRecall,
  unlink,
  toWire,
  serializeEntry,
  toSyncForm,
  serializeEntryForSync,
  parseEntry,
} from './model.js'

// Encrypted self-backup (spec §6.7, §12.1). INCLUDES private annotations — it is the user's own
// sealed copy, not a graph disclosure.
export { exportEntriesEncrypted, importEntries, BACKUP_FORMAT_VERSION } from './backup.js'

// Companion data rail envelope (model-level projection + serialize/parse,
// same surface class as toWire/serializeEntry/parseEntry).
export {
  toGrantView,
  buildGrantEnvelope,
  parseGrantEnvelope,
  GRANT_CONTACTS_CAP,
} from './grant-envelope.js'
export type { GrantContactView, GrantScope, GrantEnvelope } from './grant-envelope.js'

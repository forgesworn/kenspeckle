// kindred — `.` surface. Ships the relationship model types + re-exported nostr-tools aliases
// (K-1), the local model ops + encrypted self-backup (K-2). The subpath surfaces (./handshake,
// ./bond, ./ken, ./discovery, ./invite) land in later tasks via their own entrypoints.
export * from './types.js'
export {
  scopeToPersona,
  assertOwnedPersona,
  searchEntries,
  linkForRecall,
  unlink,
  toWire,
  serializeEntry,
  parseEntry,
} from './model.js'
export { exportEntriesEncrypted, importEntries } from './backup.js'

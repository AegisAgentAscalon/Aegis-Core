# W03 — cloud storage identity and namespace comparison

SD-01: new namespace directories and object filenames use domain-separated
SHA-256 hashes of JSON tuples under `.aegis-cloud-v2`. Tuple encoding preserves
component boundaries; lowercase hex paths keep case-only identities separate
on Windows and other case-insensitive filesystems. Public object references,
manifest serialization and manifest hashes are unchanged.

Legacy directories are read-only fallbacks. Exact embedded namespace, kind,
object ID, hash, size and timestamp authorize references; lossy filenames do
not authorize another identity. Listing merges surviving legacy and v2 records,
deduplicates identical references and rejects conflicting records. Foreign
legacy namespaces are excluded from lists; a mismatched legacy manifest is
reported as ErrCloudStoreCorrupt. Existing v2 corruption cannot fall back to an
older record. New writes never migrate, rename or delete legacy files, so
interruption cannot destroy the original during migration.

If an old colon/underscore or case collision already overwrote a record, its
reference fails with ErrCloudHashMismatch (or ErrCloudObjectNotFound if absent).
The original is unrecoverable without a backup or authoritative re-publication;
the provider never invents it from the surviving identity. Retain backups and
old directories until application-owned recovery is complete.

Older Core versions cannot see newly written v2 records. Upgrade every writer
sharing this store before writing new data; downgrade does not synchronize v2
writes back to legacy directories. Cross-process transactions and shared atomic
replacement durability remain deferred to W07; this is not a durability release.

SD-07: normalized manifests from different namespaces return invalid with review
required before any generation comparison, including case-only differences.

Regression tests cover collisions, namespace isolation, legacy references,
mixed stores, missing overwritten identities, conflicting survivors and legacy
byte preservation across canceled or failed writes. Sixteen audited findings
remain. W04 is not started; hosted CI and Linux race validation remain pending.

# W07 - Destination-preserving persistence

> Historical record for the revision named below. See [current status](../STATUS.md).

Baseline: W06 c8bbdedcba91d0f93340282530bea71b292e5c57.
See ../plans/W07_PERSISTENCE_DESIGN.md for the contract and platform limits.

The private primitive passed its Windows fault/path tests at 65c1904 before
owner migration. Initial tests exposed Windows sharing-error classification,
reserved names and trailing-dot normalization; the corrected checks reject
unsafe names before path normalization. Nil contexts are normalized for existing
owner API compatibility. Updates and Profile Sync are migrated separately.

Updates removes delete-before-rename, fixed-name artifact temporary files and
its unbounded metadata reader. Writers flush and close before replacement.
Caller contexts now reach metadata IO and lifecycle/restage helpers. The existing
context-free validation adapter and directory setup use a background context;
artifact hashing itself is unchanged, so this is not whole-operation interruptible
IO. Stream read failures retain ErrDownloadFailed; storage/cancellation errors
retain their existing public sentinels.

Profile Sync local and file-object storage uses bounded shared reads and writes,
with the existing 8 MiB JSON read bound now also enforced on write. Its historical
indented JSON plus final newline is preserved. Unsafe parents are rejected before
creating owner directories. The architecture guard allows only the exact shared
private primitive, not other owner implementations.

UA-05 is promoted to an ordinary Updates regression test. Additional owner tests
cover exact metadata bytes/reopen, cancellation, oversized/malformed writes and
stream failure preservation. Primitive tests inject create/chmod/write/short-write/
sync/close/replace/encoding/cleanup failures, test cancellation immediately before
commit, and exercise successful overwrite and Windows sharing denial. Symlink
checks can skip where Windows privileges are unavailable; report actual skips.

No persisted schemas, public APIs or dependency manifests changed. No cross-process
coordination, multi-file transaction, power-loss guarantee or W04 inbox is added.
Single-writer trusted roots and host-managed Windows ACLs are required. Existing
Auth/DeviceLink/ProfileMesh writers are not migrated in this first owner slice.

Independent review and Linux runtime/race tests remain qualification gates. Local
self-review is not independent review, and Linux cross-compilation is not execution.
The implementation is a local candidate; no hosted CI, push, merge or release.
Exact validation/evidence lives in the control repository under
 evidence/aegis-core-w07-20260911.

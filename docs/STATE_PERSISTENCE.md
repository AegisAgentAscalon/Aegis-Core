# Profile Mesh and Updates state

W14 replaces independent native metadata writes with one committed generation per
existing Profile Mesh root or Updates application/namespace/source/channel scope.
Each owner retains its own versioned state codec and validation rules. The shared
internal mechanism coordinates local processes and publishes bounded JSON state.

## Deployment and recovery boundary

Stop all writers using W13 or earlier before the first mutation with this format.
Those binaries ignore the new locks and state authority. Do not run old and new
writers against one root or roll back to an executable that cannot read this format.
Legacy files remain frozen; no dual writes or transparent historical restore occur.

The supported model uses trusted local filesystems and cooperating writers. It
covers process interruption, cancellation, individual metadata loss/corruption,
sharing violations and I/O failures. It does not promise power-loss ordering,
network-filesystem semantics, protection against hostile filesystem replacement,
or recovery after deletion of the entire root or native authority directory.

## Authority

The stable `.state.lock` file is never replaced, truncated or deleted. Each
acquisition opens a separate regular-file handle. Windows uses exclusive
nonblocking LockFileEx over byte `[0,1)`; supported Unix platforms use flock.
Blocking acquisition retries with context cancellation. Unsupported platforms
return an error instead of running without exclusion.

Before migration, absent `state-v2` means legacy metadata is authoritative.
A successful first mutation validates the old state and requested change, then
prepares a unique sibling `.state-prepare-ID` directory containing:

- `format.json`, binding the format and exact owner identity;
- one immutable `generation-ID.json`, containing a complete owner payload;
- `current.json`, binding revision, generation, parent token, byte count and hash;
- `backup/inventory.json` and exact original metadata bytes, including an explicit
  distinction between absent files and present empty files.

Files are flushed, closed and read back before one directory rename publishes the
prepared directory as `state-v2`. An orphan preparation directory has no authority.
Legacy metadata and artifact files are preserved.

After activation, only `state-v2/current.json` selects authority. Missing or corrupt
format, pointer, generation, binding or digest returns a storage error. Readers
never promote a backup, predecessor, orphan generation or frozen legacy file.
Deleting only `current.json` therefore cannot revive revoked trust.

A later commit writes and verifies a new immutable generation, then replaces
`current.json` without deleting its destination first. The directory rename or
pointer replacement is the commit point. Cancellation after that point cannot be
reported as rollback. An expected-token mismatch rejects publication. Readers
copy one selected generation while holding the same process lock.

## Bounds and retention

Private format/pointer records are limited to 16 KiB. Each complete encoded
generation, including its envelope, is limited to 64 MiB. Up to eight legacy
metadata files, each at most 64 MiB, can be backed up during initial activation.
Oversized changes fail without truncating or replacing legacy state. Private JSON
envelopes reject unknown, duplicated, missing or case-aliased keys and trailing
input. Integrity hashes detect corruption; domain signatures and admission checks
remain separate authority checks.

The current and preceding metadata generation and the complete initial backup are
retained. Only known unreferenced generation files are eligible for best-effort
metadata cleanup under the root lock. Failed first preparations may remain for
explicit offline inspection; they are not selected by recovery.

Updates stores immutable artifact copies in the sibling
`.updates-blobs/ID/filename`. Transfer and staged roles use distinct files. No
committed artifact is automatically deleted in W14, including after Clear. This
permits retained disk growth and keeps previously disclosed paths intact; Clear
removes current authority and prevents fresh handoff of the cleared stage. It
does not securely erase files or revoke an already disclosed path. Artifact
retention/cleanup and historical backup restoration require separate procedures.

## Owner admission

Profile Mesh publishes identity, hosting, devices, resources and hints together.
Stored structural validity preserves existing zero/backward timestamps and
historical unavailable hosts. Live host eligibility remains a separate check.
Safe schema-two hints are validated before normalization and persist with the
aggregate; import replaces or clears them. Existing fingerprint rules remain.
Full snapshot imports reject a concurrent commit rather than rebase a stale full
replacement. Incremental mutations may reload and revalidate their intent.

Updates keeps selected, downloaded, verified, staged and lifecycle authority
independent inside a compact graph. Invalid legacy candidate metadata can be
quarantined while independently valid staged/lifecycle state remains available;
it cannot regain candidate authority without a successful fresh Check. Native
corruption is never treated as legacy quarantine. Successful replacement downloads
invalidate verification of the same logical filename atomically. Failed downloads
preserve prior verification. Handoffs continue to verify artifact bytes freshly.

No external clock, provider, network call or app callback runs under a commit lock.
Profile Mesh discards stale time samples after contention and compares tokens
before admission. Updates orders combined locks as workflow, commit, then owner;
it does not wait for commit while holding the owner lock or hold two scope locks.
A separate stable `.apply.lock` spans legacy app execution. Guarded mutations and
recursive Apply fail promptly while it is held; status and lifecycle reporting
remain available. Process exit releases the gate but cannot roll back an external
action or provide exactly-once installer execution.

Design approval and local test results do not constitute consumer deployment,
native qualification on an untested platform, installation or a tagged release.

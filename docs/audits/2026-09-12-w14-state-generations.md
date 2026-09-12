# W14: coherent persisted state

> Historical record for the revision named below. See [current status](../STATUS.md).

W14 starts from reviewed W13 `d6b5cca5`. Profile Mesh and Updates now publish one
authoritative metadata generation per existing storage scope. Public imports,
method signatures, signed manifest payloads and lifecycle schema remain stable.
Private storage changes require the deployment and recovery procedure in
[STATE_PERSISTENCE.md](../STATE_PERSISTENCE.md).

## Division of responsibility

`internal/filelock` coordinates cooperating local processes through a stable OS
lock. `internal/generation` owns bounded metadata envelopes, expected-token
publication, initial activation, exact legacy backups and metadata retention.
The existing `internal/filepersist` package supplies narrow checked file/path and
replacement operations. Each domain owns its own codec, admission rules and
operation state; neither domain depends on the other's private representation.

Profile Mesh's operation runner owns one aggregate of profile, hosting, devices,
resources and hints. Incremental mutations reload after contention; full imports
reject a stale expected token. External clock calls occur outside commit locks,
and a time sample discarded after contention is acquired again before admission.
Stored historical state is validated separately from current host eligibility.
Safe schema-two relay/endpoint hints survive reopen, import and public round-trip.

Updates stores complete manifests once in a bounded reference graph. Selection,
download, verification, staging and lifecycle retain independent observations,
including distinct manifests and original timestamps. Stored observations do not
grant permission: current signature, source, policy and artifact checks still run
at their existing operation boundaries. Handoff freshly verifies staged bytes.

An operation reads one state view and publishes its intended result with an exact
expected token. Immutable artifact copies separate download and staged authority.
A distinct OS execution gate spans only legacy app callback execution; guarded
mutations and recursive Apply fail promptly while status/lifecycle reentry remains
available. The gate does not promise exactly-once external installation.

## Deliberate behavior and migration boundaries

- Stop all older writers before first native mutation. Old executables ignore the
  new authority and locks; mixed writers and rollback to an incompatible reader
  are unsupported. Legacy files remain frozen without dual writes.
- Invalid legacy candidate metadata can be quarantined while independently valid
  staging/lifecycle survives. Only a successful fresh check repairs that fault.
  Native corruption fails the whole snapshot and never falls back to old state.
  Historical valid-candidate cleanup on no-compatible/no-update selection errors
  remains a permitted mutation; the same failing result cannot clear quarantine.
- A successful download replacing a verified logical filename invalidates that
  verification atomically. Failed downloads retain the prior observation.
- Clear drops staged/lifecycle/verification references but retains committed blob
  files. Previously disclosed paths remain available; no fresh handoff is possible
  after Clear. Retained artifact disk growth is currently unbounded. Metadata
  cleanup never implies artifact deletion, secure erasure or path revocation.
- Oversized encoding rejects activation and preserves original legacy bytes.
  Complete pre-migration backup is required before a successful first commit;
  rejected oversized requests do not create a new backup. The 64 MiB generation
  limit includes its shared envelope. Bounded encoded output is not a guarantee
  of constant heap use inside Go's component JSON encoder.

## Evidence scope

W14 adds migration/partial-state, corruption, exact native grammar, cancellation,
stale-writer, concurrent-owner/process, immutable-blob, hint ownership and callback
reentry regressions. Shared tests cover real process termination at publication
boundaries and Windows pointer sharing violations. Checkpoint failure injection
around generation write/flush/close boundaries does not constitute direct fault
injection into every underlying OS write, Sync or Close call.

Existing compatibility probes and public/security regressions remain required on
the exact committed source and an independently recreated export. The campaign's
external evidence records their results and maps changed tests to retained cases.
This source note does not claim hosted Linux runtime/race qualification, power-loss
durability, network-filesystem support, consumer migration or installation.

W14 introduces persistence mechanisms and safety checks, so line counts may grow.
Active metadata deduplication is distinct from total retained disk usage, runtime
speed, binary size and test-line reduction. W15 owns measured I/O/computation work;
W16 owns mapped test/example/documentation consolidation.

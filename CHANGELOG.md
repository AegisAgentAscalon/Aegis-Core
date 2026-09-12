# Changelog

All notable changes to Aegis Core are recorded here. The repository remains experimental until a tagged stability policy says otherwise.

## Unreleased

### September repair and integration campaign (W01-W17)

- Repaired Identity Gate authority/expiry, Auth session ownership/cancellation,
  callback reentry, update artifact/source binding and cloud storage identity.
- Added opt-in reliable v2 delivery custody and inbox handling. Legacy exchange
  retains the documented SD-02/SD-03 limitations and needs consumer migration.
- Added W14 committed generations for Profile Mesh and Updates with bounded native
  codecs, cooperating-process locks, explicit migration and no silent legacy
  fallback after activation. Old writers must stop; executable downgrade against
  migrated roots is unsupported. See [migration](docs/CONSUMER_MIGRATION.md).
- Reduced selected repeated work while retaining fresh integrity observations:
  private reliable-receiver inventory reuse, fewer Cloud allocations, one artifact
  hash instead of two on the first Updates handoff, and fewer private manifest
  digests. Timing samples are mixed; there is no universal speedup claim.
- Consolidated 59 test setups and example helpers without removing tests. W16
  reduced tests by 132 lines and examples by 21; library source stayed unchanged.
- Corrected current architecture status and example import documentation. W17
  establishes an experimental release/deprecation policy, keeps legacy public APIs,
  documents consumer migration and prepares exact-checkout CI/export gates.
- Local validation and hosted qualification are distinct. W18 publication and
  exact-published-head hosted Windows/Linux/race results remain required; no tag,
  consumer installation or production qualification is implied by this changelog.

### Module organization

- Consolidated Auth, Device Link, Profile Mesh, Setup State and Updates under
  their public domain owners, removing duplicate internal contract trees while
  retaining private storage records and the existing public API paths.
- Divided large service implementations into responsibility files; retained
  state-owning structs, injected host ports and focused private Identity Gate
  and Secret Store implementations.
- Added the architecture and ownership map. The original structural pass preceded
  the correctness repairs recorded above; dated audit findings remain historical.

### Security and correctness

- Added an optional host-owned protected secret-store contract and strict Auth mode for OAuth tokens and pending PKCE sessions, including revisioned compare-and-swap consumption, all-record migration preflight/read-back, retry-safe rollback, and no plaintext fallback.
- Added side-effect-free Device Link bootstrap inspection, validated public identity bundles, serializable versioned registry backups with schema-1 compatibility, trust-complete fingerprints, durable proof receipts, proof/reachability separation, revocation invalidation, and strict Profile Mesh registration.
- Added a separate record-only update lifecycle with atomic bounded history, revision/idempotency checks, rehash-before-handoff, explicit non-execution capabilities, consumer-reported outcomes, and active-lifecycle restage protection while retaining legacy callbacks only as deprecated compatibility behavior.
- Added receive-only Profile Sync relay construction, deterministic mailbox IDs, directional capability diagnostics, pull-only exchange, schema-1 exchange-record compatibility, bounded safe exchange persistence, and cross-platform path redaction without changing the schema-1 envelope wire shape.
- Bound Identity Gate verification completions to a monotonic session epoch, bounded replay tracking by expiry and count, enforced cadence policy flags, and preserved the intentional fail-closed explicit-provider break from the earlier implicit allow-all mock behavior.
- Reconciled the 2026-07-11 internal audit with the public `github.com/AegisAgentAscalon/aegis-core` module without replacing newer Identity Gate work.
- Bound cached update selections and downloads to their configured source, cleared withdrawn candidates, and rejected persisted path redirection outside package-owned storage.
- Added separate public and app-owned authenticated update transports, exact destination restrictions, source-specific signing-key pins, safe source provenance, atomic lane switching, and source/channel/policy-scoped state so stable and development lanes can share an application repository strategy without sharing trust or cached state.
- Serialized mutable update configuration/workflow state while keeping consumer apply callbacks outside the service lock.
- Hardened update metadata validation, version comparison, cancellation, private storage, URL boundaries, and Windows reserved-name handling.
- Removed Device Link discovery callback reentrancy deadlocks and made remote-resource availability require fresh, matching, trusted presence.
- Bounded local relay duplicate tracking and tightened relay URL and single-document JSON handling.
- Normalized selected nil-context entry points and repaired private directory permissions on supported filesystems.
- Prevented `StageUpdate` from replacing an active lifecycle: exact pre-handoff restages are idempotent, while different-package or post-handoff restages return `ErrLifecycleRestageConflict` without changing staged bytes or lifecycle state.
- Added directional Profile Sync relay capability status and made `Exchange` run only available push/pull directions, including a working receive-only pull exchange.
- Moved strict local exchange persistence to schema 2 while preserving schema 1 reads, restored the original `SyncEnvelope` schema 1 wire shape by deferring signature evidence, and expanded cross-platform path redaction for relay diagnostics and exchange summaries.

### Documentation and validation

- Added a consumer-driven hardening report and a measured, compatibility-aware whole-library consolidation plan.
- Added Windows and Linux ordinary-test/vet CI while retaining Linux race-test gates.
- Added the live-repository audit reconciliation and a canonical Core roadmap.
- Updated project status language to distinguish an internal hardening review from an independent professional audit.
- Expanded pull-request CI with module verification, ordinary test, race-test, and vet gates.
- Added golden vectors for update manifest signature payloads, deterministic relay mailbox IDs, Profile Sync status/envelope JSON, and exchange-record JSON.
- Hardened the Go workflow with pinned actions, cancellation of superseded runs,
  explicit timeouts, and read-only module validation.

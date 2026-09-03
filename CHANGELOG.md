# Changelog

All notable changes to Aegis Core are recorded here. The repository remains experimental until a tagged stability policy says otherwise.

## Unreleased

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

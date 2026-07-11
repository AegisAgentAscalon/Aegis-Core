# Changelog

All notable changes to Aegis Core are recorded here. The repository remains experimental until a tagged stability policy says otherwise.

## Unreleased

### Security and correctness

- Reconciled the 2026-07-11 internal audit with the public `github.com/AegisAgentAscalon/aegis-core` module without replacing newer Identity Gate work.
- Bound cached update selections and downloads to their configured source, cleared withdrawn candidates, and rejected persisted path redirection outside package-owned storage.
- Added separate public and app-owned authenticated update transports, exact destination restrictions, source-specific signing-key pins, safe source provenance, atomic lane switching, and source/channel/policy-scoped state so stable and development lanes can share an application repository strategy without sharing trust or cached state.
- Serialized mutable update configuration/workflow state while keeping consumer apply callbacks outside the service lock.
- Hardened update metadata validation, version comparison, cancellation, private storage, URL boundaries, and Windows reserved-name handling.
- Removed Device Link discovery callback reentrancy deadlocks and made remote-resource availability require fresh, matching, trusted presence.
- Bounded local relay duplicate tracking and tightened relay URL and single-document JSON handling.
- Normalized selected nil-context entry points and repaired private directory permissions on supported filesystems.

### Documentation and validation

- Added the live-repository audit reconciliation and a canonical Core roadmap.
- Updated project status language to distinguish an internal hardening review from an independent professional audit.
- Expanded pull-request CI with module verification, ordinary test, race-test, and vet gates.

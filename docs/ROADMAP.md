# Aegis Core Roadmap and Ownership Boundary

## Purpose

This is the canonical Core-side roadmap. Consumer application implementation notes may reveal useful gaps, but they do not become Core requirements until they are translated into app-independent contracts with a clear owner and safety boundary.

## Current supported foundation

Aegis Core currently provides experimental, reusable public packages for:

- app-scoped OAuth setup and safe status;
- app-owned update discovery, verification, staging, and apply handoff;
- Device Link identity, trust registry, presence, resource metadata, and signed proof primitives;
- Profile Mesh and Profile Sync metadata, proposals, conflict records, local/cloud stores, and optional LAN/relay transport seams;
- relay/rendezvous contracts plus local/dev and self-hostable HTTP helpers;
- setup and infrastructure status composition;
- read-only security-posture and Identity Gate vocabulary.

These are infrastructure contracts and reference implementations. They do not authorize application content, become profile truth, run installers, start application runtimes, or replace caller-owned deployment security.

## Priority 0 — release and security gates

These items should be addressed before claiming stable production security behavior:

1. **Secure-update authorization:** independent artifact signatures, key lifecycle and revocation, expiring/delegated metadata, rollback protection, and release-pipeline verification.
2. **Outbound update policy:** redirect restrictions, destination/IP policy, optional host allowlists or pinning, and explicit private-network behavior.
3. **Protected key storage:** platform keystore adapters behind the existing narrow Auth and Device Link storage boundaries.
4. **Transactional persistence:** generation directories, atomic pointer swaps, journals, or a transactional store for multi-file Auth, Device Link, Profile Mesh, and Profile Sync workflows.
5. **Authenticated distributed metadata:** signer identity, epoch, freshness, rollback, and revocation validation for snapshots and manifests.
6. **Hardened relay deployment:** a reference server wrapper with TLS, read/write/idle timeouts, rate limits, replay controls, identity binding, monitoring, and abuse handling.
7. **Profile referential integrity:** stricter import/removal validation plus repair tooling for stale resource-host and hosting references.
8. **Context contract:** consistently normalize nil contexts or document and test a repository-wide non-nil requirement.
9. **Release process:** define stable versus experimental packages, breaking-change policy, version tags, release notes, fresh-clone validation, and supported Go versions.

## Priority 1 — app-independent public contract candidates

Consumer integrations have exposed recurring contract opportunities. These are **backlog candidates**, not promises and not evidence that current behavior is broken.

### Network, membership, and Device Link

- Generic app-network/group descriptors without product-specific policy.
- Separate state for discovery, membership request/approval, signer trust, Device Link trust, signed proof, payload authorization, and revocation/staleness.
- Generic join/challenge/decision/finalization DTOs while proof policy remains caller-owned.
- Machine-readable capability flags distinguishing key bootstrap, registry writes, signed proof, payload transport, and content sync.
- Browser-safe RFC 3339 DTO mirrors or conversion helpers.
- Pure registry/resource validation, fingerprint, redaction, and trust-count helpers.
- Non-authoritative host-role metadata and normalized discovery classification.
- Public identity export/read/validate helpers and side-effect-free bootstrap status.
- App-owned transport envelopes for identity exchange, handshake, signed-session proof, proof-to-route projection, route probes, and reciprocal proof.
- Evidence-oriented trust-registry preflight/result DTOs without embedding any consumer's membership policy.

### Profile Sync over relay/cloud

- Receive-only relay transport construction.
- A documented deterministic mailbox-ID helper or strategy.
- Optional preservation of caller-owned signature bytes in sync envelopes.
- Exchange-result persistence helpers for local metadata stores.
- Safe relay Profile Sync diagnostics DTOs.

### Update package and install handoff

- Safe package, catalog, manifest-route, and validation DTOs.
- Explicit separation of discovery, download, verification, reveal, handoff, execution, restart, and completion states.
- Capability flags for record-only handoff, package reveal, installer execution, extraction, restart, and rollback candidates.
- App-independent install-choreography gate and safe action-history DTOs.
- Browser-safe time conversion and source/path redaction helpers.

## Consumer-owned work and non-goals

Aegis Core should not absorb application-specific product tiers, release lanes, UI wording, organization models, passphrase policy, installer command lines, runtime behavior, or content semantics.

The consuming application remains responsible for:

- UI and approval flows;
- application network membership policy;
- profile/content merge policy and conflict review UX;
- knowledge-base and memory content sync;
- agent, companion, model, voice, file, and command traffic;
- installer execution, restart, rollback, and product release policy;
- OAuth provider configuration and credential lifecycle;
- relay/cloud endpoint selection and production operations.

## Explicitly deferred

Until separately designed and reviewed, Core does not imply authorization for automatic content merge, arbitrary payload routing, unattended update installation, public relay exposure, or consumer-specific organization behavior.

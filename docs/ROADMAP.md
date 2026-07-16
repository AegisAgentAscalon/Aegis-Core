# Aegis Core Roadmap and Ownership Boundary

## Purpose

This is the canonical Core-side roadmap. Consumer application implementation notes may reveal useful gaps, but they do not become Core requirements until they are translated into app-independent contracts with a clear owner and safety boundary.

## Current supported foundation

Aegis Core currently provides experimental, reusable public packages for:

- app-scoped OAuth setup, safe status, and an optional host-owned protected-store seam;
- app-owned update discovery, verification, staging, record-only handoff, and external-result lifecycle tracking;
- Device Link identity, versioned trust-registry backups, presence, resource metadata, bootstrap inspection, and durable signed-proof evidence;
- Profile Mesh and Profile Sync metadata, proposals, conflict records, local/cloud stores, and optional LAN/relay transport seams;
- relay/rendezvous contracts plus local/dev and self-hostable HTTP helpers;
- setup and infrastructure status composition;
- read-only security-posture vocabulary and fail-closed Identity Gate verification receipts, cadence, scope, provenance, and model packets.

These are infrastructure contracts and reference implementations. They do not authorize application content, become profile truth, run installers, start application runtimes, or replace caller-owned deployment security.

## Priority 0 — release and security gates

These items should be addressed before claiming stable production security behavior:

1. **Secure-update authorization beyond the current signed-manifest foundation:** artifact authorization independent of transport, key lifecycle and revocation, expiring/delegated metadata, stronger rollback protection, build provenance, and release-pipeline verification.
2. **Outbound update policy beyond current exact host/redirect restrictions:** DNS rebinding resistance, destination-IP and private-network policy, optional certificate/key pinning, and deployment-specific egress controls.
3. **Protected key storage:** production platform keystore adapters behind the new generic secret-store seam, followed by Device Link private-key and Profile Sync signer adoption. Strict Auth integration exists, but Core intentionally ships no DPAPI, Keychain, libsecret, or homegrown encrypted-file adapter.
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
- Trust-grant preflight and evidence DTOs above the implemented public identity export/validation and side-effect-free bootstrap status.
- App-owned transport envelopes for identity exchange, handshake, signed-session proof, proof-to-route projection, route probes, and reciprocal proof.
- Evidence-oriented trust-registry preflight/result DTOs without embedding any consumer's membership policy.

### Profile Sync over relay/cloud

Receive-only relay construction, deterministic mailbox IDs, directional capability diagnostics, pull-only exchange behavior, and local exchange-result persistence are now implemented. Strict exchange records use schema 2 and legacy schema 1 records remain readable.

- A future caller-owned signature-evidence contract must use explicit schema 2 envelope APIs; `SyncEnvelope` schema 1 must keep its existing wire shape.
- Longer exchange history remains a possible caller-owned storage extension; Core currently persists only the latest safe exchange summary.

### Update package and install handoff

The public/private source foundation, lane isolation, record-only package lifecycle, rehash-before-handoff, safe action history, and explicit non-execution capabilities are implemented. Remaining candidates focus on catalog/route discovery and richer application-owned installation reporting rather than repository topology.

- Safe catalog and manifest-route discovery DTOs beyond the current staged-package summary.
- Separate first-class discovery/download/reveal states beyond the current staged/validated/handoff/external-action/completion lifecycle.
- Metadata-only rollback-candidate inventory; Core must not claim or execute rollback readiness.
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

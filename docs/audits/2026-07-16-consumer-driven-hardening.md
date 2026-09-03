# 2026-07-16 Consumer-Driven Hardening

Status: internal engineering implementation and review

## Scope

This campaign translated integration lessons from a downstream consumer into
app-independent Aegis Core contracts. The consumer repository was read only and
served as field evidence; no product names, tiers, UI policy, passphrase rules,
installer commands, content semantics, or runtime behavior entered Core.

The starting revision was `a16c0f0cf532d85949a69bcdb6700f8d31cb0499`.

## Implemented

### Identity Gate

- Removed the implicit allow-all mock verifier.
- Required an explicit provider and introduced opaque, session-bound receipts.
- Bound receipts to subject, provider, session, attempt, assertion, security
  epoch, timestamps, expiry, and provider-proven freshness.
- Moved provider calls outside the service mutex and invalidated stale in-flight
  completions after lock, downgrade, identity transition, cancellation, idle
  expiry, or other assurance changes.
- Bounded replay tracking and enforced cadence, sliding-window, idle, and
  burn-fresh policy.
- Kept biometric samples, templates, credentials, and provider payloads outside
  all contracts, state, audit records, and model packets.

This intentionally changes the experimental zero-config behavior:
`identitygate.NewService(Config{})` no longer self-verifies. Tests and examples
must inject the mock explicitly; production consumers must supply a provider.

### Auth protected storage

- Added the opaque host-owned `pkg/secretstore` contract.
- Added strict Auth constructors that never fall back to plaintext for OAuth
  tokens or pending PKCE sessions.
- Added revisioned compare-and-swap and compare-delete behavior for cross-service
  session addition and one-time consumption.
- Added all-record migration preflight, staged writes, read-back verification,
  retry-safe destination rollback, and legacy-source deletion only after every
  protected record succeeds.

Core ships no production platform adapter. Legacy Auth construction remains for
compatibility and is not protected storage.

### Device Link and Profile Mesh

- Added side-effect-free bootstrap inspection and public identity bundles.
- Added versioned, JSON-round-trippable local registry backups with legacy
  schema-1 compatibility and complete trust-bearing fingerprints.
- Added durable proof receipts and evaluation independent of reachability.
- Made revocation/re-trust invalidate old proof and made proof persistence
  failures fail the handshake.
- Preserved existing status redaction while retaining public keys only inside
  explicit backup/exchange DTOs.
- Added canonical trust material and hint ordering plus strict Profile Mesh
  registration with coherent lifecycle timestamps.

Membership, passphrases, payload authorization, content sync, and application
route policy remain caller-owned.

### Updates

- Added a separate atomic record-only lifecycle envelope with bounded history.
- Added revisions, idempotency, rehash-before-handoff, consumer binding, and
  consumer-reported external action/completion states.
- Exposed explicit false capabilities for installer execution, extraction,
  restart, and rollback.
- Protected active lifecycles from destructive re-stage.
- Preserved the signed Manifest v1 payload unchanged.

Legacy callback apply APIs remain deprecated compatibility behavior. New code
should use the record-only constructors.

### Profile Sync and Relay

- Added receive-only relay construction and deterministic mailbox IDs.
- Added directional push/pull diagnostics and working pull-only exchange.
- Added explicit exchange-result persistence with schema-1 read compatibility
  and schema-2 strict records.
- Strengthened diagnostics and persistence redaction for Windows, POSIX, and
  relative path forms.
- Preserved the existing `SyncEnvelope` schema-1 wire shape; caller signature
  evidence is deferred to an explicitly versioned future envelope.

## Review process

Five initial implementation tracks were followed by four independent review
tracks. Review findings produced a second hotfix campaign covering stale
verification completion, bounded replay state, cross-service PKCE atomicity,
migration rollback, backup serialization and schema compatibility, proof
revocation/reachability, lifecycle re-stage, receive-only exchange behavior,
wire compatibility, and path redaction.

The exported API comparison against the starting revision reported only additive
symbol/field changes. The Identity Gate zero-config runtime behavior is an
intentional fail-closed change in an experimental package and is documented
above.

## Validation

Completed locally on Windows:

- `go test ./... -count=1`
- five repeated runs of every changed security-critical owner package
- `go vet ./...`
- `go mod verify`
- `git diff --check`
- exported module API comparison against the starting revision
- product-reference, biometric-material, and update-execution primitive scans

The local Go toolchain has `CGO_ENABLED=0` and no C compiler, so local race tests
were unavailable. CI runs ordinary tests and vet on Windows and Linux, with race
tests on Linux.

## Residual release gates

- Production platform protected-store adapters and Device Link key adoption.
- One crash-tested transactional persistence primitive for multi-record owners.
- Secure update key lifecycle, revocation/delegation, provenance, and stronger
  rollback metadata.
- Production relay TLS, identity binding, rate/replay controls, monitoring, and
  abuse handling.
- Authenticated distributed metadata epochs, freshness, rollback, and revocation.
- Stable/experimental package policy, semantic tags, and an independent security
  review before production-security claims.
- Removal of deprecated update callbacks in a separately versioned breaking
  release.

## Consolidation follow-up

The measured refactor plan is documented in
`docs/plans/LIBRARY_CONSOLIDATION_PLAN.md`. It deliberately starts after this
hardening behavior is frozen and keeps App Bridge because downstream evidence
shows it is an active public consumer contract.

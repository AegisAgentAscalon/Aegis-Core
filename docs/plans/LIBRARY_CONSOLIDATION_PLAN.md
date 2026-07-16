# Aegis Core Library Consolidation Plan

Status: planned after the current hardening campaign

## Purpose

Aegis Core has accumulated useful contracts through repeated consumer integration,
but several packages now maintain parallel public and internal DTOs, conversion
layers, status projections, and JSON persistence helpers. This plan reduces that
maintenance surface without weakening package ownership or silently breaking
current consumers.

Consolidation means fewer representations and fewer implementations of the same
rule. It does not mean merging unrelated domains into one manager, removing
safety evidence, or making application policy part of Core.

## Measured baseline

The pre-hardening baseline at commit `a16c0f0cf532d85949a69bcdb6700f8d31cb0499`
contains:

- 99 Go files;
- approximately 26,369 Go lines including tests and examples;
- four independent JSON persistence implementations across Auth, Device Link,
  Profile Mesh, Updates, and additional public Profile Sync stores;
- mirrored public/internal DTO and conversion blocks in Auth, Device Link,
  Profile Mesh, Setup State, and Updates;
- production files above 800 lines in Updates, Profile Sync, App Bridge, and
  Device Link;
- two large generic-consumer examples with substantial overlapping setup code.

The hardening campaign may increase this baseline before consolidation begins.
The post-hardening baseline must therefore be measured again and committed with
the first consolidation change.

## Non-negotiable boundaries

- Existing public import paths remain stable during compatibility-preserving
  phases.
- No application-specific product, membership, entitlement, installer,
  organization, content, or UI policy moves into Core.
- Auth, Updates, Device Link, Profile Mesh, Profile Sync, Relay, Identity Gate,
  Setup State, App Bridge, and Security Posture retain distinct owners.
- A reduction may not weaken signature coverage, trust checks, freshness,
  redaction, path safety, context cancellation, or crash recovery.
- Public API removals occur only in a separately versioned breaking release.
- Every storage format change includes migration, interruption, and rollback
  tests before old readers or writers are removed.

## Campaign 1: Freeze behavior

Before structural edits:

1. Record a post-hardening public API inventory for every `pkg/...` package.
2. Add external-package compile tests for provider and adapter interfaces.
3. Add golden JSON tests for persisted state and signed manifest payloads.
4. Add crash-point and concurrent-service tests for shared state roots.
5. Record ordinary, race, vet, module verification, and fresh-consumer results.

No consolidation change begins while the hardening branch has failing tests or
unresolved migration behavior.

## Campaign 2: One hardened persistence implementation

Create a small internal persistence package responsible only for:

- bounded single-document JSON reads;
- final-component symlink rejection and safe parent preparation;
- private directory and file creation modes where the platform supports them;
- write-temp, flush, close, and replace behavior without deleting a valid
  destination before replacement is committed;
- context checks before and after blocking filesystem work;
- normalized not-found, corrupt, unsafe-path, and unavailable errors;
- optional generation-envelope helpers for multi-record transactions.

Migrate one owner at a time. Auth and Device Link migrate first, followed by
Profile Mesh, Updates, and Profile Sync stores. Domain validation remains in the
owning package; the shared primitive must not learn token, key, trust, update, or
profile semantics.

Acceptance:

- one production implementation of bounded atomic JSON persistence;
- no remove-then-rename fallback that creates a destination data-loss window;
- fault-injection tests cover every replacement stage;
- legacy files remain readable until their owning migration is complete.

## Campaign 3: Eliminate mirrored implementation models

The public package path should own its stable contracts. Implementation can live
behind unexported symbols in that same package, which avoids maintaining a second
private copy of every DTO merely to preserve encapsulation.

Evaluate these packages independently:

1. `auth`
2. `setupstate`
3. `profilemesh`
4. `devicelink`
5. `updates`

For each package:

- move implementation behind the existing `pkg/<owner>` import path;
- preserve exported names and JSON behavior;
- replace public/internal conversion blocks with cloning only where ownership
  isolation actually requires it;
- keep unexported storage and validation details inaccessible to consumers;
- remove the old `internal/<owner>` package only after external compile tests,
  persisted-state fixtures, and all behavior tests pass.

This is performed package by package, never as a repository-wide flag day.

## Campaign 4: Shrink status composition

App Bridge and Setup State currently repeat portions of owner DTOs. Replace broad
copying with small capability interfaces and owner-produced safe summaries.

- Setup State remains the generic capability/readiness aggregator.
- App Bridge remains only if it provides meaningful composition beyond Setup
  State; otherwise deprecate it for the next breaking release.
- Optional services are discovered through narrow interfaces rather than by
  enlarging one interface whenever an owner gains a method.
- Browser-safe RFC 3339 mirrors should use shared conversion helpers, not a new
  hand-written DTO tree per consumer surface.

## Campaign 5: Decompose large owner files

Split by responsibility while keeping packages stable:

- Updates: manifest, source, selection, download, verification, staging,
  lifecycle, and persistence.
- Profile Sync: orchestration, envelope validation, relay transport, conflict
  review, diagnostics, and stores.
- Device Link: identity, registry, presence/resources, proof, and persistence.
- App Bridge: contracts, composition, and safe projection.

File splitting alone is not counted as consolidation. A split is successful only
when it removes duplicate helpers, clarifies an owner boundary, or enables a
smaller independently tested unit.

## Campaign 6: Examples and documentation

- Keep one canonical generic consumer walkthrough.
- Move reusable example setup into a small example-only helper or replace the
  second full example with focused package examples.
- Keep security invariants near their public package and link to them from the
  root documentation instead of repeating long boundary lists.
- Generate or verify package-map and public-API inventory sections where
  practical so documentation does not drift.

## Breaking-release candidates

The following changes require a separately approved major-version campaign:

- remove callback-based Update `ApplyStrategy` execution;
- remove deprecated Identity Gate verification-result APIs after receipt
  migration;
- require explicit Profile Mesh trust and device states where omission currently
  defaults to authority-bearing values;
- remove App Bridge if usage evidence shows Setup State and owner summaries fully
  replace it;
- remove legacy plaintext secret persistence after protected-store migration has
  a supported platform adapter story.

## Success measures

Measure production and test code separately after every campaign.

- At least 15 percent fewer non-test Go lines than the post-hardening baseline,
  without deleting security tests or public documentation.
- No production Go file above 1,000 lines; target below 700 lines per owner file.
- One bounded atomic JSON persistence implementation.
- No mirrored public/internal DTO tree for a migrated owner.
- No package imports another owner's private implementation.
- No increase in exported API surface unless the hardening contract requires it.
- Ordinary tests, targeted race tests, `go vet`, `go mod verify`, fresh-consumer
  compilation, and persisted-state migration tests all pass.

## Stop conditions

Stop and split the campaign if a change:

- alters signed-manifest bytes or trust fingerprints without an explicit schema
  version and migration;
- requires two owner packages to mutate the same private state;
- removes a public contract before an external consumer migration window;
- converts metadata delivery into authorization;
- requires application content, credentials, installer commands, or biometric
  material to enter a generic Core DTO;
- cannot demonstrate rollback to the prior persisted generation.

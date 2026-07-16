# Code Translation

This document explains Aegis Core for human readers who want to understand the code before using or changing it. It is not generated API documentation and it is not a security audit.

## Core Shape

Aegis Core is organized around one rule:

```text
consumer app -> pkg/* public contracts -> internal/* implementation where needed
```

The `pkg/` packages are what an external app should import. The `internal/` packages are private implementation details used by public wrappers. Examples must import only `pkg/` packages.

## Read This First

Start with these files:

- `README.md`: public project posture and non-goals.
- `pkg/appbridge/appbridge.go`: the broadest app-facing overview surface.
- `pkg/setupstate/setupstate.go`: read-only setup capability summary vocabulary.
- `pkg/updates/updates.go`: update discovery, verification, and staging wrapper.
- `pkg/updates/lifecycle.go`: record-only handoff and external-result lifecycle.
- `pkg/identitygate/identitygate.go`: current-operator verification receipts and scope policy.
- `pkg/secretstore/secretstore.go`: host-owned protected-storage contract.
- `pkg/profilesync/profilesync.go`: metadata-only profile sync orchestration.
- `pkg/relay/relay.go`: relay/rendezvous contracts and validation rules.
- `examples/generic-consumer-smoke/main.go`: a compact consumer example.

## Package Responsibilities

### `pkg/auth`

Owns the public Google OAuth setup facade. It can build a sign-in URL, complete a callback, clear stored auth state, and return safe status/profile summaries.

It must not expose raw access tokens, refresh tokens, PKCE verifiers, auth codes, client secrets, token-store paths, raw provider responses, or raw provider HTTP status details through `AuthStatus.LastError`.

When callback `PortHint` is zero, the implementation discovers a free loopback port and releases it after constructing the redirect URL. The consuming app owns the actual callback listener and should handle bind retries if that port is no longer available.

Stateful implementation lives in `internal/auth`.

`NewStrictService` and `WithStrictProtectedStorage` keep OAuth tokens and pending
PKCE sessions in a host-supplied protected store. Strict pending-session storage
requires revisioned compare-and-swap behavior so separate service instances
cannot reopen consumed sessions. Core provides only a development/test memory
implementation; it does not provide production platform encryption.

### `pkg/secretstore`

Defines opaque logical keys plus host-owned Get/Put/Delete and optional
revisioned compare-and-swap operations. Platform protection, ACL scope, roaming,
backup, and credential lifecycle remain host responsibilities.

It must not expose filesystem paths, choose a platform mechanism, or provide an
encrypted file whose key is stored beside its ciphertext.

### `pkg/updates`

Owns app-owned update evaluation and staging contracts. It can check a manifest,
select an artifact, download, verify, stage, and describe staged state. New
integrations should use `NewRecordOnlyService`, which can reveal freshly
rehashed staged bytes and record consumer-reported handoff/action/completion
states without invoking execution code.

It must not install, extract, restart, replace binaries, delete app-owned data,
execute rollback, or decide that a provider is final trust authority. The older
`ApplyStrategy` callback surface remains deprecated compatibility behavior and
is not part of the strict non-execution contract.

Stateful implementation lives in `internal/updates`.

Important safety notes:

- Remote manifest providers may use HTTP or GitHub raw manifests.
- Local file artifacts are restricted to the local file-manifest provider path.
- SHA-256 artifact verification is always enforced by service normalization.
- Ed25519 manifest verification exists when callers provide keys and require signatures.
- Manifest signatures are calculated over Aegis Core's current Go JSON payload with `Signature` removed. This is deterministic for this implementation but is not RFC 8785/JCS canonical JSON, so cross-language signing tools must match the same serialization or wait for a later canonicalization pass.
- Public and app-owned authenticated sources use separate host-supplied HTTP clients. Credentials stay in the app-owned transport and are never persisted or exposed through status DTOs.
- Explicit `SourceID` lanes isolate selected, downloaded, verified, and staged state by source, channel, and effective policy. `ConfigureLane` switches those values atomically.
- Authenticated sources require exact destination restrictions, a signed manifest, and a source-pinned verification key. See `docs/UPDATE_SOURCES.md`.

### `pkg/devicelink`

Owns device identity, trusted-device metadata, resource advertisement,
side-effect-free bootstrap inspection, public identity exchange bundles, and
signed handshake/proof contracts. Durable proof and transport reachability are
separate states; neither one grants application membership or payload authority.

It must not implement NAT traversal, automatic discovery, managed relay behavior, OAuth authority, profile truth, runtime routing, or cross-module control flow.

Stateful implementation lives in `internal/devicelink`.

### `pkg/profilemesh`

Owns profile-centered metadata: profile identity, trusted device records, profile-owned resources, hosting hints, and profile-sync proposal contracts.

It must not store private profile data, choose profile truth automatically, perform merges, or become a cloud authority.

Stateful implementation lives in `internal/profilemesh`.

### `pkg/profilesync`

Owns metadata/proposal exchange for Profile Sync. It can push and pull signed snapshot/proposal metadata through a caller-provided store and optional relay transport. It also includes a local JSON metadata store and a file-backed object provider for local/dev workflows.

Relay transports report push and pull capability independently. Receive-only
construction and pull-only exchange do not require a placeholder target.
`SyncEnvelope` schema 1 retains its original wire shape.

It must not sync private profile content, auto-merge conflicts, store provider credentials, run background workers, or treat relay/cloud storage as truth.

### `pkg/relay`

Owns optional relay/rendezvous contracts and validation. It includes:

- `LocalDevProvider`: in-process local/dev provider.
- `HTTPRelayHandler`: self-hostable HTTP handler.
- `HTTPRelayClient`: HTTP client implementation.

Relay is always transport. It is not device trust, profile truth, sync authority, or access-control policy.

The HTTP handler refuses to start without an `Authorizer` unless the caller explicitly sets `AllowUnauthenticated` for local/dev use. That opt-in should not be used for public relay endpoints. Access control is route-wide, including `/status`; callers that need public health checks should expose a separate health handler outside the relay API.

Endpoint-hint and rendezvous query parameters are validated by the HTTP handler before injected providers receive them, even though the built-in client and local provider also validate those query DTOs.

### `pkg/setupstate`

Owns read-only capability summaries. It aggregates safe status cards and issues for setup surfaces.

It must not mutate OAuth, update, relay, sync, or device state.

Stateful implementation lives in `internal/setupstate`.

### `pkg/appbridge`

Owns a generic app-facing setup facade that composes the public packages into overview/status DTOs.

It must not reach into `internal/` packages, execute update apply by itself, trigger sync/relay operations from status reads, or expose raw provider errors.

### `pkg/securityposture`

Owns read-only security posture vocabulary, redaction helpers, and trust-boundary classifications.

It must not scan files, detect malware, quarantine, remediate, block, trust providers, trigger updates, trigger sync, or become a security product.

### `pkg/identitygate`

Owns fail-closed current-operator verification receipts, bounded verification
cadence, scope decisions, prompt provenance, and safe model identity packets.
Consumers must explicitly inject a provider; the mock provider is only for
explicit tests and examples.

It must not capture or store biometric samples/templates, passkey or
hardware-key credentials, raw provider assertions, or arbitrary evidence
payloads. Recognition, account login, and device trust remain context rather
than current-operator verification.

## Examples

`examples/generic-consumer-smoke` is the short example. It composes AppBridge, SetupState, Updates, Relay, Profile Sync, and local object verification through public APIs.

`examples/generic-consumer-proof` is broader and exercises more edge cases. It is still a proof, not a production template.

## Common Footguns

- Do not import `internal/*` from a consuming app.
- Do not expose `ArtifactPath`, token files, provider raw errors, local filesystem paths, or secret-like strings in UI status.
- Do not assume `AuthStatus.LastError` contains raw provider diagnostics; it is intentionally mapped to safe fixed messages.
- Do not treat relay delivery as trust.
- Do not treat cloud/object metadata as profile truth.
- Do not auto-apply staged updates without an app-owned policy and rollback plan.
- Do not use deprecated update callbacks when the record-only lifecycle can express the integration.
- Do not treat Device Link proof as transport reachability or payload authorization.
- Do not construct Identity Gate without an explicit provider or move provider evidence into its receipts.
- Do not put update credentials in source URLs or manifests; supply them through the app-owned authenticated HTTP client.
- Do not reuse a signing key across development and stable lanes.
- Do not expose the self-hosted HTTP relay publicly without TLS, authentication, abuse controls, monitoring, and deployment hardening.
- Do not set `AllowUnauthenticated` outside isolated local/dev tests.
- Do not make `/status` unauthenticated by setting `AllowUnauthenticated`; create a separate health endpoint instead.
- Do not assume this repo has been audited.

## What Human Review Should Focus On

The highest-value review areas are:

- update manifest and artifact trust policy;
- file and path handling around staging/local stores;
- OAuth token storage and callback handling;
- relay access-control expectations;
- Profile Sync conflict classification;
- public DTO redaction and status wording;
- whether examples create false confidence.

# Aegis Core

Aegis Core is an experimental Go library for app setup infrastructure. It provides reusable contracts and local-first helpers for Google OAuth setup, app-owned update flows, Device Link metadata and signed proof, Profile Mesh metadata, Profile Sync metadata exchange, optional LAN/relay coordination, setup-state summaries, security posture vocabulary, and current-operator verification receipts.

This repository is intended to be readable, inspectable infrastructure code. It is not a managed service, not a production security product, and not a guarantee of safe deployment.

## Status

Aegis Core is public and experimental. It completed an internal engineering audit and hardening pass on 2026-07-11, followed by a consumer-driven contract and security pass on 2026-07-16. See [`docs/audits/2026-07-11-internal-hardening.md`](docs/audits/2026-07-11-internal-hardening.md) and [`docs/audits/2026-07-16-consumer-driven-hardening.md`](docs/audits/2026-07-16-consumer-driven-hardening.md).

That work is not an independent professional security audit, penetration test, or certification. Treat the repository as reference-quality infrastructure that still requires consumer-specific review before production use.

## What This Is

- A Go module for reusable setup infrastructure.
- A set of public packages under `pkg/` with app-facing DTOs and narrow service contracts.
- Private implementation packages under `internal/` where stateful implementation details live.
- Local/dev implementations for metadata stores, relay transport, update staging, and OAuth setup flows.
- Examples showing generic consumer usage through public packages only.

## What This Is Not

- Not a production-ready security framework.
- Not malware scanning.
- Not a managed relay, cloud sync, OAuth, or update service.
- Not a TUF, Sigstore, or full secure-updater replacement.
- Not a UI framework.
- Not an installer, app restarter, rollback executor, or binary replacement system.
- Not legal, compliance, or deployment advice.

## Module Path

Use the lowercase module path exactly as declared in `go.mod`; the GitHub
repository display name is not the import path.

```text
github.com/AegisAgentAscalon/aegis-core
```

After the repository is published:

```powershell
go get github.com/AegisAgentAscalon/aegis-core
```

## Package Map

| Package | Purpose |
| --- | --- |
| `pkg/auth` | Public Google OAuth setup facade, safe status DTOs, and optional strict host-protected token/session storage. |
| `pkg/secretstore` | Opaque host-owned protected-storage contract; Core provides no production platform adapter. |
| `pkg/updates` | App-owned update check/download/verify/stage plus record-only handoff and external-result lifecycle contracts. |
| `pkg/devicelink` | Device identity, trust registry, resources, side-effect-free bootstrap inspection, and durable signed-proof evidence. |
| `pkg/profilemesh` | Profile-owned resource and device metadata contracts. |
| `pkg/profilesync` | Metadata/proposal orchestration over caller-owned stores with directional LAN/relay transport seams. |
| `pkg/relay` | Optional relay/rendezvous contracts plus local/dev and self-hostable HTTP helpers. |
| `pkg/identitygate` | Fail-closed current-operator verification receipts, cadence, scope, provenance, and safe model identity packets. |
| `pkg/setupstate` | Read-only setup capability aggregation. |
| `pkg/appbridge` | Generic app-facing setup overview facade built over the public packages. |
| `pkg/securityposture` | Read-only DTO vocabulary, redaction helpers, and trust-boundary classification helpers. |

See [docs/CODE_TRANSLATION.md](docs/CODE_TRANSLATION.md) for a human-oriented walkthrough of how the code is shaped. Public/private update-source configuration is documented in [docs/UPDATE_SOURCES.md](docs/UPDATE_SOURCES.md).

The current Core-side priorities and consumer/Core ownership boundary are tracked in [docs/ROADMAP.md](docs/ROADMAP.md).

## Safety Model

Aegis Core tries to keep infrastructure honest by separating public contracts from private implementation details, keeping provider outputs non-authoritative, redacting obvious unsafe status text, and forcing app-owned decisions for operations such as update apply, conflict review, credential handling, and deployment policy.

Those boundaries reduce footguns, but they do not replace human review.

Consumer apps remain responsible for:

- choosing OAuth client identity and scopes;
- running the loopback OAuth callback listener and retrying if a discovered
  callback port is no longer available when binding;
- supplying a production protected-store adapter when strict Auth storage is used;
- protecting Device Link private keys until that package adopts the protected-store seam;
- choosing update providers and signing policy;
- keeping update manifest signing/verifying code aligned with Aegis Core's
  current Go JSON signature payload, which is not a cross-language canonical
  JSON format;
- hosting any relay endpoint safely with authentication, TLS, monitoring, and abuse controls;
- deciding whether profile-sync conflicts should be accepted;
- applying staged updates;
- securing deployment, TLS, logs, monitoring, and access control.

Update artifact SHA-256 verification is always enforced by the service.
Host applications may provide separate public and credential-scoped HTTP clients. Authenticated sources require a non-secret source identity, exact destination restrictions, a signed manifest, and a source-pinned verification key. Aegis isolates persisted update state by explicit source, channel, and effective policy; credentials remain entirely app-owned.

Profile Sync relay status distinguishes provider, push, and pull availability. `SyncManager.Exchange` uses only the available directions, so a receive-only transport performs a pull exchange without attempting a push. New local exchange records use schema 2, while existing schema 1 records remain readable. `SyncEnvelope` schema 1 retains its original wire shape; caller-owned signature evidence is deferred to a future explicitly versioned envelope API.

Identity Gate requires an explicitly configured verification provider. It has no implicit allow-all verifier. Providers keep biometric capture, passkeys, hardware-key interaction, templates, credentials, and raw assertion evidence outside Core; Core accepts only bounded, session-bound verification receipts. The included mock provider is for explicit tests and examples only.

The HTTP relay handler now requires either an explicit `Authorizer` or an explicit local/dev opt-in through `AllowUnauthenticated`; do not set that opt-in on a public endpoint. Handler access control is route-wide, including `/status`, so public unauthenticated health checks should be hosted separately by the caller.

## Validation

Run the core validation from the repository root:

```powershell
go test ./...
go vet ./...
go test -race ./internal/...
go test -race ./pkg/...
go mod verify
```

The examples also run as part of `go test ./...`.

## License

This repository is staged under the MIT License.

MIT is a conventional permissive software license with a clear warranty disclaimer and broad compatibility for public source code.

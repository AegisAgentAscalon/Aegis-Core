# Aegis Core

Aegis Core is an experimental Go library for app setup infrastructure. It provides reusable contracts and local-first helpers for Google OAuth setup, app-owned update flows, Device Link metadata, Profile Mesh metadata, Profile Sync metadata exchange, optional LAN/relay coordination, setup-state summaries, and read-only security posture vocabulary.

This repository is intended to be readable, inspectable infrastructure code. It is not a managed service, not a production security product, and not a guarantee of safe deployment.

## Status

Aegis Core is public, experimental, and unaudited.

The code has tests and defensive boundaries, but it has not been professionally reviewed, penetration tested, or certified. Treat it as reference-quality infrastructure that must be reviewed by the app developer before use in production.

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
| `pkg/auth` | Public Google OAuth setup facade and safe auth status DTOs. |
| `pkg/updates` | App-owned update check, download, verify, stage, describe, and apply-handoff contracts. |
| `pkg/devicelink` | Device identity, trust registry, resource advertisement, and signed link-test metadata. |
| `pkg/profilemesh` | Profile-owned resource and device metadata contracts. |
| `pkg/profilesync` | Profile Sync metadata/proposal orchestration over caller-owned stores and optional relay transport. |
| `pkg/relay` | Optional relay/rendezvous contracts plus local/dev and self-hostable HTTP helpers. |
| `pkg/setupstate` | Read-only setup capability aggregation. |
| `pkg/appbridge` | Generic app-facing setup overview facade built over the public packages. |
| `pkg/securityposture` | Read-only DTO vocabulary, redaction helpers, and trust-boundary classification helpers. |

See [docs/CODE_TRANSLATION.md](docs/CODE_TRANSLATION.md) for a human-oriented walkthrough of how the code is shaped.

## Safety Model

Aegis Core tries to keep infrastructure honest by separating public contracts from private implementation details, keeping provider outputs non-authoritative, redacting obvious unsafe status text, and forcing app-owned decisions for operations such as update apply, conflict review, credential handling, and deployment policy.

Those boundaries reduce footguns, but they do not replace human review.

Consumer apps remain responsible for:

- choosing OAuth client identity and scopes;
- storing secrets safely;
- choosing update providers and signing policy;
- hosting any relay endpoint safely with authentication, TLS, monitoring, and abuse controls;
- deciding whether profile-sync conflicts should be accepted;
- applying staged updates;
- securing deployment, TLS, logs, monitoring, and access control.

The HTTP relay handler now requires either an explicit `Authorizer` or an explicit local/dev opt-in through `AllowUnauthenticated`; do not set that opt-in on a public endpoint.

## Validation

Run the core validation from the repository root:

```powershell
go test ./...
go vet ./...
```

The examples also run as part of `go test ./...`.

## License

This repository is staged under the MIT License.

MIT is a conventional permissive software license with a clear warranty disclaimer and broad compatibility for public source code.

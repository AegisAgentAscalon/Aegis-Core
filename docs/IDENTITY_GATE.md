# Aegis Core Identity Gate

Status: Build 001 foundation with production-provider-ready receipt hardening

Identity Gate provides the first Aegis Core foundation for current-operator awareness, scope gating, prompt/context provenance, safe model identity packets, and provider-backed identity verification receipts.

## Core law

```text
Recognition is not verification.
Account login is not current-operator verification.
Trusted device is not current-operator verification.
Text/context is not authority.
Verification receipts are references, not captured evidence.
```

## Build 001 boundaries

Build 001 keeps session state local and in memory. It provides a receipt-provider contract and an explicitly injected mock provider, but it does not include a production identity provider, biometric capture, passkey or hardware-key capture, encrypted vault integration, downstream app integration, or embodied runtime integration.

Identity Gate never accepts or returns raw biometric samples, biometric templates, provider credentials, assertions, or opaque provider payloads. A production provider owns its verification ceremony and evidence. Aegis Core receives only the safe fields in `VerificationReceipt`.

## Public package

Consumers should import:

```go
import "github.com/AegisAgentAscalon/aegis-core/pkg/identitygate"
```

The public package wraps the private implementation under `internal/identitygate`.

## Provider configuration

`Config{}` fails with `ErrVerificationProviderRequired`. Tests and examples may explicitly inject `MockVerificationProvider{Allow: true}`. Production integrations should implement `VerificationReceiptProvider` and set `Config.ReceiptProvider`.

The provider receives a `VerificationRequest` containing cryptographically random one-use attempt and assertion identifiers, the current session identifier, the requested subject, a sanitized reason, the freshness requirement, and the request time. Provider code is called without the Identity Gate service mutex held.

The provider must return a `VerificationReceipt` that:

- echoes the attempt, assertion, session, and subject exactly;
- names the configured provider exactly;
- uses a cryptographically random, one-use receipt identifier;
- marks `Verified` only after provider-owned verification;
- marks `Fresh` only when the provider proves a fresh ceremony;
- timestamps the proof within the current attempt's clock-skew allowance;
- expires after verification and remains unexpired when evaluated.

Aegis Core consumes each identifier once, rejects replay or mismatched bindings, and caps local assurance by the provider expiry and local policy. Local configuration cannot extend verified assurance beyond one hour or fresh assurance beyond ten minutes.

The legacy `IdentityVerificationProvider`, `Config.VerificationProvider`, `RequestVerification`, and `RequestFreshVerification` surfaces remain as deprecated adapters. They still fail closed, and legacy fresh results must explicitly set `Fresh`.

## Minimal flow

1. Create an `identitygate.Service` with an explicit receipt provider.
2. Add a local profile.
3. Recognize a profile as a non-authoritative hint.
4. Deny protected scopes until current-operator verification succeeds.
5. Use provider-proven fresh verification for high-risk scopes.
6. Classify prompt/context sources before granting authority.
7. Send only safe model identity packets downstream.

## Roadmap count

The roadmap currently tracks 12 build slices: public facade, state machine, cadence, local profiles, recognition, provider receipts plus explicit mock verification, scope policy, prompt provenance, model packet generation, audit events, invariant tests, and public examples/docs.

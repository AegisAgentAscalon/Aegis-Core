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

This is an intentional experimental breaking change from the earlier implicit allow-all mock fallback. Identity Gate is fail-closed by default, and the implicit fallback must not be restored. Every consumer, including development code, must choose and inject its provider explicitly.

The provider receives a `VerificationRequest` containing cryptographically random one-use attempt and assertion identifiers, the current session identifier and verification epoch, the requested subject, a sanitized reason, the freshness requirement, and bounded request timestamps. Provider code is called without the Identity Gate service mutex held.

The provider must return a `VerificationReceipt` that:

- echoes the attempt, assertion, session, and subject exactly;
- names the configured provider exactly;
- uses a cryptographically random, one-use receipt identifier;
- marks `Verified` only after provider-owned verification;
- marks `Fresh` only when the provider proves a fresh ceremony;
- timestamps the proof within the current attempt's clock-skew allowance;
- expires after verification and remains unexpired when evaluated.

Aegis Core rechecks cancellation and the session verification epoch after provider completion, consumes each identifier once, rejects replay or mismatched bindings, and caps local assurance by the provider expiry and local policy. Downgrade, lock, identity transitions, expiry, idle reset, fresh-assurance burn, and successful assurance mutation advance the epoch so stale concurrent completions cannot restore or overwrite assurance.

Replay tracking is bounded by both expiry and a fixed entry count. Identity Gate prunes expired entries and fails closed with `ErrVerificationTrackingCapacity` instead of evicting an unexpired one. Local configuration cannot extend verified assurance beyond one hour or fresh assurance beyond ten minutes.

The legacy `IdentityVerificationProvider`, `Config.VerificationProvider`, `RequestVerification`, and `RequestFreshVerification` surfaces remain as deprecated adapters. They still fail closed, and legacy fresh results must explicitly set `Fresh`.

## Cadence enforcement

`PublicChatRequiresAuth` and `ProfileLightRequiresAuth` remove those scopes until account authentication is present. `IdleTimeout` downgrades verified assurance after the last gated activity. Sliding verified and fresh windows extend only on gated activity and never beyond provider expiry or their configured hard maxima. `BurnFreshAfterSensitiveUse` consumes fresh assurance immediately after one successful high-risk `RequireScope` authorization while preserving any still-valid ordinary verification; observational `EvaluateScope` and `CanAccessScope` calls do not consume it.

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

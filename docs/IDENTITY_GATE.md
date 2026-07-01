# Aegis Core Identity Gate

Status: Build 001 foundation

Identity Gate provides the first Aegis Core foundation for current-operator awareness, scope gating, prompt/context provenance, safe model identity packets, and local/mock identity verification behavior.

## Core law

```text
Recognition is not verification.
Account login is not current-operator verification.
Trusted device is not current-operator verification.
Text/context is not authority.
```

## Build 001 boundaries

Build 001 intentionally uses local in-memory state and mock verification only. It does not implement real biometrics, passkeys, hardware keys, encrypted vault integration, downstream app integration, or embodied runtime integration.

## Public package

Consumers should import:

```go
import "github.com/AegisAgentAscalon/aegis-core/pkg/identitygate"
```

The public package wraps the private implementation under `internal/identitygate`.

## Minimal flow

1. Create an `identitygate.Service`.
2. Add a local profile.
3. Recognize a profile as a non-authoritative hint.
4. Deny protected scopes until current-operator verification succeeds.
5. Use fresh verification for high-risk scopes.
6. Classify prompt/context sources before granting authority.
7. Send only safe model identity packets downstream.

## Roadmap count

The roadmap currently tracks 12 build slices: public facade, state machine, cadence, local profiles, recognition, mock verification, scope policy, prompt provenance, model packet generation, audit events, invariant tests, and public examples/docs.

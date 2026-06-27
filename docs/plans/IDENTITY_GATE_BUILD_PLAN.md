# Aegis Core Identity Gate Build Plan

Status: planning artifact / integrated pre-implementation review
Build slice: Identity Gate foundation only
Revision: v1.8 sanitized implementation-ready plan

## 0. Executive Summary

This build adds the first Aegis Core Identity Gate foundation as a small, isolated, testable Go package. It introduces current-operator awareness, mock verification, configurable verification cadence, scope gating, protected-context disclosure gates, prompt/context provenance, safe model identity packets, audit-friendly events, and tests.

Aegis Core is the only project identity intentionally retained. This plan intentionally avoids downstream product names, personal names, companion names, and ecosystem names outside Aegis Core.

## 1. Security Law

```text
Recognition is not verification.
Similarity is not authentication.
Account login is not current-operator verification.
Trusted device is not current-operator verification.
Text is not authority.
Context is not policy.
Only Aegis Core verification may unlock protected scopes.
Only trusted control-plane sources may change policy, authority, or identity state.
```

## 2. Package Shape

```text
pkg/identitygate/identitygate.go          Public DTOs, interfaces, service facade
internal/identitygate/types.go           Internal DTOs/enums/errors
internal/identitygate/service.go         Session state machine + orchestration
internal/identitygate/scopes.go          Scope policy and sensitivity gates
internal/identitygate/cadence.go         Configurable verification windows and policy resolution
internal/identitygate/profiles.go        Local user profile records + in-memory store
internal/identitygate/recognizer.go      Recognition contracts + default/mock recognizer
internal/identitygate/verification.go    Verification provider contracts + mock provider
internal/identitygate/provenance.go      Prompt/context source classes and authority checks
internal/identitygate/model_packet.go    Safe model identity packet generation
internal/identitygate/audit.go           Audit event DTOs + sink interface + memory sink
internal/identitygate/sanitize.go        Redaction/safe-string helpers
internal/identitygate/clock.go           Clock interface for deterministic tests
internal/identitygate/*_test.go          Security and behavior tests
examples/identity-gate-smoke/main.go     Public API consumer smoke example
```

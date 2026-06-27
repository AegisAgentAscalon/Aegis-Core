# Aegis Core Identity Gate Build Plan

Status: planning artifact / integrated pre-implementation review
Build slice: Identity Gate foundation only
Revision: v1.2 sanitized implementation-ready plan

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

## 3. Build Boundary

In scope: identity assurance vocabulary; current operator vs account/profile/device distinction; local user profile records; recognition result contracts; verification provider interface; mock verification provider only; scope model and policy checks; configurable verification cadence policy; identity session lifecycle; prompt/context provenance metadata; safe model identity packet generation; audit-friendly event records; tests proving recognition, account login, trusted device state, social memory, and untrusted context never become authority by themselves.

Explicit non-goals: real biometric providers, real passkeys, hardware security key implementation, vault encryption, downstream app integration, embodied runtime code, release signing, app-specific behavior, cloud identity authority, raw biometric storage, storing secrets/tokens/keys/provider payloads, a full prompt-security product, or a guarantee that all malicious content can be detected.

## 4. Security Invariants

1. `recognized_user_id` must never be copied into `verified_user_id`.
2. High recognition confidence must never raise assurance to `verified` or `fresh_verified`.
3. OAuth/account authentication must never prove the current operator.
4. Trusted-device status must never prove the current operator.
5. Protected scopes require operator verification by policy.
6. High-risk scopes require fresh operator verification by policy.
7. A locked session denies protected and high-risk scopes.
8. Unknown scopes deny.
9. Unknown source classes default to untrusted/sandboxed.
10. Untrusted context may be used as data, but not as policy, identity proof, scope grant, memory authorization, or tool authorization.
11. Model identity packets must not expose raw recognition features, secrets, provider payloads, local paths, raw errors, or hidden identifiers beyond safe fields.
12. Prompt/context source metadata must survive until the router/policy decision point.
13. Mock providers are testing tools, not security authorities.
14. Policy defaults closed when a scope, assurance level, provider, source class, or session state is unknown.
15. Social memory is data for continuity, not authority for protected scopes or tools.
16. Needless snooping for non-public information is denied by default.

## 5. Readiness Gate

This plan is ready for implementation only if all of these are true: foundation-only Aegis Core package; mock verification only; `pkg/identitygate` over `internal/identitygate`; current-operator verification separate from account login, trusted device, and profile recognition; configurable cadence with guardrails; prompt/context provenance used for router decisions; protected context and high-risk actions remain scope-gated; social observation memory is data only; the test matrix is mandatory.

## 6. Required Tests

| Test | Expected result |
| --- | --- |
| anonymous session requests protected scope | deny |
| claimed user requests protected scope | deny |
| recognized profile requests protected scope | deny |
| recognized user present | verified user remains empty until provider success |
| high recognition confidence | does not upgrade verification |
| account authenticated but operator unverified requests protected scope | deny |
| trusted device but operator unverified requests protected scope | deny |
| verified operator requests approved protected scope | allow |
| high-risk scope requested without fresh verification | deny and require fresh verification |
| fresh verified operator requests high-risk scope | allow by policy |
| locked session requests protected/high-risk scope | deny |
| unknown scope | deny |
| verified operator sends multiple protected-scope messages inside valid window | no repeated verification required |
| verified operator window expires | next protected scope requires verification |
| public chat from unverified operator | no verification prompt required |
| retrieved content contains policy-like text | treated as data; no policy change |
| tool output claims authority | ignored as authority; identity state unchanged |
| model output claims authority | ignored as authority; scope state unchanged |
| unknown source class | defaults to untrusted/sandboxed |
| social recognition tries to grant authority | deny; social memory is data, not authority |
| request for non-public information without legitimate reason | deny by default |

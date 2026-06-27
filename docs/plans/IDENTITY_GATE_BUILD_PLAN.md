# Aegis Core Identity Gate Build Plan

Status: planning artifact / integrated pre-implementation review
Build slice: Identity Gate foundation only
Revision: v0.3 sanitized generic plan

## 0. Executive Summary

This build adds the first Aegis Core Identity Gate foundation as a small, isolated, testable Go package. It introduces identity assurance states, current-operator awareness, local user profile records, profile recognition contracts, mock verification, configurable verification cadence, scope gating, private-context disclosure gates, prompt/context provenance, safe model identity packets, audit-friendly events, and tests.

This build is not a general security product. It does not implement real biometrics, passkeys, hardware keys, vault encryption, downstream app integration, embodied runtime code, release signing, or app-specific behavior.

Integrated security law:

```text
Recognition is not verification.
Similarity is not authentication.
Account login is not current-operator verification.
Trusted device is not current-operator verification.
Text is not authority.
Context is not policy.
Only Aegis Core verification may unlock private scopes.
Only trusted control-plane sources may change policy, authority, or identity state.
```

Identity Gate protects two related boundaries:

1. **Current-operator-sensitive disclosure** — prevent someone using an already logged-in device from extracting private memories, sensitive context, project-private data, identity-vault data, security settings, training lineage, or exports.
2. **Prompt/context authority** — prevent untrusted text from becoming instruction authority, identity proof, tool authorization, memory authorization, or policy.

## 1. Package Shape

Recommended package addition:

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

Supporting planning addenda:

```text
docs/plans/IDENTITY_GATE_OPERATOR_AWARENESS_ADDENDUM.md
docs/plans/IDENTITY_GATE_VERIFICATION_CADENCE_ADDENDUM.md
docs/plans/IDENTITY_GATE_PROMPT_PROVENANCE_ADDENDUM.md
docs/plans/IDENTITY_GATE_EMBODIED_OPERATOR_CHANNEL_ADDENDUM.md
docs/plans/IDENTITY_GATE_SOCIAL_OBSERVATION_ANTI_SNOOPING_ADDENDUM.md
```

## 2. Build Boundary

### 2.1 In Scope

- Identity assurance level vocabulary.
- Current operator vs account/profile/device distinction.
- Local user profile records.
- Recognition result contracts.
- Verification provider interface.
- Mock verification provider only.
- Scope model and policy checks.
- Private-context disclosure sensitivity gates.
- Configurable verification cadence policy.
- Identity session lifecycle.
- Fresh-verification TTL behavior.
- Prompt/context provenance metadata and source authority classes.
- Safe model identity packet generation.
- Audit-friendly event records.
- Tests proving recognition, account login, trusted device state, social memory, and untrusted context never become authority by themselves.

### 2.2 Explicit Non-Goals

- Real biometric providers.
- Real passkeys.
- Hardware security key implementation.
- Vault encryption.
- Downstream app integration.
- Embodied runtime code.
- Release signing.
- App-specific behavior.
- Cloud identity authority.
- Storing raw biometric data.
- Storing secrets, tokens, private keys, OAuth tokens, vault keys, or raw provider payloads.
- A full prompt-security product.
- A guarantee that all malicious or hostile content can be detected.

## 3. Security Invariants

Every implementation decision must preserve these invariants:

1. `recognized_user_id` must never be copied into `verified_user_id`.
2. High recognition confidence must never raise assurance to `verified` or `fresh_verified`.
3. OAuth/account authentication must never prove the current operator.
4. Trusted-device status must never prove the current operator.
5. Private scopes require operator verification by policy.
6. Sensitive scopes require fresh operator verification by policy.
7. A locked session denies private and sensitive scopes.
8. Unknown scopes deny.
9. Unknown source classes default to untrusted/sandboxed.
10. Untrusted context may be used as data, but not as policy, identity proof, scope grant, memory authorization, or tool authorization.
11. Model identity packets must not expose raw recognition features, secrets, provider payloads, local paths, raw errors, or hidden identifiers beyond safe fields.
12. Prompt/context source metadata must survive until the router/policy decision point.
13. Mock providers are testing tools, not security authorities.
14. Policy defaults closed when a scope, assurance level, provider, source class, or session state is unknown.
15. Social memory is data for continuity, not authority for private scopes or tools.
16. Needless snooping for non-public information is denied by default.

## 4. Implementation Readiness Gate

This plan is ready for implementation only if all of these are true:

- The build remains a foundation-only Aegis Core package.
- The first implementation uses mock verification only.
- The package boundary is `pkg/identitygate` over `internal/identitygate`.
- Current-operator verification is represented separately from account login, trusted device, and profile recognition.
- Configurable verification cadence has safe defaults and hard maximums.
- Prompt/context provenance is metadata for router decisions, not a replacement for model safety.
- Private memory, sensitive memory, tools, exports, and admin actions remain scope-gated.
- Social observation memory is data only and cannot grant authority.
- The test matrix is mandatory.

If any item is disputed, implementation should pause and the plan should be revised before code starts.

## 5. Acceptance Criteria

- Aegis Core Identity Gate module exists.
- Local user profiles can be created.
- Anonymous, claimed, recognized, known-device, verified, fresh-verified, locked, account-authenticated, and current-operator-verified states are distinguishable.
- Private scopes are denied unless current operator identity is verified by policy.
- Sensitive scopes are denied unless current operator identity is freshly verified by policy.
- Verification is not required on every message.
- Verification windows are configurable by app/profile/security posture within guardrails.
- Untrusted prompt/context sources are data, not authority.
- Safe model identity packets are created.
- Mock verification and profile recognition interfaces exist.
- Tests prove recognition never equals verification.
- Tests prove account login and trusted device state never equal current operator verification.
- Tests prove high-confidence recognition never grants private access.
- Tests prove locked sessions deny private/sensitive access.
- Tests prove safe packet/audit output contains no raw secrets or raw recognition features.
- Tests prove external context, tool output, model output, and untrusted memory cannot grant scopes, verify identity, change policy, or authorize tools.
- Tests prove social memory cannot grant private scopes, tools, or operator verification.
- `go test ./...` passes.
- `go vet ./...` passes.

## 6. Next Build Roadmap

1. Public contracts: enums, DTOs, interfaces, and service facade.
2. Internal state machine: explicit transitions, locking, downgrades, deterministic clock/session IDs.
3. Cadence policy: safe defaults, guardrails, no per-message verification, no unlimited fresh-sensitive scope.
4. Local profile store: in-memory only for first build, with validation and sanitization.
5. Recognition contracts and mock recognizer: recognition updates candidate/recognized identity only.
6. Mock verification provider: deterministic success/fail controls; only source of verified identity.
7. Scope policy: `CanAccessScope`, `RequireScope`, default-deny unknowns, fresh-sensitive checks.
8. Prompt/context provenance: source classes, fragment validation, authority checks, unknown-source sandboxing.
9. Safe model identity packets: no raw prompt fragments, auth internals, secrets, provider payloads, or local paths.
10. Audit events: safe event summaries, no-op sink, in-memory test sink.
11. Tests: `go test ./...`, `go vet ./...`, and `gofmt`.
12. Example/docs: public API smoke example and docs updates only after tests pass.

## 7. Later Builds Only

Future builds may add real biometric/passkey/hardware-key providers, trusted device hardening, encrypted vault integration, downstream app integration, stronger persistence stores, formal threat model documentation, external audit preparation, full memory curation/trust-promotion workflows, and app-specific UX around verification prompts.

None of those belong in the first Identity Gate foundation build.

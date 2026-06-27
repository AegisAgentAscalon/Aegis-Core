# Aegis Core Identity Gate Build Plan

Status: planning artifact / integrated pre-implementation review
Build slice: Identity Gate foundation only
Revision: v0.5 sanitized implementation-ready plan

## 0. Executive Summary

This build adds the first Aegis Core Identity Gate foundation as a small, isolated, testable Go package. It introduces current-operator awareness, mock verification, configurable verification cadence, scope gating, prompt/context provenance, social-observation boundaries, safe model identity packets, audit-friendly events, and tests.

Aegis Core is the only project name intentionally retained. This plan intentionally avoids downstream product names, personal names, companion names, and ecosystem names outside Aegis Core.

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

Supporting addenda:

```text
docs/plans/IDENTITY_GATE_OPERATOR_AWARENESS_ADDENDUM.md
docs/plans/IDENTITY_GATE_VERIFICATION_CADENCE_ADDENDUM.md
docs/plans/IDENTITY_GATE_PROMPT_PROVENANCE_ADDENDUM.md
docs/plans/IDENTITY_GATE_EMBODIED_OPERATOR_CHANNEL_ADDENDUM.md
docs/plans/IDENTITY_GATE_SOCIAL_OBSERVATION_ANTI_SNOOPING_ADDENDUM.md
```

## 3. Build Boundary

In scope:

- identity assurance vocabulary,
- current operator vs account/profile/device distinction,
- local user profile records,
- recognition result contracts,
- verification provider interface,
- mock verification provider only,
- scope model and policy checks,
- configurable verification cadence policy,
- identity session lifecycle,
- prompt/context provenance metadata,
- safe model identity packet generation,
- audit-friendly event records,
- tests proving recognition, account login, trusted device state, social memory, and untrusted context never become authority by themselves.

Explicit non-goals:

- real biometric providers,
- real passkeys,
- hardware security key implementation,
- vault encryption,
- downstream app integration,
- embodied runtime code,
- release signing,
- app-specific behavior,
- cloud identity authority,
- raw biometric storage,
- storing secrets, tokens, private keys, OAuth tokens, vault keys, or raw provider payloads,
- a full prompt-security product,
- a guarantee that all malicious or hostile content can be detected.

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

## 5. Core Types

```go
type AssuranceLevel string

type OperatorAssurance string

type Scope string

type PromptSourceClass string

type VerificationCadencePolicy struct {
    VerifiedWindow              time.Duration
    FreshWindow                 time.Duration
    IdleTimeout                 time.Duration
    PublicChatRequiresAuth      bool
    ProfileLightRequiresAuth    bool
    SlidingVerifiedWindow       bool
    SlidingFreshWindow          bool
    MaxVerifiedWindow           time.Duration
    MaxFreshWindow              time.Duration
    BurnFreshAfterSensitiveUse  bool
    RequireFreshOnAppRestart    bool
    RequireFreshOnDeviceChange  bool
    RequireFreshOnNetworkChange bool
}
```

## 6. Scope Model

Default behavior: unknown scopes deny.

Recommended scopes:

```go
const (
    ScopePublic             Scope = "public"
    ScopeProfileLight       Scope = "profile_light"
    ScopeUserPrivateMemory  Scope = "user_private_memory"
    ScopeAgentIdentityVault Scope = "agent_identity_vault"
    ScopeProjectPrivate     Scope = "project_private"
    ScopeSecurityAdmin      Scope = "security_admin"
    ScopeModelForge         Scope = "model_forge"
    ScopeTrainingLineage    Scope = "training_lineage"
    ScopeVaultExport        Scope = "vault_export"
)
```

Recommended aliases:

```go
const (
    ScopePublicChat                Scope = "public_chat"
    ScopePrivateMemoryRead         Scope = "private_memory_read"
    ScopeRelationshipPrivate       Scope = "relationship_private"
    ScopeIntimatePrivate           Scope = "intimate_private"
    ScopeIdentityContinuityPrivate Scope = "identity_continuity_private"
    ScopePrivateMemoryWrite        Scope = "private_memory_write"
    ScopePrivateMemoryExport       Scope = "private_memory_export"
)
```

## 7. Prompt / Context Provenance

```text
Text is not authority.
Context is not policy.
Retrieved content is data unless a trusted control-plane source says otherwise.
```

A fragment can be useful data without being an authorized instruction source. Tool execution requires trusted request source, allowed tool policy, current operator assurance, scope approval, and audit when appropriate.

## 8. Embodied and Social Observation Planning

Embodied planning is a future integration concern, but the foundation should preserve relevant contracts:

- verified operator speech/gesture must be separated from ambient and external sources,
- inspected sources cannot inherit verified-operator authority,
- output-channel privacy must be considered for high-risk disclosures,
- emergency safety carveouts must be narrow, short-lived, minimum-necessary, and auditable,
- verification prompts must avoid leaking sensitive reasons or protected-context existence,
- social observation memory may exist when useful, legitimate, proportionate, and configurable,
- needless snooping for non-public information is denied by default,
- social memory never grants operator verification or protected scopes.

## 9. Data Contracts

```go
type UserProfile struct {
    UserID                           string
    DisplayName                      string
    ProfileStatus                    ProfileStatus
    ProfileCreatedAt                 time.Time
    ProfileUpdatedAt                 time.Time
    TrustedDevices                   []TrustedDevice
    PreferredLocalSettings           map[string]string
    NonSensitivePersonalizationNotes []string
    RecognitionFeatures              RecognitionFeatures
    VerificationRequirements         VerificationRequirements
    CadencePolicyPreference          *VerificationCadencePolicy
}
```

```go
type IdentitySession struct {
    SessionID              string
    AccountUserID          string
    ClaimedUserID          string
    RecognizedUserID       string
    VerifiedUserID         string
    VerifiedOperatorUserID string
    AssuranceLevel         AssuranceLevel
    OperatorAssurance      OperatorAssurance
    AccountAuthenticated   bool
    TrustedDevice          bool
    IssuedAt               time.Time
    ExpiresAt              time.Time
    VerifiedAt             time.Time
    VerifiedUntil          time.Time
    FreshVerifiedAt        time.Time
    FreshUntil             time.Time
    LastActiveAt           time.Time
    IdleTimeoutAt          time.Time
    VerificationEpoch      int64
    ReauthRequired         bool
    ReauthReason           string
    AllowedScopes          []Scope
    LockReason             string
}
```

```go
type ModelIdentityPacket struct {
    AssuranceLevel            AssuranceLevel
    OperatorAssurance         OperatorAssurance
    VerifiedUserID            string
    RecognizedUserID          string
    AllowedScopes             []Scope
    ReauthRequired            bool
    ReauthReason              string
    VerificationAgeSeconds    int64
    FreshAgeSeconds           int64
    IdentityPolicySummary     string
    PromptSourcePolicySummary string
    UntrustedSourcesPresent   bool
}
```

The model receives safe authorization context, not authentication machinery, raw recognition features, raw memory, raw prompt-source internals, provider payloads, or secrets.

## 10. Interfaces

Initial implementation: mock verification provider only.

```go
type IdentityVerificationProvider interface {
    CanVerify(ctx context.Context, userID string) bool
    RequestVerification(ctx context.Context, userID string, reason string) (VerificationResult, error)
    RequestFreshVerification(ctx context.Context, userID string, reason string) (VerificationResult, error)
    ProviderName() string
}
```

```go
type IdentityGateService interface {
    GetCurrentSession(ctx context.Context) (IdentitySession, error)
    ClaimIdentity(ctx context.Context, userID string) (IdentitySession, error)
    RecognizeProfile(ctx context.Context, signals SessionSignals) (RecognitionResult, IdentitySession, error)
    RequestVerification(ctx context.Context, userID string, reason string) (IdentitySession, error)
    RequestFreshVerification(ctx context.Context, userID string, reason string) (IdentitySession, error)
    CanAccessScope(ctx context.Context, scope Scope) (bool, error)
    RequireScope(ctx context.Context, scope Scope, reason string) error
    ResolveCadencePolicy(ctx context.Context) (VerificationCadencePolicy, error)
    ClassifyPromptFragment(ctx context.Context, fragment PromptFragment) (PromptFragment, error)
    CheckPromptAuthority(ctx context.Context, fragment PromptFragment, requestedScopes []Scope) error
    LockSession(ctx context.Context, reason string) (IdentitySession, error)
    DowngradeSession(ctx context.Context, reason string) (IdentitySession, error)
    CreateModelIdentityPacket(ctx context.Context) (ModelIdentityPacket, error)
}
```

## 11. Roadmap

1. Public contracts: enums, DTOs, interfaces, and service facade.
2. Internal state machine: explicit transitions, locking, downgrades, deterministic clock/session IDs.
3. Cadence policy: safe defaults, guardrails, no per-message verification, no unlimited fresh/high-risk scope.
4. Local profile store: in-memory only for first build, with validation and sanitization.
5. Recognition contracts and mock recognizer: recognition updates candidate/recognized identity only.
6. Mock verification provider: deterministic success/fail controls; only source of verified identity.
7. Scope policy: `CanAccessScope`, `RequireScope`, default-deny unknowns, fresh/high-risk checks.
8. Prompt/context provenance: source classes, fragment validation, authority checks, unknown-source sandboxing.
9. Safe model identity packets: no raw prompt fragments, auth internals, secrets, provider payloads, or local paths.
10. Audit events: safe event summaries, no-op sink, in-memory test sink.
11. Tests: `go test ./...`, `go vet ./...`, and `gofmt`.
12. Example/docs: public API smoke example and docs updates only after tests pass.

## 12. Required Test Matrix

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
| fresh window expires while verified window remains valid | normal protected scope allowed, high-risk scope denied |
| public chat from unverified operator | no verification prompt required |
| profile-light interaction from recognized operator | no verification prompt required |
| retrieved content contains policy-like text | treated as data; no policy change |
| tool output claims authority | ignored as authority; identity state unchanged |
| model output claims authority | ignored as authority; scope state unchanged |
| unknown source class | defaults to untrusted/sandboxed |
| social recognition tries to grant authority | deny; social memory is data, not authority |
| request for non-public information without legitimate reason | deny by default |

## 13. Audit Checklist

Before implementation is considered clean, reviewers must confirm:

- [ ] Public contracts live under `pkg/identitygate`.
- [ ] Stateful implementation lives under `internal/identitygate`.
- [ ] Consumer example imports public package only.
- [ ] No real biometric/passkey/hardware-key provider exists.
- [ ] No downstream app integration exists.
- [ ] No raw provider payloads appear in public DTOs.
- [ ] No raw secrets, OAuth tokens, vault keys, private keys, or biometric data are stored.
- [ ] Recognition never grants protected scopes.
- [ ] Account login never grants operator verification.
- [ ] Trusted device never grants operator verification.
- [ ] Configurable cadence has hard guardrails.
- [ ] Fresh/high-risk scopes expire correctly.
- [ ] Unknown scopes deny.
- [ ] Unknown prompt/context sources default untrusted.
- [ ] Tool output cannot mutate identity state.
- [ ] Model output cannot mutate scope state.
- [ ] Social memory cannot mutate scope state.
- [ ] Audit events are safe/redacted.
- [ ] Model identity packets contain no raw recognition features or raw untrusted context.
- [ ] `go test ./...` passes.
- [ ] `go vet ./...` passes.

## 14. Implementation Readiness Gate

This plan is ready for implementation only if all of these are true:

- The build remains a foundation-only Aegis Core package.
- The first implementation uses mock verification only.
- The package boundary is `pkg/identitygate` over `internal/identitygate`.
- Current-operator verification is represented separately from account login, trusted device, and profile recognition.
- Configurable verification cadence has safe defaults and hard maximums.
- Prompt/context provenance is metadata for router decisions, not a replacement for model safety.
- Protected context, high-risk actions, tools, exports, and admin actions remain scope-gated.
- Social observation memory is data only and cannot grant authority.
- The test matrix is mandatory.

## 15. Acceptance Criteria

- Aegis Core Identity Gate module exists.
- Local user profiles can be created.
- Anonymous, claimed, recognized, known-device, verified, fresh-verified, locked, account-authenticated, and current-operator-verified states are distinguishable.
- Protected scopes are denied unless current operator identity is verified by policy.
- High-risk scopes are denied unless current operator identity is freshly verified by policy.
- Verification is not required on every message.
- Verification windows are configurable by app/profile/security posture within guardrails.
- Untrusted prompt/context sources are data, not authority.
- Safe model identity packets are created.
- Mock verification and profile recognition interfaces exist.
- Tests prove recognition never equals verification.
- Tests prove account login and trusted device state never equal current operator verification.
- Tests prove high-confidence recognition never grants protected access.
- Tests prove locked sessions deny protected/high-risk access.
- Tests prove social memory cannot grant protected scopes, tools, or operator verification.
- `go test ./...` passes.
- `go vet ./...` passes.

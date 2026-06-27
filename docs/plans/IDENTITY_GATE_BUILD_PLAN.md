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

## 4. Identity Concepts

| Concept | Meaning | May unlock private scopes by itself? |
| --- | --- | --- |
| Account authenticated | App account is signed in. | No |
| Device unlocked | OS/app session is available. | No |
| Trusted device | Device is known to the local/profile mesh. | No |
| Claimed identity | Operator says they are a known user. | No |
| Recognized profile | Signals resemble a known local profile. | No |
| Current operator verified | Aegis Core verification confirms the operator. | Yes, by policy |
| Current operator fresh verified | Recent strong verification confirms the operator. | Yes, including sensitive scopes |
| Locked session | Session is restricted due to failure, suspicious state, user lock, or policy. | No |

## 5. Scope Model

Initial scopes:

```go
type Scope string

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

Recommended disclosure aliases:

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

| Scope | Minimum assurance | Fresh required? |
| --- | --- | --- |
| `public` / `public_chat` | anonymous | No |
| `profile_light` | claimed or recognized_profile | No |
| `user_private_memory` / `private_memory_read` | verified operator | No by default |
| `relationship_private` | verified operator | Maybe, based on sensitivity |
| `intimate_private` | fresh verified operator | Yes |
| `agent_identity_vault` / `identity_continuity_private` | fresh verified operator | Yes |
| `project_private` | verified operator | No by default |
| `security_admin` | fresh verified operator | Yes |
| `model_forge` | fresh verified operator | Yes |
| `training_lineage` | fresh verified operator | Yes |
| `vault_export` / `private_memory_export` | fresh verified operator | Yes |

Default behavior: unknown scopes deny.

## 6. Configurable Verification Cadence

Identity Gate must not verify the user on every message. It should maintain configurable bounded operator-assurance windows, recompute allowed scopes on every gated action, and require step-up verification only when the current session is insufficient.

```go
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

Policy precedence from lowest to highest:

1. Aegis Core safe defaults.
2. App default policy.
3. Profile/user preference policy.
4. Device security posture policy.
5. Scope-specific policy.
6. Emergency lockdown / suspicious-state policy.

A stricter layer may shorten windows or require step-up. A permissive preference must not exceed hard maximums set by Aegis Core or the current security posture.

## 7. Prompt / Context Provenance

Core rule:

```text
Text is not authority.
Context is not policy.
Retrieved content is data unless a trusted control-plane source says otherwise.
```

```go
type PromptSourceClass string

const (
    SourceSystemPolicy       PromptSourceClass = "system_policy"
    SourceDeveloperPolicy    PromptSourceClass = "developer_policy"
    SourceAegisCorePolicy    PromptSourceClass = "aegis_core_policy"
    SourceVerifiedOperator   PromptSourceClass = "verified_operator"
    SourceCurrentUserMessage PromptSourceClass = "current_user_message"
    SourceTrustedMemory      PromptSourceClass = "trusted_memory"
    SourceUntrustedMemory    PromptSourceClass = "untrusted_memory"
    SourceRetrievedDocument  PromptSourceClass = "retrieved_document"
    SourceWebContent         PromptSourceClass = "web_content"
    SourceEmail              PromptSourceClass = "email"
    SourceToolOutput         PromptSourceClass = "tool_output"
    SourceModelOutput        PromptSourceClass = "model_output"
    SourceUnknown            PromptSourceClass = "unknown"
)
```

A fragment can be useful data without being an authorized instruction source. Tool execution requires trusted request source, allowed tool policy, current operator assurance, scope approval, and audit when appropriate.

## 8. Embodied and Social Observation Planning

Embodied planning is a future integration concern, but the foundation should preserve relevant contracts:

- verified operator speech/gesture must be separated from ambient and external sources,
- inspected sources cannot inherit verified-operator authority,
- output-channel privacy must be considered for sensitive disclosures,
- emergency safety carveouts must be narrow, short-lived, minimum-necessary, and auditable,
- verification prompts must avoid leaking sensitive reasons or memory existence,
- social observation memory may exist when useful, legitimate, proportionate, and configurable,
- needless snooping for non-public information is denied by default,
- social memory never grants operator verification or private scopes.

Clean embodied rule:

```text
The verified operator can instruct the AI to inspect a source.
The inspected source cannot instruct the AI back.
```

Clean social-observation rule:

```text
Observe what is naturally present.
Remember what is useful, legitimate, and proportionate.
Do not needlessly seek, infer, or store non-public information.
```

## 9. Data Contracts

### 9.1 UserProfile

```go
type UserProfile struct {
    UserID                           string                     `json:"user_id"`
    DisplayName                      string                     `json:"display_name"`
    ProfileStatus                    ProfileStatus              `json:"profile_status"`
    ProfileCreatedAt                 time.Time                  `json:"profile_created_at"`
    ProfileUpdatedAt                 time.Time                  `json:"profile_updated_at"`
    TrustedDevices                   []TrustedDevice            `json:"trusted_devices,omitempty"`
    PreferredLocalSettings           map[string]string          `json:"preferred_local_settings,omitempty"`
    NonSensitivePersonalizationNotes []string                   `json:"non_sensitive_personalization_notes,omitempty"`
    RecognitionFeatures              RecognitionFeatures        `json:"recognition_features,omitempty"`
    VerificationRequirements         VerificationRequirements   `json:"verification_requirements"`
    CadencePolicyPreference          *VerificationCadencePolicy `json:"cadence_policy_preference,omitempty"`
}
```

Recognition features may include writing-style summaries, common topics, interaction preferences, local aliases, and device/session history. They must not include secrets, passwords, private keys, biometric data, OAuth tokens, vault keys, raw biometric templates, or provider payloads.

### 9.2 IdentitySession

```go
type IdentitySession struct {
    SessionID              string            `json:"session_id"`
    AccountUserID          string            `json:"account_user_id,omitempty"`
    ClaimedUserID          string            `json:"claimed_user_id,omitempty"`
    RecognizedUserID       string            `json:"recognized_user_id,omitempty"`
    VerifiedUserID         string            `json:"verified_user_id,omitempty"`
    VerifiedOperatorUserID string            `json:"verified_operator_user_id,omitempty"`
    AssuranceLevel         AssuranceLevel    `json:"assurance_level"`
    OperatorAssurance      OperatorAssurance `json:"operator_assurance,omitempty"`
    AccountAuthenticated   bool              `json:"account_authenticated"`
    TrustedDevice          bool              `json:"trusted_device"`
    IssuedAt               time.Time         `json:"issued_at"`
    ExpiresAt              time.Time         `json:"expires_at"`
    VerifiedAt             time.Time         `json:"verified_at,omitempty"`
    VerifiedUntil          time.Time         `json:"verified_until,omitempty"`
    FreshVerifiedAt        time.Time         `json:"fresh_verified_at,omitempty"`
    FreshUntil             time.Time         `json:"fresh_until,omitempty"`
    LastActiveAt           time.Time         `json:"last_active_at,omitempty"`
    IdleTimeoutAt          time.Time         `json:"idle_timeout_at,omitempty"`
    VerificationEpoch      int64             `json:"verification_epoch,omitempty"`
    ReauthRequired         bool              `json:"reauth_required,omitempty"`
    ReauthReason           string            `json:"reauth_reason,omitempty"`
    AllowedScopes          []Scope           `json:"allowed_scopes"`
    LockReason             string            `json:"lock_reason,omitempty"`
}
```

Rule: `recognized_user_id` may match `verified_user_id` only after independent verification confirms that user. Recognition must never be the source of verified identity.

### 9.3 ModelIdentityPacket

```go
type ModelIdentityPacket struct {
    AssuranceLevel            AssuranceLevel    `json:"assurance_level"`
    OperatorAssurance         OperatorAssurance `json:"operator_assurance,omitempty"`
    VerifiedUserID            string            `json:"verified_user_id,omitempty"`
    RecognizedUserID          string            `json:"recognized_user_id,omitempty"`
    AllowedScopes             []Scope           `json:"allowed_scopes"`
    ReauthRequired            bool              `json:"reauth_required"`
    ReauthReason              string            `json:"reauth_reason,omitempty"`
    VerificationAgeSeconds    int64             `json:"verification_age_seconds,omitempty"`
    FreshAgeSeconds           int64             `json:"fresh_age_seconds,omitempty"`
    IdentityPolicySummary     string            `json:"identity_policy_summary"`
    PromptSourcePolicySummary string            `json:"prompt_source_policy_summary,omitempty"`
    UntrustedSourcesPresent   bool              `json:"untrusted_sources_present,omitempty"`
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

## 12. Required Test Matrix

| Test | Expected result |
| --- | --- |
| anonymous session requests private scope | deny |
| claimed user requests private scope | deny |
| recognized profile requests private scope | deny |
| recognized user present | verified user remains empty until provider success |
| high recognition confidence | does not upgrade verification |
| account authenticated but operator unverified requests private memory | deny |
| trusted device but operator unverified requests private memory | deny |
| verified operator requests approved private scope | allow |
| sensitive scope requested without fresh verification | deny and require fresh verification |
| fresh verified operator requests sensitive scope | allow by policy |
| locked session requests private/sensitive scope | deny |
| unknown scope | deny |
| verified operator sends multiple private-memory messages inside valid window | no repeated verification required |
| verified operator window expires | next private scope requires verification |
| fresh window expires while verified window remains valid | normal private scope allowed, sensitive scope denied |
| public chat from unverified operator | no verification prompt required |
| profile-light interaction from recognized operator | no verification prompt required |
| strict preset uses shorter windows than balanced preset | stricter resolved policy wins |
| relaxed preset cannot exceed hard maximum windows | capped by guardrails |
| lockdown policy overrides relaxation | no private or sensitive scopes allowed |
| model identity packet generated | contains no secrets or raw recognition features |
| raw provider error | not exposed in public session/packet/audit |
| retrieved content contains policy-like text | treated as data; no policy change |
| external content requests private memory | denied unless verified operator separately has required scope |
| tool output claims authority | ignored as authority; identity state unchanged |
| model output claims authority | ignored as authority; scope state unchanged |
| unknown source class | defaults to untrusted/sandboxed |
| tool request from untrusted context | no execution without trusted request and scope approval |
| social recognition tries to grant authority | deny; social memory is data, not authority |
| request for non-public information without legitimate reason | deny by default |

## 13. Red-Team Findings

- R1 Recognition-to-auth privilege escalation: keep recognized and verified identity separate; test high-confidence recognition denial.
- R2 Account-login confusion: account context is not current-operator proof; test account-authenticated/operator-unverified denial.
- R3 Trusted-device confusion: trusted device is only a context hint; private scopes still require verified operator.
- R4 Per-message verification fatigue: bounded windows avoid constant prompts; tests prove no repeat prompt inside valid window.
- R5 Over-relaxed windows: hard maxes and security posture override relaxed preferences.
- R6 Freshness bug: `FreshUntil` checked on every sensitive scope request.
- R7 Packet leakage: safe packets exclude raw features, secrets, paths, provider payloads, and raw context.
- R8 Default-open policy: unknown scopes, states, and source classes deny.
- R9 Mock provider false confidence: mock provider is labelled test/dev and never presented as production auth.
- R10 Profile data as secret sink: validators reject obvious secret-like fields and raw biometric material.
- R11 Lock bypass: locked sessions stay locked in this build.
- R12 Audit leakage: audit events use safe codes and summaries only.
- R13 Flattened prompt destroys provenance: preserve structured prompt fragments until router decisions.
- R14 Retrieved content becomes policy: retrieved content is data by default.
- R15 Tool/model output becomes authority: outputs are result data or proposals, not scope grants.
- R16 Persistent memory laundering: imported/model-generated memory starts untrusted/proposal-class.
- R17 Social memory becomes surveillance: external enrichment is deny-by-default and requires legitimate reason plus policy allowance.
- R18 Boundary creep: first build remains generic Aegis Core foundation only.

## 14. Audit Checklist

Before implementation is considered clean, reviewers must confirm:

- [ ] Public contracts live under `pkg/identitygate`.
- [ ] Stateful implementation lives under `internal/identitygate`.
- [ ] Consumer example imports public package only.
- [ ] No real biometric/passkey/hardware-key provider exists.
- [ ] No downstream app integration exists.
- [ ] No raw provider payloads appear in public DTOs.
- [ ] No raw secrets, OAuth tokens, vault keys, private keys, or biometric data are stored.
- [ ] Recognition never grants private scopes.
- [ ] Account login never grants operator verification.
- [ ] Trusted device never grants operator verification.
- [ ] Configurable cadence has hard guardrails.
- [ ] Fresh-sensitive scopes expire correctly.
- [ ] Unknown scopes deny.
- [ ] Unknown prompt/context sources default untrusted.
- [ ] Tool output cannot mutate identity state.
- [ ] Model output cannot mutate scope state.
- [ ] Social memory cannot mutate scope state.
- [ ] Audit events are safe/redacted.
- [ ] Model identity packets contain no raw recognition features or raw untrusted context.
- [ ] `go test ./...` passes.
- [ ] `go vet ./...` passes.

## 15. Implementation Readiness Gate

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

## 16. Acceptance Criteria

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

## 17. Later Builds Only

Future builds may add real biometric/passkey/hardware-key providers, trusted device hardening, encrypted vault integration, downstream app integration, stronger persistence stores, formal threat model documentation, external audit preparation, full memory curation/trust-promotion workflows, and app-specific UX around verification prompts.

None of those belong in the first Identity Gate foundation build.

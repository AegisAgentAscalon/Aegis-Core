// Package securityposture defines read-only security posture contracts for
// Aegis Core public status surfaces.
//
// The package is intentionally data-only. It does not scan, remediate, route,
// mutate provider state, trigger update/sync/relay operations, or decide trust.
package securityposture

// Severity is the stable issue severity vocabulary for security posture status.
type Severity string

const (
	SeverityInfo     Severity = "info"
	SeverityLow      Severity = "low"
	SeverityMedium   Severity = "medium"
	SeverityHigh     Severity = "high"
	SeverityCritical Severity = "critical"
)

// Posture is the stable status vocabulary for a security posture summary.
type Posture string

const (
	PostureUnknown        Posture = "unknown"
	PostureReady          Posture = "ready"
	PostureDegraded       Posture = "degraded"
	PostureReviewRequired Posture = "review_required"
	PostureBlocked        Posture = "blocked"
	PostureOutOfScope     Posture = "out_of_scope"
)

// TrustBoundary classifies the authority boundary for an issue or capability.
type TrustBoundary string

const (
	BoundaryUnknown              TrustBoundary = "unknown"
	BoundaryAegisCoreOwned       TrustBoundary = "aegis_core_owned"
	BoundaryCallerOwned          TrustBoundary = "caller_owned"
	BoundaryConsumerOwned        TrustBoundary = "consumer_owned"
	BoundaryProviderTransport    TrustBoundary = "provider_transport"
	BoundaryRelayTransport       TrustBoundary = "relay_transport"
	BoundaryLocalReference       TrustBoundary = "local_reference"
	BoundaryExternalService      TrustBoundary = "external_service"
	BoundaryDeferredFutureWork   TrustBoundary = "deferred_future_work"
	BoundaryExplicitlyOutOfScope TrustBoundary = "explicitly_out_of_scope"
)

// CapabilityRisk classifies why a public capability needs caveats or review.
type CapabilityRisk string

const (
	RiskNone                 CapabilityRisk = "none"
	RiskDeferred             CapabilityRisk = "deferred"
	RiskCaveated             CapabilityRisk = "caveated"
	RiskUnsafeIfTrusted      CapabilityRisk = "unsafe_if_trusted"
	RiskRequiresCallerPolicy CapabilityRisk = "requires_caller_policy"
	RiskOutOfScope           CapabilityRisk = "out_of_scope"
)

// RedactionStatus classifies whether a public status surface has been reduced
// to safe summary text.
type RedactionStatus string

const (
	RedactionNotApplicable RedactionStatus = "not_applicable"
	RedactionApplied       RedactionStatus = "applied"
	RedactionRequired      RedactionStatus = "required"
	RedactionUnsafe        RedactionStatus = "unsafe"
)

// Issue is a read-only public status DTO for security posture summaries.
//
// Summary must be safe display text. Callers and future Aegis helpers must not
// place raw provider bodies, raw payloads, local paths, credential material, or
// stack traces in this field.
type Issue struct {
	Code           string          `json:"code"`
	Severity       Severity        `json:"severity"`
	Posture        Posture         `json:"posture"`
	Boundary       TrustBoundary   `json:"boundary,omitempty"`
	Risk           CapabilityRisk  `json:"risk,omitempty"`
	Redaction      RedactionStatus `json:"redaction,omitempty"`
	Summary        string          `json:"summary,omitempty"`
	ReviewRequired bool            `json:"review_required,omitempty"`
}

// Summary is a read-only public DTO for one capability posture.
type Summary struct {
	Capability string          `json:"capability"`
	Posture    Posture         `json:"posture"`
	Boundary   TrustBoundary   `json:"boundary,omitempty"`
	Risk       CapabilityRisk  `json:"risk,omitempty"`
	Redaction  RedactionStatus `json:"redaction,omitempty"`
	Issues     []Issue         `json:"issues,omitempty"`
}

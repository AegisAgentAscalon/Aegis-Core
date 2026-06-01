package securityposture

// Surface identifies an Aegis Core-owned public surface that can be described
// for posture/status purposes without executing that surface or treating it as
// an authority.
type Surface string

const (
	SurfaceUnknown             Surface = "unknown"
	SurfaceUpdateProvider      Surface = "update_provider"
	SurfaceUpdateManifest      Surface = "update_manifest"
	SurfaceUpdateArtifact      Surface = "update_artifact"
	SurfaceProfileSyncProvider Surface = "profile_sync_provider"
	SurfaceProfileSyncConflict Surface = "profile_sync_conflict"
	SurfaceRelayTransport      Surface = "relay_transport"
	SurfaceLocalReference      Surface = "local_reference"
	SurfaceDevOnly             Surface = "dev_only"
	SurfaceAppBridgeStatus     Surface = "appbridge_status"
	SurfaceSetupStateStatus    Surface = "setupstate_status"
)

// SurfaceClassification is a read-only public description of a surface's trust
// boundary. It is status/classification data only. It must not be used as an
// execution, validation, merge, retry, or control instruction.
type SurfaceClassification struct {
	Surface        Surface        `json:"surface"`
	Boundary       TrustBoundary  `json:"boundary"`
	Risk           CapabilityRisk `json:"risk,omitempty"`
	Posture        Posture        `json:"posture"`
	ReviewRequired bool           `json:"review_required,omitempty"`
	Summary        string         `json:"summary,omitempty"`
}

// ClassifySurface returns the default public posture classification for an
// Aegis Core surface. The function is deterministic and read-only. It does not
// inspect providers, validate manifests, evaluate trust, execute operations, or
// remediate anything.
func ClassifySurface(surface Surface) SurfaceClassification {
	switch surface {
	case SurfaceUpdateProvider, SurfaceProfileSyncProvider:
		return safeSurfaceClassification(SurfaceClassification{
			Surface:        surface,
			Boundary:       BoundaryProviderTransport,
			Risk:           RiskUnsafeIfTrusted,
			Posture:        PostureReviewRequired,
			ReviewRequired: true,
			Summary:        "provider output is storage or transport data and is not authority",
		})
	case SurfaceRelayTransport:
		return safeSurfaceClassification(SurfaceClassification{
			Surface:        surface,
			Boundary:       BoundaryRelayTransport,
			Risk:           RiskUnsafeIfTrusted,
			Posture:        PostureReviewRequired,
			ReviewRequired: true,
			Summary:        "relay transport is untrusted transport and is not authority",
		})
	case SurfaceUpdateManifest:
		return safeSurfaceClassification(SurfaceClassification{
			Surface:        surface,
			Boundary:       BoundaryProviderTransport,
			Risk:           RiskRequiresCallerPolicy,
			Posture:        PostureReviewRequired,
			ReviewRequired: true,
			Summary:        "update manifest candidates require validation and caller policy",
		})
	case SurfaceUpdateArtifact:
		return safeSurfaceClassification(SurfaceClassification{
			Surface:        surface,
			Boundary:       BoundaryProviderTransport,
			Risk:           RiskRequiresCallerPolicy,
			Posture:        PostureReviewRequired,
			ReviewRequired: true,
			Summary:        "update artifact candidates require validation and caller policy",
		})
	case SurfaceProfileSyncConflict:
		return safeSurfaceClassification(SurfaceClassification{
			Surface:        surface,
			Boundary:       BoundaryCallerOwned,
			Risk:           RiskRequiresCallerPolicy,
			Posture:        PostureReviewRequired,
			ReviewRequired: true,
			Summary:        "profile sync conflicts remain review required and do not auto merge",
		})
	case SurfaceLocalReference:
		return safeSurfaceClassification(SurfaceClassification{
			Surface:  surface,
			Boundary: BoundaryLocalReference,
			Risk:     RiskCaveated,
			Posture:  PostureDegraded,
			Summary:  "local reference surfaces are visible and non fatal",
		})
	case SurfaceDevOnly:
		return safeSurfaceClassification(SurfaceClassification{
			Surface:  surface,
			Boundary: BoundaryDeferredFutureWork,
			Risk:     RiskCaveated,
			Posture:  PostureDegraded,
			Summary:  "development only surfaces are visible and non fatal",
		})
	case SurfaceAppBridgeStatus, SurfaceSetupStateStatus:
		return safeSurfaceClassification(SurfaceClassification{
			Surface:  surface,
			Boundary: BoundaryAegisCoreOwned,
			Risk:     RiskNone,
			Posture:  PostureReady,
			Summary:  "status surfaces are read only composition surfaces",
		})
	default:
		return safeSurfaceClassification(SurfaceClassification{
			Surface:        SurfaceUnknown,
			Boundary:       BoundaryUnknown,
			Risk:           RiskCaveated,
			Posture:        PostureUnknown,
			ReviewRequired: true,
			Summary:        "surface classification is unknown and requires review",
		})
	}
}

// IssueForSurface returns a read-only issue DTO derived from the default
// surface classification. The issue is safe public status data and does not
// imply any operation or control behavior.
func IssueForSurface(surface Surface, code string, severity Severity) Issue {
	classification := ClassifySurface(surface)
	if code == "" {
		code = "surface_classification"
	}
	if severity == "" {
		severity = SeverityInfo
	}
	return Issue{
		Code:           code,
		Severity:       severity,
		Posture:        classification.Posture,
		Boundary:       classification.Boundary,
		Risk:           classification.Risk,
		Redaction:      RedactionNotApplicable,
		Summary:        classification.Summary,
		ReviewRequired: classification.ReviewRequired,
	}
}

// SummaryForSurface returns a read-only summary DTO derived from the default
// surface classification. It exists for status/reporting surfaces only.
func SummaryForSurface(surface Surface, capability string) Summary {
	classification := ClassifySurface(surface)
	if capability == "" {
		capability = string(surface)
	}
	return Summary{
		Capability: capability,
		Posture:    classification.Posture,
		Boundary:   classification.Boundary,
		Risk:       classification.Risk,
		Redaction:  RedactionNotApplicable,
		Issues:     []Issue{IssueForSurface(surface, "surface_classification", SeverityInfo)},
	}
}

func safeSurfaceClassification(classification SurfaceClassification) SurfaceClassification {
	classification.Summary = RedactPublicSurfaceText(classification.Summary)
	return classification
}

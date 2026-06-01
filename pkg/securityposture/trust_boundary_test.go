package securityposture

import (
	"reflect"
	"strings"
	"testing"
)

func TestClassifySurfaceProviderAndRelayAreNotAuthority(t *testing.T) {
	cases := map[Surface]TrustBoundary{
		SurfaceUpdateProvider:      BoundaryProviderTransport,
		SurfaceProfileSyncProvider: BoundaryProviderTransport,
		SurfaceRelayTransport:      BoundaryRelayTransport,
	}
	for surface, boundary := range cases {
		got := ClassifySurface(surface)
		if got.Boundary != boundary {
			t.Fatalf("%s boundary = %s, want %s", surface, got.Boundary, boundary)
		}
		if got.Boundary == BoundaryAegisCoreOwned {
			t.Fatalf("%s must not be classified as Aegis Core authority", surface)
		}
		if !got.ReviewRequired || got.Risk != RiskUnsafeIfTrusted || got.Posture != PostureReviewRequired {
			t.Fatalf("%s must require review if trusted, got %+v", surface, got)
		}
		if strings.Contains(strings.ToLower(got.Summary), "authority") && !strings.Contains(strings.ToLower(got.Summary), "not authority") {
			t.Fatalf("%s summary must not imply authority: %q", surface, got.Summary)
		}
	}
}

func TestClassifySurfaceUpdateCandidatesRequireValidationAndPolicy(t *testing.T) {
	for _, surface := range []Surface{SurfaceUpdateManifest, SurfaceUpdateArtifact} {
		got := ClassifySurface(surface)
		if got.Posture != PostureReviewRequired || got.Risk != RiskRequiresCallerPolicy || !got.ReviewRequired {
			t.Fatalf("%s must require validation and caller policy, got %+v", surface, got)
		}
		if !strings.Contains(got.Summary, "validation") || !strings.Contains(got.Summary, "policy") {
			t.Fatalf("%s summary must mention validation and policy, got %q", surface, got.Summary)
		}
	}
}

func TestClassifySurfaceProfileSyncConflictRequiresReview(t *testing.T) {
	got := ClassifySurface(SurfaceProfileSyncConflict)
	if got.Posture != PostureReviewRequired || got.Risk != RiskRequiresCallerPolicy || !got.ReviewRequired {
		t.Fatalf("profile sync conflict must remain review required, got %+v", got)
	}
	if !strings.Contains(got.Summary, "review required") || strings.Contains(strings.ToLower(got.Summary), "auto merge") == false {
		t.Fatalf("profile sync conflict summary should preserve non auto merge posture, got %q", got.Summary)
	}
}

func TestClassifySurfaceReferenceAndDevOnlyAreVisibleNonFatal(t *testing.T) {
	for _, surface := range []Surface{SurfaceLocalReference, SurfaceDevOnly} {
		got := ClassifySurface(surface)
		if got.Posture != PostureDegraded || got.ReviewRequired {
			t.Fatalf("%s should be visible degraded and non review-gated by default, got %+v", surface, got)
		}
		if !strings.Contains(got.Summary, "non fatal") {
			t.Fatalf("%s summary should state non fatal posture, got %q", surface, got.Summary)
		}
	}
}

func TestClassifySurfaceStatusSurfacesAreReadOnly(t *testing.T) {
	for _, surface := range []Surface{SurfaceAppBridgeStatus, SurfaceSetupStateStatus} {
		got := ClassifySurface(surface)
		if got.Boundary != BoundaryAegisCoreOwned || got.Risk != RiskNone || got.Posture != PostureReady {
			t.Fatalf("%s should be ready Aegis-owned read-only status, got %+v", surface, got)
		}
		if !strings.Contains(got.Summary, "read only") {
			t.Fatalf("%s summary should say read only, got %q", surface, got.Summary)
		}
	}
}

func TestSurfaceClassificationSummariesArePublicSafe(t *testing.T) {
	for _, surface := range []Surface{
		SurfaceUpdateProvider,
		SurfaceUpdateManifest,
		SurfaceUpdateArtifact,
		SurfaceProfileSyncProvider,
		SurfaceProfileSyncConflict,
		SurfaceRelayTransport,
		SurfaceLocalReference,
		SurfaceDevOnly,
		SurfaceAppBridgeStatus,
		SurfaceSetupStateStatus,
		Surface("unexpected"),
	} {
		got := ClassifySurface(surface)
		if ContainsUnsafePublicSurfaceMarkers(got.Summary) {
			t.Fatalf("%s produced unsafe summary %q", surface, got.Summary)
		}
	}
}

func TestSurfaceIssueAndSummaryAreReadOnlyDTOs(t *testing.T) {
	if reflect.TypeOf(SurfaceClassification{}).NumMethod() != 0 {
		t.Fatal("SurfaceClassification must remain a DTO without command methods")
	}
	issue := IssueForSurface(SurfaceRelayTransport, "relay_transport_not_authority", SeverityMedium)
	if issue.Boundary != BoundaryRelayTransport || issue.Risk != RiskUnsafeIfTrusted || !issue.ReviewRequired {
		t.Fatalf("relay issue did not preserve classification: %+v", issue)
	}
	summary := SummaryForSurface(SurfaceUpdateManifest, "updates")
	if summary.Capability != "updates" || summary.Posture != PostureReviewRequired || len(summary.Issues) != 1 {
		t.Fatalf("surface summary did not preserve classification: %+v", summary)
	}
}

func TestSurfaceClassificationDoesNotServiceControlActions(t *testing.T) {
	forbidden := []string{"Scan", "Quarantine", "Remediate", "Execute", "Apply", "Merge", "Retry", "Daemon", "Schedule"}
	for _, name := range []string{
		"Surface",
		"SurfaceClassification",
		"ClassifySurface",
		"IssueForSurface",
		"SummaryForSurface",
	} {
		for _, term := range forbidden {
			if strings.Contains(name, term) {
				t.Fatalf("classification symbol %s must not service control action term %s", name, term)
			}
		}
	}
}

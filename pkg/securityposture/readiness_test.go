package securityposture

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestSecurityPostureReadinessSurfacesRemainReadOnlyDTOs(t *testing.T) {
	for _, surface := range []Surface{
		SurfaceUpdateProvider,
		SurfaceUpdateManifest,
		SurfaceUpdateArtifact,
		SurfaceProfileSyncProvider,
		SurfaceProfileSyncConflict,
		SurfaceRelayTransport,
		SurfaceAppBridgeStatus,
		SurfaceSetupStateStatus,
	} {
		classification := ClassifySurface(surface)
		if classification.Surface != surface {
			t.Fatalf("classification changed surface %q to %q", surface, classification.Surface)
		}
		if classification.Summary == "" {
			t.Fatalf("classification for %q needs safe human summary text", surface)
		}
		assertSecurityPostureTextSafe(t, classification)
	}
}

func TestSecurityPostureReadinessDocumentsHardNonGoalsInCode(t *testing.T) {
	for _, surface := range []Surface{
		SurfaceUpdateProvider,
		SurfaceUpdateManifest,
		SurfaceUpdateArtifact,
		SurfaceProfileSyncProvider,
		SurfaceProfileSyncConflict,
		SurfaceRelayTransport,
	} {
		classification := ClassifySurface(surface)
		if !classification.ReviewRequired {
			t.Fatalf("%q must stay review-required; it is not an automatic action", surface)
		}
		if classification.Posture != PostureReviewRequired {
			t.Fatalf("%q should advertise review-required posture, got %q", surface, classification.Posture)
		}
	}
}

func TestSecurityPostureReadinessUnknownSurfaceIsConservative(t *testing.T) {
	classification := ClassifySurface(Surface("future_surface"))
	if classification.Surface != SurfaceUnknown {
		t.Fatalf("unknown surface should remain unknown, got %q", classification.Surface)
	}
	if !classification.ReviewRequired {
		t.Fatalf("unknown surface must require review")
	}
	if classification.Posture != PostureUnknown {
		t.Fatalf("unknown surface should not be treated as ready, got %q", classification.Posture)
	}
}

func assertSecurityPostureTextSafe(t *testing.T, value any) {
	t.Helper()
	raw, err := json.Marshal(value)
	if err != nil {
		t.Fatalf("marshal security posture value: %v", err)
	}
	lower := strings.ToLower(string(raw))
	for _, forbidden := range []string{
		"client_secret",
		"refresh_token",
		"access_token",
		"id_token",
		"auth_code",
		"private_key",
		"github_pat",
		"ghp_",
		"token=",
		"password=",
		"secret=",
		`c:\\users\\`,
		"appdata",
		"downloads",
		"remediate",
		"quarantine",
		"delete threats",
		"scan files",
	} {
		if strings.Contains(lower, forbidden) {
			t.Fatalf("security posture public DTO leaked forbidden marker %q: %s", forbidden, lower)
		}
	}
}

package setupstate

import (
	"context"
	"errors"
	"strings"
	"testing"
)

func TestBuildOverviewPublicDTOsDoNotLeakDisabledCapabilities(t *testing.T) {
	overview, err := BuildOverview(context.Background(), AppSetupConfig{
		AppID:               "aegis-test",
		DisplayName:         "Aegis Test",
		EnabledCapabilities: []Capability{CapabilityUpdates},
	}, map[Capability]StatusProvider{
		CapabilityUpdates: StatusProviderFunc(func(ctx context.Context) (CapabilityStatus, error) {
			return CapabilityStatus{Capability: CapabilityUpdates, Enabled: true, Ready: true, State: StateReady, Summary: "updates ready"}, nil
		}),
		CapabilityRelay: StatusProviderFunc(func(ctx context.Context) (CapabilityStatus, error) {
			t.Fatal("disabled relay capability provider should not be called")
			return CapabilityStatus{}, nil
		}),
	})
	if err != nil {
		t.Fatalf("BuildOverview returned error: %v", err)
	}
	if !overview.Ready {
		t.Fatalf("disabled capabilities should not block readiness: %+v", overview)
	}
	if len(overview.Capabilities) != 1 || overview.Capabilities[0].Capability != CapabilityUpdates {
		t.Fatalf("expected only enabled update capability, got %+v", overview.Capabilities)
	}
}

func TestBuildOverviewSanitizesProviderErrors(t *testing.T) {
	overview, err := BuildOverview(context.Background(), AppSetupConfig{
		AppID:               "aegis-test",
		DisplayName:         "Aegis Test",
		EnabledCapabilities: []Capability{CapabilityAuth},
	}, map[Capability]StatusProvider{
		CapabilityAuth: StatusProviderFunc(func(ctx context.Context) (CapabilityStatus, error) {
			return CapabilityStatus{}, errors.New(`C:\Users\name\AppData\secret-token.txt`)
		}),
	})
	if err != nil {
		t.Fatalf("BuildOverview should degrade provider errors, got: %v", err)
	}
	if overview.Ready || len(overview.BlockingIssues) != 1 {
		t.Fatalf("expected provider failure to become a blocking setup issue: %+v", overview)
	}
	if strings.Contains(overview.BlockingIssues[0].Message, `C:\`) || strings.Contains(strings.ToLower(overview.BlockingIssues[0].Message), "token") {
		t.Fatalf("provider issue leaked unsafe detail: %q", overview.BlockingIssues[0].Message)
	}
}

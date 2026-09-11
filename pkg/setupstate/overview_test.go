package setupstate

import (
	"context"
	"errors"
	"strings"
	"testing"
)

func TestBuildOverviewCapabilityCombinations(t *testing.T) {
	providers := map[Capability]StatusProvider{
		CapabilityAuth: StatusProviderFunc(func(context.Context) (CapabilityStatus, error) {
			return CapabilityStatus{Ready: true, State: StateReady, Summary: "signed in"}, nil
		}),
		CapabilityUpdates: StatusProviderFunc(func(context.Context) (CapabilityStatus, error) {
			return CapabilityStatus{Ready: true, State: StateReady, Summary: "up to date"}, nil
		}),
		CapabilityDeviceLink: StatusProviderFunc(func(context.Context) (CapabilityStatus, error) {
			return CapabilityStatus{Ready: false, State: StateWarning, Summary: "no peers linked"}, nil
		}),
		CapabilityProfileMesh: StatusProviderFunc(func(context.Context) (CapabilityStatus, error) {
			return CapabilityStatus{Ready: true, State: StateReady, Summary: "profile mesh ready"}, nil
		}),
	}
	cases := [][]Capability{
		{CapabilityAuth},
		{CapabilityUpdates},
		{CapabilityAuth, CapabilityUpdates},
		{CapabilityAuth, CapabilityUpdates, CapabilityDeviceLink},
		{CapabilityProfileMesh},
		{CapabilityAuth, CapabilityUpdates, CapabilityDeviceLink, CapabilityProfileMesh},
	}
	for _, caps := range cases {
		overview, err := BuildOverview(context.Background(), AppSetupConfig{AppID: "sample-app", DisplayName: "Sample", EnabledCapabilities: caps}, providers)
		if err != nil {
			t.Fatal(err)
		}
		if len(overview.Capabilities) != len(caps) {
			t.Fatalf("expected %d capabilities, got %+v", len(caps), overview.Capabilities)
		}
	}
}

func TestDisabledCapabilitiesAreNotFailures(t *testing.T) {
	overview, err := BuildOverview(context.Background(), AppSetupConfig{AppID: "sample-app", DisplayName: "Sample", EnabledCapabilities: []Capability{CapabilityUpdates}}, map[Capability]StatusProvider{
		CapabilityUpdates: StatusProviderFunc(func(context.Context) (CapabilityStatus, error) {
			return CapabilityStatus{Ready: true, State: StateReady}, nil
		}),
	})
	if err != nil {
		t.Fatal(err)
	}
	if !overview.Ready || len(overview.BlockingIssues) != 0 || len(overview.Capabilities) != 1 {
		t.Fatalf("disabled capabilities should not block: %+v", overview)
	}
}

func TestProfileMeshCapabilityStates(t *testing.T) {
	disabled, err := BuildOverview(context.Background(), AppSetupConfig{AppID: "sample-app", DisplayName: "Sample", EnabledCapabilities: []Capability{CapabilityUpdates}}, map[Capability]StatusProvider{
		CapabilityUpdates: StatusProviderFunc(func(context.Context) (CapabilityStatus, error) {
			return CapabilityStatus{Ready: true, State: StateReady}, nil
		}),
	})
	if err != nil {
		t.Fatal(err)
	}
	if !disabled.Ready || len(disabled.Capabilities) != 1 {
		t.Fatalf("disabled profile mesh should not block: %+v", disabled)
	}
	healthy, err := BuildOverview(context.Background(), AppSetupConfig{AppID: "sample-app", DisplayName: "Sample", EnabledCapabilities: []Capability{CapabilityProfileMesh}}, map[Capability]StatusProvider{
		CapabilityProfileMesh: StatusProviderFunc(func(context.Context) (CapabilityStatus, error) {
			return CapabilityStatus{Ready: true, State: StateReady, Summary: "profile mesh ready"}, nil
		}),
	})
	if err != nil || !healthy.Ready {
		t.Fatalf("expected healthy profile mesh overview, got %+v %v", healthy, err)
	}
	notBootstrapped, err := BuildOverview(context.Background(), AppSetupConfig{AppID: "sample-app", DisplayName: "Sample", EnabledCapabilities: []Capability{CapabilityProfileMesh}}, map[Capability]StatusProvider{
		CapabilityProfileMesh: StatusProviderFunc(func(context.Context) (CapabilityStatus, error) {
			return CapabilityStatus{Ready: false, State: StateBlocked, Summary: "profile mesh is not bootstrapped"}, nil
		}),
	})
	if err != nil {
		t.Fatal(err)
	}
	if notBootstrapped.Ready || len(notBootstrapped.BlockingIssues) != 1 {
		t.Fatalf("expected safe profile mesh blocking issue, got %+v", notBootstrapped)
	}
}

func TestProviderErrorsBecomeSafeIssues(t *testing.T) {
	overview, err := BuildOverview(context.Background(), AppSetupConfig{AppID: "sample-app", DisplayName: "Sample", EnabledCapabilities: []Capability{CapabilityAuth}}, map[Capability]StatusProvider{
		CapabilityAuth: StatusProviderFunc(func(context.Context) (CapabilityStatus, error) {
			return CapabilityStatus{}, errors.New("secret token at C:\\Users\\person\\token.json")
		}),
	})
	if err != nil {
		t.Fatal(err)
	}
	if overview.Ready || len(overview.BlockingIssues) != 1 {
		t.Fatalf("expected blocking provider issue: %+v", overview)
	}
	msg := overview.BlockingIssues[0].Message
	if strings.Contains(msg, "secret") || strings.Contains(msg, "Users") || strings.Contains(msg, "token") {
		t.Fatalf("issue leaked provider error: %q", msg)
	}
}

func TestInvalidConfig(t *testing.T) {
	if _, err := BuildOverview(context.Background(), AppSetupConfig{DisplayName: "Sample"}, nil); !errors.Is(err, ErrInvalidConfig) {
		t.Fatalf("expected invalid config, got %v", err)
	}
}

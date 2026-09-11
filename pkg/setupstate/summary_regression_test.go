package setupstate

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
)

func TestWarningWithoutReadinessBlocksOverview(t *testing.T) {
	overview, err := BuildOverview(context.Background(), AppSetupConfig{AppID: "test", DisplayName: "Test", EnabledCapabilities: []Capability{CapabilitySecurityPosture}}, map[Capability]StatusProvider{CapabilitySecurityPosture: StatusProviderFunc(func(context.Context) (CapabilityStatus, error) {
		return CapabilityStatus{State: StateWarning, Ready: false, Summary: "unknown posture"}, nil
	})})
	if err != nil || overview.Ready || len(overview.BlockingIssues) != 1 {
		t.Fatalf("warning readiness discarded: %+v %v", overview, err)
	}
}

func TestSuccessfulAndDegradedSummariesAreSanitizedTogether(t *testing.T) {
	for _, state := range []CapabilityState{StateReady, StateWarning, StateBlocked} {
		const unsafe = "access_token=sentinel at C:\\Users\\sentinel\\cache"
		calls := 0
		overview, err := BuildOverview(context.Background(), AppSetupConfig{AppID: "test", DisplayName: "Test", EnabledCapabilities: []Capability{CapabilityAuth}}, map[Capability]StatusProvider{CapabilityAuth: StatusProviderFunc(func(context.Context) (CapabilityStatus, error) {
			calls++
			return CapabilityStatus{Ready: state != StateBlocked, State: state, Summary: unsafe}, nil
		})})
		if err != nil || calls != 1 {
			t.Fatalf("calls=%d err=%v", calls, err)
		}
		raw, _ := json.Marshal(overview)
		if strings.Contains(string(raw), "sentinel") {
			t.Fatalf("unsafe canonical summary: %s", raw)
		}
		for _, issue := range append(overview.BlockingIssues, overview.Warnings...) {
			if issue.Message != overview.Capabilities[0].Summary {
				t.Fatal("capability and issue summaries disagree")
			}
		}
	}
}

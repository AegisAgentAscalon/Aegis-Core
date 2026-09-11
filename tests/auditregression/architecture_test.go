package auditregression

// This audit-only program exercises public APIs without changing the Core tree.
import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/AegisAgentAscalon/aegis-core/pkg/appbridge"
	"github.com/AegisAgentAscalon/aegis-core/pkg/auth"
	"github.com/AegisAgentAscalon/aegis-core/pkg/relay"
	"github.com/AegisAgentAscalon/aegis-core/pkg/securityposture"
	"github.com/AegisAgentAscalon/aegis-core/pkg/setupstate"
)

type relayProvider struct{ status relay.RelayStatus }

func (p *relayProvider) GetStatus(context.Context) relay.RelayStatus { return p.status }

type postureProvider struct{}

func (postureProvider) BuildSecurityPosture(context.Context) securityposture.Summary {
	return securityposture.Summary{Capability: "security_posture", Posture: "future_unrecognized_posture"}
}

type authProvider struct{ calls int }

func (p *authProvider) Status(context.Context) (auth.AuthStatus, error) {
	p.calls++
	if p.calls == 1 {
		return auth.AuthStatus{Configured: true, SignedIn: true}, nil
	}
	return auth.AuthStatus{}, errors.New("second status read failed")
}
func (*authProvider) StartSignIn(context.Context) (auth.SignInStartResult, error) {
	return auth.SignInStartResult{}, nil
}
func (*authProvider) CompleteSignIn(context.Context, auth.CompleteSignInRequest) (auth.CompleteSignInResult, error) {
	return auth.CompleteSignInResult{}, nil
}
func (*authProvider) SignOut(context.Context) error { return nil }

func TestArchitectureAudit(t *testing.T) {
	ctx := context.Background()
	rp := &relayProvider{status: relay.RelayStatus{Enabled: true, Available: true, Issues: []relay.RelayIssue{{Code: "provider_issue", Message: "access_token=audit-sentinel", Blocking: true}}}}
	ap := &authProvider{}
	bridge, err := appbridge.NewSetupBridge(appbridge.AppBridgeConfig{
		Identity:        appbridge.AppIdentity{AppID: "audit", DisplayName: "Audit"},
		Relay:           appbridge.RelayBridgeConfig{CapabilityConfig: appbridge.CapabilityConfig{Enabled: true}, Provider: rp},
		SecurityPosture: appbridge.SecurityPostureBridgeConfig{CapabilityConfig: appbridge.CapabilityConfig{Enabled: true}, Provider: postureProvider{}},
		Auth:            appbridge.AuthBridgeConfig{CapabilityConfig: appbridge.CapabilityConfig{Enabled: true}, Service: ap},
	})
	if err != nil {
		t.Fatal(err)
	}
	_, err = bridge.RelayStatus(ctx)
	if err != nil {
		t.Fatal(err)
	}
	posture, err := bridge.SecurityPostureStatus(ctx)
	if err != nil {
		t.Fatal(err)
	}
	authResult, authErr := bridge.AuthStatus(ctx)
	sentinel := "access_token=audit-sentinel at C:\\Users\\audit\\token.json"
	setup, err := setupstate.BuildOverview(ctx,
		setupstate.AppSetupConfig{AppID: "audit", DisplayName: "Audit", EnabledCapabilities: []setupstate.Capability{setupstate.CapabilityAuth}},
		map[setupstate.Capability]setupstate.StatusProvider{setupstate.CapabilityAuth: setupstate.StatusProviderFunc(func(context.Context) (setupstate.CapabilityStatus, error) {
			return setupstate.CapabilityStatus{Ready: true, State: setupstate.StateReady, Summary: sentinel}, nil
		})})
	if err != nil {
		t.Fatal(err)
	}
	out := map[string]any{
		"relay_provider_issue_mutated":        rp.status.Issues[0].Message != "access_token=audit-sentinel" || !rp.status.Issues[0].Blocking,
		"relay_provider_issue_after":          rp.status.Issues[0],
		"unknown_posture_card_ready":          posture.Card.Ready,
		"unknown_posture_card_state":          posture.Card.State,
		"auth_status_provider_calls":          ap.calls,
		"auth_card_ready":                     authResult.Card.Ready,
		"auth_status_configured":              authResult.Status.Configured,
		"auth_second_error_discarded":         authErr == nil,
		"setupstate_unsafe_summary_preserved": setup.Capabilities[0].Summary == sentinel,
	}

	if out["relay_provider_issue_mutated"].(bool) {
		t.Error("AR-01: bridge mutated provider-owned status")
	}
	if posture.Card.Ready {
		t.Error("AR-02: unknown security posture reported ready")
	}
	if ap.calls != 1 || authErr != nil || !authResult.Status.Configured {
		t.Errorf("AR-03: incoherent auth snapshot: calls=%d err=%v", ap.calls, authErr)
	}
	if strings.Contains(setup.Capabilities[0].Summary, "audit-sentinel") || strings.Contains(setup.Capabilities[0].Summary, `C:\Users\audit\token.json`) {
		t.Error("AR-04: unsafe setup summary preserved")
	}
}

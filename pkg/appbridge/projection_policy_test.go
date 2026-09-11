package appbridge

import (
	"context"
	"errors"
	"testing"

	"github.com/AegisAgentAscalon/aegis-core/pkg/setupstate"
	"github.com/AegisAgentAscalon/aegis-core/pkg/updates"
)

type policyUpdateOwner struct {
	UpdateService
	status updates.CurrentState
	err    error
	calls  int
}

func (p *policyUpdateOwner) GetStatus(context.Context) (updates.CurrentState, error) {
	p.calls++
	if p.calls > 1 {
		panic("status fetched twice")
	}
	return p.status, p.err
}

func TestUpdateProjectionPolicies(t *testing.T) {
	ownerError := errors.New("private owner failure")
	for _, tc := range []struct {
		name              string
		enabled, missing  bool
		status            updates.CurrentState
		err               error
		setup, diagnostic setupstate.CapabilityState
	}{
		{name: "disabled", diagnostic: setupstate.StateDisabled},
		{name: "missing", enabled: true, missing: true, setup: setupstate.StateBlocked, diagnostic: setupstate.StateWarning},
		{name: "failure", enabled: true, err: ownerError, diagnostic: setupstate.StateWarning},
		{name: "unconfigured", enabled: true, setup: setupstate.StateBlocked, diagnostic: setupstate.StateWarning},
		{name: "ready", enabled: true, status: updates.CurrentState{Configured: true}, setup: setupstate.StateReady, diagnostic: setupstate.StateReady},
		{name: "available", enabled: true, status: updates.CurrentState{Configured: true, UpdateAvailable: true}, setup: setupstate.StateWarning, diagnostic: setupstate.StateWarning},
		{name: "degraded", enabled: true, status: updates.CurrentState{Configured: true, LastError: "unavailable", Message: "retry later"}, setup: setupstate.StateReady, diagnostic: setupstate.StateWarning},
	} {
		t.Run(tc.name, func(t *testing.T) {
			owner := &policyUpdateOwner{status: tc.status, err: tc.err}
			b := &Bridge{cfg: AppBridgeConfig{Updates: UpdateBridgeConfig{CapabilityConfig: CapabilityConfig{Enabled: tc.enabled}, Service: owner}}}
			if tc.missing {
				b.cfg.Updates.Service = nil
			}
			strict, err := b.UpdateStatus(context.Background())
			wantError := tc.err
			if !tc.enabled {
				wantError = ErrDisabled
			}
			if err != wantError || strict.Card.State != tc.setup {
				t.Fatalf("setup: %+v, error %v; want %s, %v", strict, err, tc.setup, wantError)
			}
			wantCalls := 0
			if tc.enabled && !tc.missing {
				wantCalls = 1
			}
			if owner.calls != wantCalls {
				t.Fatalf("setup reads: %d", owner.calls)
			}
			owner.calls = 0
			diagnostic, err := b.BuildInfrastructureStatus(context.Background())
			if err != nil || !diagnostic.Ready || !diagnostic.Updates.Card.Ready || diagnostic.Updates.Card.State != tc.diagnostic {
				t.Fatalf("diagnostic: %+v, error %v", diagnostic, err)
			}
			if owner.calls != wantCalls {
				t.Fatalf("diagnostic reads: %d", owner.calls)
			}
			if wantError == nil && strict.Card.Ready != (tc.setup != setupstate.StateBlocked) {
				t.Fatalf("incorrect strict readiness: %+v", strict.Card)
			}
		})
	}
}

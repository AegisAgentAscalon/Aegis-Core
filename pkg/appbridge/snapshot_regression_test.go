package appbridge

import (
	"context"
	"errors"
	"reflect"
	"sync"
	"testing"

	"github.com/AegisAgentAscalon/aegis-core/pkg/auth"
	"github.com/AegisAgentAscalon/aegis-core/pkg/profilemesh"
	"github.com/AegisAgentAscalon/aegis-core/pkg/profilesync"
	"github.com/AegisAgentAscalon/aegis-core/pkg/securityposture"
	"github.com/AegisAgentAscalon/aegis-core/pkg/setupstate"
	"github.com/AegisAgentAscalon/aegis-core/pkg/updates"
)

type changingAuth struct {
	AuthService
	calls int
	fail  bool
}

func (p *changingAuth) Status(context.Context) (auth.AuthStatus, error) {
	p.calls++
	if p.fail || p.calls > 1 {
		return auth.AuthStatus{}, errors.New("unavailable")
	}
	return auth.AuthStatus{Configured: true, SignedIn: true}, nil
}

type changingUpdate struct {
	UpdateService
	calls int
	fail  bool
}

func (p *changingUpdate) GetStatus(context.Context) (updates.CurrentState, error) {
	p.calls++
	if p.fail || p.calls > 1 {
		return updates.CurrentState{}, errors.New("unavailable")
	}
	return updates.CurrentState{Configured: true, UpdateAvailable: true}, nil
}

func TestStatusAndCardUseOneOwnerRead(t *testing.T) {
	for _, fail := range []bool{false, true} {
		a, u := &changingAuth{fail: fail}, &changingUpdate{fail: fail}
		b := &Bridge{cfg: AppBridgeConfig{Auth: AuthBridgeConfig{CapabilityConfig: CapabilityConfig{Enabled: true}, Service: a}, Updates: UpdateBridgeConfig{CapabilityConfig: CapabilityConfig{Enabled: true}, Service: u}}}
		ar, ae := b.AuthStatus(context.Background())
		ur, ue := b.UpdateStatus(context.Background())
		if a.calls != 1 || u.calls != 1 {
			t.Fatalf("reads: auth=%d update=%d", a.calls, u.calls)
		}
		if fail {
			if ae == nil || ue == nil || ar.Card.Ready || ur.Card.Ready {
				t.Fatal("owner error discarded")
			}
		} else if ae != nil || ue != nil || !ar.Status.SignedIn || !ar.Card.Ready || !ur.Status.UpdateAvailable || ur.Card.State != setupstate.StateWarning {
			t.Fatalf("incoherent projections: %+v %+v %v %v", ar, ur, ae, ue)
		}
	}
}

func TestProjectionClonesAllMutableStatusFields(t *testing.T) {
	// Concurrent projection and caller mutation must never write cached snapshots.
	a := auth.AuthStatus{Scopes: []string{"scope"}}
	u := updates.CurrentState{LatestRelease: &updates.Release{Version: "1"}}
	p := profilesync.SyncStatus{Issues: []profilesync.SyncIssue{{Message: "access_token=private"}}}
	m := profilemesh.ProfileMeshOverview{Issues: []profilemesh.ProfileMeshIssue{{Message: "access_token=private"}}, Warnings: []profilemesh.ProfileMeshIssue{{Message: "access_token=private", Blocking: true}}}
	s := securityposture.Summary{Posture: securityposture.PostureReady, Issues: []securityposture.Issue{{Summary: "access_token=private"}}}
	var wg sync.WaitGroup
	for i := 0; i < 16; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			ac, uc, pc, mc, sc := sanitizeAuthStatus(a), sanitizeUpdateStatus(u), sanitizeProfileSyncStatus(p), sanitizeProfileMeshOverview(m), sanitizeSecurityPostureSummary(s)
			ac.Scopes[0] = "changed"
			uc.LatestRelease.Version = "changed"
			pc.Issues[0].Message = "changed"
			mc.Issues[0].Message = "changed"
			mc.Warnings[0].Message = "changed"
			sc.Issues[0].Summary = "changed"
		}()
	}
	wg.Wait()
	if a.Scopes[0] != "scope" || u.LatestRelease.Version != "1" || p.Issues[0].Message != "access_token=private" || m.Issues[0].Message != "access_token=private" || m.Warnings[0].Message != "access_token=private" || !m.Warnings[0].Blocking || s.Issues[0].Summary != "access_token=private" {
		t.Fatal("provider-owned snapshot mutated")
	}
	// Nil and empty slices keep their original JSON distinction.
	if sanitizeAuthStatus(auth.AuthStatus{}).Scopes != nil || !reflect.DeepEqual(sanitizeAuthStatus(auth.AuthStatus{Scopes: []string{}}).Scopes, []string{}) {
		t.Fatal("slice shape changed")
	}
}

func TestUnknownSecurityPostureIsNotReady(t *testing.T) {
	for _, posture := range []securityposture.Posture{"", securityposture.PostureUnknown, "future", securityposture.PostureReady, securityposture.PostureBlocked, securityposture.PostureReviewRequired, securityposture.PostureDegraded, securityposture.PostureOutOfScope} {
		summary := sanitizeSecurityPostureSummary(securityposture.Summary{Posture: posture})
		card := securityPostureCard(summary)
		wantReady := posture == securityposture.PostureReady || posture == securityposture.PostureReviewRequired || posture == securityposture.PostureDegraded || posture == securityposture.PostureOutOfScope
		if card.Ready != wantReady {
			t.Errorf("posture %q: %+v", posture, card)
		}
		if !wantReady && card.State == setupstate.StateReady {
			t.Errorf("posture %q displayed ready", posture)
		}
	}
}

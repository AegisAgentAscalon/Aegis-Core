package identitygate

import (
	"context"
	"errors"
	"testing"
)

func TestEvaluateScopeExplainsDeniedProtectedAndHighRisk(t *testing.T) {
	ctx := context.Background()
	s, _ := svc(t)
	protected, err := s.EvaluateScope(ctx, ScopeUserPrivateMemory)
	if err != nil {
		t.Fatal(err)
	}
	if protected.Allowed || !protected.ReauthRequired || protected.FreshRequired || protected.Reason != "operator verification required" {
		t.Fatalf("unexpected protected decision: %+v", protected)
	}
	highRisk, err := s.EvaluateScope(ctx, ScopeVaultExport)
	if err != nil {
		t.Fatal(err)
	}
	if highRisk.Allowed || !highRisk.ReauthRequired || !highRisk.FreshRequired || highRisk.Reason != "fresh verification required" {
		t.Fatalf("unexpected high-risk decision: %+v", highRisk)
	}
}

func TestEvaluateScopeExplainsUnknownAndLocked(t *testing.T) {
	ctx := context.Background()
	s, _ := svc(t)
	unknown, err := s.EvaluateScope(ctx, Scope("not_real"))
	if !errors.Is(err, ErrUnknownScope) {
		t.Fatalf("expected unknown scope error, got %v", err)
	}
	if unknown.KnownScope || unknown.Reason != "unknown scope" {
		t.Fatalf("unexpected unknown decision: %+v", unknown)
	}
	_, _ = s.LockSession(ctx, "lock")
	locked, err := s.EvaluateScope(ctx, ScopeUserPrivateMemory)
	if err != nil {
		t.Fatal(err)
	}
	if locked.Allowed || !locked.Locked || !locked.ReauthRequired || locked.Reason != "session locked" {
		t.Fatalf("unexpected locked decision: %+v", locked)
	}
}

func TestEvaluateScopeExplainsAllowedAfterVerification(t *testing.T) {
	ctx := context.Background()
	s, _ := svc(t)
	_, _ = s.RequestVerification(ctx, "u1", "test")
	decision, err := s.EvaluateScope(ctx, ScopeUserPrivateMemory)
	if err != nil {
		t.Fatal(err)
	}
	if !decision.Allowed || decision.ReauthRequired || decision.FreshRequired || decision.CurrentAssurance != AssuranceVerified {
		t.Fatalf("unexpected verified decision: %+v", decision)
	}
}

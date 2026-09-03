package identitygate

import (
	"context"
	"testing"
)

func TestPublicEvaluateScopeDecision(t *testing.T) {
	ctx := context.Background()
	svc, err := NewService(testConfig())
	if err != nil {
		t.Fatal(err)
	}
	decision, err := svc.EvaluateScope(ctx, ScopeUserPrivateMemory)
	if err != nil {
		t.Fatal(err)
	}
	if decision.Allowed || !decision.ReauthRequired || decision.FreshRequired {
		t.Fatalf("unexpected protected decision: %+v", decision)
	}
	_, err = svc.RequestVerification(ctx, "user", "test")
	if err != nil {
		t.Fatal(err)
	}
	decision, err = svc.EvaluateScope(ctx, ScopeUserPrivateMemory)
	if err != nil {
		t.Fatal(err)
	}
	if !decision.Allowed {
		t.Fatalf("expected allowed protected decision, got %+v", decision)
	}
}

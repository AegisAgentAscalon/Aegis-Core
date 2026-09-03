package identitygate

import (
	"context"
	"testing"
	"time"
)

func TestCadenceAuthRequirementsGatePublicChatAndProfileLight(t *testing.T) {
	ctx := context.Background()
	clock := &fakeClock{now: time.Date(2026, 1, 1, 12, 0, 0, 0, time.UTC)}
	svc, err := NewService(Config{
		Clock:           clock,
		ReceiptProvider: MockVerificationProvider{Allow: true, Clock: clock},
		CadencePolicy: VerificationCadencePolicy{
			PublicChatRequiresAuth:   true,
			ProfileLightRequiresAuth: true,
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := svc.CreateUserProfile(ctx, UserProfile{UserID: "u1", DisplayName: "User"}); err != nil {
		t.Fatal(err)
	}

	publicChat, err := svc.EvaluateScope(ctx, ScopePublicChat)
	if err != nil || publicChat.Allowed || !publicChat.ReauthRequired || publicChat.Reason != "account authentication required" {
		t.Fatalf("public chat auth policy was not enforced: decision=%+v err=%v", publicChat, err)
	}
	claimed, err := svc.ClaimIdentity(ctx, "u1")
	if err != nil {
		t.Fatal(err)
	}
	profileLight, err := svc.EvaluateScope(ctx, ScopeProfileLight)
	if err != nil || profileLight.Allowed || !profileLight.ReauthRequired || profileLight.Reason != "account authentication required" {
		t.Fatalf("profile-light auth policy was not enforced: decision=%+v err=%v", profileLight, err)
	}

	_, authenticated, err := svc.RecognizeProfile(ctx, SessionSignals{ClaimedUserID: "u1", AccountUserID: "u1"})
	if err != nil {
		t.Fatal(err)
	}
	if authenticated.VerificationEpoch <= claimed.VerificationEpoch {
		t.Fatalf("recognition/auth transition did not advance epoch: claimed=%d authenticated=%d", claimed.VerificationEpoch, authenticated.VerificationEpoch)
	}
	for _, scope := range []Scope{ScopePublicChat, ScopeProfileLight} {
		allowed, err := svc.CanAccessScope(ctx, scope)
		if err != nil || !allowed {
			t.Fatalf("authenticated scope %q denied: allowed=%v err=%v", scope, allowed, err)
		}
	}
}

func TestIdleTimeoutUsesLastGatedActivityAndDowngrades(t *testing.T) {
	ctx := context.Background()
	clock := &fakeClock{now: time.Date(2026, 1, 1, 12, 0, 0, 0, time.UTC)}
	svc, err := NewService(Config{
		Clock:           clock,
		ReceiptProvider: MockVerificationProvider{Allow: true, Clock: clock},
		CadencePolicy: VerificationCadencePolicy{
			VerifiedWindow:    30 * time.Minute,
			MaxVerifiedWindow: 30 * time.Minute,
			IdleTimeout:       5 * time.Minute,
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	verified, err := svc.RequestVerification(ctx, "user", "test")
	if err != nil {
		t.Fatal(err)
	}
	clock.Add(4 * time.Minute)
	if err := svc.RequireScope(ctx, ScopeUserPrivateMemory, "activity"); err != nil {
		t.Fatal(err)
	}
	active, err := svc.CurrentSession(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if got := active.IdleTimeoutAt.Sub(clock.Now()); got != 5*time.Minute {
		t.Fatalf("gated activity did not reset idle deadline: %v", got)
	}
	clock.Add(4 * time.Minute)
	if err := svc.RequireScope(ctx, ScopeUserPrivateMemory, "still active"); err != nil {
		t.Fatalf("verification idled out too early: %v", err)
	}
	clock.Add(5*time.Minute + time.Second)
	idle, err := svc.CurrentSession(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if idle.VerifiedOperatorUserID != "" || !idle.ReauthRequired || idle.ReauthReason != "idle timeout" {
		t.Fatalf("idle timeout did not downgrade assurance: %+v", idle)
	}
	if idle.VerificationEpoch <= verified.VerificationEpoch {
		t.Fatalf("idle reset did not advance epoch: verified=%d idle=%d", verified.VerificationEpoch, idle.VerificationEpoch)
	}
}

func TestSlidingWindowsExtendOnlyToHardCaps(t *testing.T) {
	ctx := context.Background()
	clock := &fakeClock{now: time.Date(2026, 1, 1, 12, 0, 0, 0, time.UTC)}
	start := clock.Now()
	svc, err := NewService(Config{
		Clock:           clock,
		ReceiptProvider: MockVerificationProvider{Allow: true, Clock: clock},
		CadencePolicy: VerificationCadencePolicy{
			VerifiedWindow:        2 * time.Minute,
			FreshWindow:           time.Minute,
			IdleTimeout:           10 * time.Minute,
			MaxVerifiedWindow:     5 * time.Minute,
			MaxFreshWindow:        3 * time.Minute,
			SlidingVerifiedWindow: true,
			SlidingFreshWindow:    true,
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := svc.RequestFreshVerification(ctx, "user", "test"); err != nil {
		t.Fatal(err)
	}

	for _, advance := range []time.Duration{30 * time.Second, 50 * time.Second, 50 * time.Second, 40 * time.Second} {
		clock.Add(advance)
		allowed, err := svc.CanAccessScope(ctx, ScopeVaultExport)
		if err != nil || !allowed {
			t.Fatalf("fresh window did not slide at %v: allowed=%v err=%v", clock.Now().Sub(start), allowed, err)
		}
	}
	session, err := svc.CurrentSession(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if !session.FreshUntil.Equal(start.Add(3 * time.Minute)) {
		t.Fatalf("fresh window escaped or missed hard cap: %v", session.FreshUntil)
	}
	if session.VerifiedUntil.After(start.Add(5 * time.Minute)) {
		t.Fatalf("verified window escaped hard cap: %v", session.VerifiedUntil)
	}

	clock.Add(10 * time.Second)
	if allowed, err := svc.CanAccessScope(ctx, ScopeVaultExport); err != nil || allowed {
		t.Fatalf("fresh scope survived hard cap: allowed=%v err=%v", allowed, err)
	}
	if allowed, err := svc.CanAccessScope(ctx, ScopeUserPrivateMemory); err != nil || !allowed {
		t.Fatalf("verified scope was lost with fresh expiry: allowed=%v err=%v", allowed, err)
	}
	clock.Add(2 * time.Minute)
	if allowed, err := svc.CanAccessScope(ctx, ScopeUserPrivateMemory); err != nil || allowed {
		t.Fatalf("verified scope survived hard cap: allowed=%v err=%v", allowed, err)
	}
}

func TestBurnFreshAfterSensitiveUseConsumesOnlyFreshAssurance(t *testing.T) {
	ctx := context.Background()
	clock := &fakeClock{now: time.Date(2026, 1, 1, 12, 0, 0, 0, time.UTC)}
	svc, err := NewService(Config{
		Clock:           clock,
		ReceiptProvider: MockVerificationProvider{Allow: true, Clock: clock},
		CadencePolicy: VerificationCadencePolicy{
			BurnFreshAfterSensitiveUse: true,
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	fresh, err := svc.RequestFreshVerification(ctx, "user", "test")
	if err != nil {
		t.Fatal(err)
	}
	if allowed, err := svc.CanAccessScope(ctx, ScopeVaultExport); err != nil || !allowed {
		t.Fatalf("fresh capability check failed: allowed=%v err=%v", allowed, err)
	}
	stillFresh, err := svc.CurrentSession(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if stillFresh.AssuranceLevel != AssuranceFreshVerified || stillFresh.FreshUntil.IsZero() {
		t.Fatalf("read-only capability check burned freshness: %+v", stillFresh)
	}
	if err := svc.RequireScope(ctx, ScopeVaultExport, "sensitive use"); err != nil {
		t.Fatal(err)
	}
	burned, err := svc.CurrentSession(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if burned.AssuranceLevel != AssuranceVerified || !burned.FreshUntil.IsZero() || burned.VerifiedOperatorUserID == "" {
		t.Fatalf("burn did not preserve only ordinary verification: %+v", burned)
	}
	if burned.VerificationEpoch <= fresh.VerificationEpoch {
		t.Fatalf("fresh burn did not advance epoch: fresh=%d burned=%d", fresh.VerificationEpoch, burned.VerificationEpoch)
	}
	if allowed, err := svc.CanAccessScope(ctx, ScopeVaultExport); err != nil || allowed {
		t.Fatalf("fresh scope remained after burn: allowed=%v err=%v", allowed, err)
	}
	if allowed, err := svc.CanAccessScope(ctx, ScopeUserPrivateMemory); err != nil || !allowed {
		t.Fatalf("ordinary verified scope was lost after burn: allowed=%v err=%v", allowed, err)
	}
}

func TestClaimDowngradeAndLockAdvanceVerificationEpoch(t *testing.T) {
	ctx := context.Background()
	svc, _ := svc(t)
	initial, err := svc.CurrentSession(ctx)
	if err != nil {
		t.Fatal(err)
	}
	claimed, err := svc.ClaimIdentity(ctx, "u1")
	if err != nil {
		t.Fatal(err)
	}
	if claimed.VerificationEpoch <= initial.VerificationEpoch {
		t.Fatalf("claim did not advance epoch: initial=%d claimed=%d", initial.VerificationEpoch, claimed.VerificationEpoch)
	}
	downgraded, err := svc.DowngradeSession(ctx, "test")
	if err != nil {
		t.Fatal(err)
	}
	if downgraded.VerificationEpoch <= claimed.VerificationEpoch {
		t.Fatalf("downgrade did not advance epoch: claimed=%d downgraded=%d", claimed.VerificationEpoch, downgraded.VerificationEpoch)
	}
	locked, err := svc.LockSession(ctx, "test")
	if err != nil {
		t.Fatal(err)
	}
	if locked.VerificationEpoch <= downgraded.VerificationEpoch {
		t.Fatalf("lock did not advance epoch: downgraded=%d locked=%d", downgraded.VerificationEpoch, locked.VerificationEpoch)
	}
}

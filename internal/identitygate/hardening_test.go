package identitygate

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"
)

func TestCadencePolicyClampsRelaxedWindows(t *testing.T) {
	ctx := context.Background()
	clock := &fakeClock{now: time.Date(2026, 1, 1, 12, 0, 0, 0, time.UTC)}
	s, err := NewService(Config{
		Clock:           clock,
		ReceiptProvider: MockVerificationProvider{Allow: true, Clock: clock},
		CadencePolicy:   VerificationCadencePolicy{VerifiedWindow: 24 * time.Hour, FreshWindow: time.Hour, MaxVerifiedWindow: 30 * time.Minute, MaxFreshWindow: time.Minute},
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.RequestFreshVerification(ctx, "user", "test"); err != nil {
		t.Fatal(err)
	}
	session, err := s.CurrentSession(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if got := session.VerifiedUntil.Sub(session.VerifiedAt); got != 30*time.Minute {
		t.Fatalf("verified window was not clamped: %v", got)
	}
	if got := session.FreshUntil.Sub(session.FreshVerifiedAt); got != time.Minute {
		t.Fatalf("fresh window was not clamped: %v", got)
	}
}

func TestModelIdentityPacketDoesNotLeakRecognitionFeatures(t *testing.T) {
	ctx := context.Background()
	s, _ := svc(t)
	_, _, err := s.RecognizeProfile(ctx, SessionSignals{ClaimedUserID: "u1", Aliases: []string{"known"}})
	if err != nil {
		t.Fatal(err)
	}
	_, _ = s.RequestVerification(ctx, "u1", "test")
	packet, err := s.CreateModelIdentityPacket(ctx)
	if err != nil {
		t.Fatal(err)
	}
	encoded, err := json.Marshal(packet)
	if err != nil {
		t.Fatal(err)
	}
	text := string(encoded)
	if strings.Contains(text, "known") || strings.Contains(strings.ToLower(text), "password") {
		t.Fatalf("packet leaked feature or secret-like value: %s", text)
	}
}

func TestLockedSessionCannotVerifyBackIn(t *testing.T) {
	ctx := context.Background()
	s, _ := svc(t)
	_, _ = s.LockSession(ctx, "lock")
	_, err := s.RequestVerification(ctx, "u1", "test")
	if !errors.Is(err, ErrLocked) {
		t.Fatalf("expected locked, got %v", err)
	}
}

func TestDowngradeClearsProtectedScopes(t *testing.T) {
	ctx := context.Background()
	s, _ := svc(t)
	_, _ = s.RequestVerification(ctx, "u1", "test")
	if err := s.RequireScope(ctx, ScopeUserPrivateMemory, "test"); err != nil {
		t.Fatal(err)
	}
	_, _ = s.DowngradeSession(ctx, "test")
	ok, _ := s.CanAccessScope(ctx, ScopeUserPrivateMemory)
	if ok {
		t.Fatal("protected scope survived downgrade")
	}
}

func TestVerifiedOperatorPromptCanRequestProtectedScope(t *testing.T) {
	ctx := context.Background()
	s, _ := svc(t)
	_, _ = s.RequestVerification(ctx, "u1", "test")
	fragment := PromptFragment{SourceClass: SourceVerifiedOperator}
	if err := s.CheckPromptAuthority(ctx, fragment, []Scope{ScopeUserPrivateMemory}); err != nil {
		t.Fatalf("verified operator prompt denied: %v", err)
	}
}

func TestCurrentUserPromptCannotGrantProtectedScopeWithoutVerification(t *testing.T) {
	ctx := context.Background()
	s, _ := svc(t)
	fragment := PromptFragment{SourceClass: SourceCurrentUserMessage}
	if err := s.CheckPromptAuthority(ctx, fragment, []Scope{ScopeUserPrivateMemory}); !errors.Is(err, ErrReauthRequired) {
		t.Fatalf("expected reauth, got %v", err)
	}
}

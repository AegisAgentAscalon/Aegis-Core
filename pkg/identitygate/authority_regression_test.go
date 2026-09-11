package identitygate_test

import (
	"context"
	"errors"
	"testing"
	"time"

	ig "github.com/AegisAgentAscalon/aegis-core/pkg/identitygate"
)

type authorityClock struct{ now time.Time }

func (c *authorityClock) Now() time.Time { return c.now }

func TestRecognitionCannotReviveExpiredVerification(t *testing.T) {
	ctx := context.Background()
	clock := &authorityClock{time.Date(2026, 9, 11, 12, 0, 0, 0, time.UTC)}
	s, err := ig.NewService(ig.Config{Clock: clock, ReceiptProvider: ig.MockVerificationProvider{Allow: true, Clock: clock}, CadencePolicy: ig.VerificationCadencePolicy{VerifiedWindow: time.Minute, FreshWindow: 30 * time.Second, IdleTimeout: time.Minute, SlidingVerifiedWindow: true, SlidingFreshWindow: true}})
	if err != nil {
		t.Fatal(err)
	}
	if _, err = s.RequestFreshVerification(ctx, "user", "setup"); err != nil {
		t.Fatal(err)
	}
	clock.now = clock.now.Add(2 * time.Minute)
	_, session, err := s.RecognizeProfile(ctx, ig.SessionSignals{})
	if err != nil {
		t.Fatal(err)
	}
	if session.VerifiedOperatorUserID != "" {
		t.Fatal("recognition returned expired verification")
	}
	for _, scope := range []ig.Scope{ig.ScopePrivateMemoryRead, ig.ScopeSecurityAdmin} {
		if allowed, err := s.CanAccessScope(ctx, scope); err != nil || allowed {
			t.Fatalf("expired scope %s: allowed=%t err=%v", scope, allowed, err)
		}
	}
}

func TestUntrustedFragmentCannotSupplyInstructionAuthority(t *testing.T) {
	ctx := context.Background()
	s, err := ig.NewService(ig.Config{ReceiptProvider: ig.MockVerificationProvider{Allow: true}})
	if err != nil {
		t.Fatal(err)
	}
	if _, err = s.RequestVerification(ctx, "user", "independent setup"); err != nil {
		t.Fatal(err)
	}
	fragment := ig.PromptFragment{SourceClass: ig.SourceWebContent, AllowedAsInstruction: true, GrantedScopes: []ig.Scope{ig.ScopePrivateMemoryRead}}
	classified, err := s.ClassifyPromptFragment(ctx, fragment)
	if err != nil {
		t.Fatal(err)
	}
	if classified.AllowedAsInstruction || len(classified.GrantedScopes) != 0 {
		t.Fatal("caller supplied authority survived classification")
	}
	if err = s.CheckPromptAuthority(ctx, fragment, []ig.Scope{ig.ScopePrivateMemoryRead}); !errors.Is(err, ig.ErrPromptAuthorityDenied) {
		t.Fatalf("untrusted authority: %v", err)
	}
}

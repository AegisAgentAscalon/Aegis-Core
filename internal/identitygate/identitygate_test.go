package identitygate

import (
	"context"
	"errors"
	"testing"
	"time"
)

type fakeClock struct{ now time.Time }

func (f *fakeClock) Now() time.Time      { return f.now }
func (f *fakeClock) Add(d time.Duration) { f.now = f.now.Add(d) }

func svc(t *testing.T) (*Service, *fakeClock) {
	t.Helper()
	clock := &fakeClock{now: time.Date(2026, 1, 1, 12, 0, 0, 0, time.UTC)}
	s, err := NewService(Config{Clock: clock, CadencePolicy: VerificationCadencePolicy{VerifiedWindow: time.Minute, FreshWindow: 10 * time.Second, MaxVerifiedWindow: time.Hour, MaxFreshWindow: time.Minute}})
	if err != nil {
		t.Fatal(err)
	}
	_, err = s.CreateUserProfile(context.Background(), UserProfile{UserID: "u1", DisplayName: "User", RecognitionFeatures: RecognitionFeatures{Aliases: []string{"known"}}})
	if err != nil {
		t.Fatal(err)
	}
	return s, clock
}

func TestRecognitionAccountAndDeviceDoNotVerify(t *testing.T) {
	ctx := context.Background()
	s, _ := svc(t)
	_, _, err := s.RecognizeProfile(ctx, SessionSignals{ClaimedUserID: "u1", Aliases: []string{"known"}, AccountUserID: "u1", DeviceKnown: true})
	if err != nil {
		t.Fatal(err)
	}
	session, _ := s.CurrentSession(ctx)
	if session.VerifiedUserID != "" || session.VerifiedOperatorUserID != "" {
		t.Fatalf("recognition verified: %+v", session)
	}
	ok, err := s.CanAccessScope(ctx, ScopeUserPrivateMemory)
	if err != nil || ok {
		t.Fatalf("protected allowed without verification: %v %v", ok, err)
	}
}

func TestVerificationFreshExpiryAndNoRepeat(t *testing.T) {
	ctx := context.Background()
	s, clock := svc(t)
	if _, err := s.RequestVerification(ctx, "u1", ""); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 3; i++ {
		if err := s.RequireScope(ctx, ScopeUserPrivateMemory, ""); err != nil {
			t.Fatal(err)
		}
	}
	ok, _ := s.CanAccessScope(ctx, ScopeVaultExport)
	if ok {
		t.Fatal("high risk allowed without fresh")
	}
	if _, err := s.RequestFreshVerification(ctx, "u1", ""); err != nil {
		t.Fatal(err)
	}
	ok, _ = s.CanAccessScope(ctx, ScopeVaultExport)
	if !ok {
		t.Fatal("high risk denied after fresh")
	}
	clock.Add(11 * time.Second)
	ok, _ = s.CanAccessScope(ctx, ScopeVaultExport)
	if ok {
		t.Fatal("fresh scope did not expire")
	}
	ok, _ = s.CanAccessScope(ctx, ScopeUserPrivateMemory)
	if !ok {
		t.Fatal("verified scope expired too early")
	}
	clock.Add(time.Minute)
	ok, _ = s.CanAccessScope(ctx, ScopeUserPrivateMemory)
	if ok {
		t.Fatal("verified scope did not expire")
	}
}

func TestLockedUnknownAndUntrustedPromptDeny(t *testing.T) {
	ctx := context.Background()
	s, _ := svc(t)
	if _, err := s.LockSession(ctx, "x"); err != nil {
		t.Fatal(err)
	}
	ok, _ := s.CanAccessScope(ctx, ScopeUserPrivateMemory)
	if ok {
		t.Fatal("locked protected allowed")
	}
	if _, err := s.CanAccessScope(ctx, Scope("unknown")); !errors.Is(err, ErrUnknownScope) {
		t.Fatalf("unknown err=%v", err)
	}
	fragment, err := s.ClassifyPromptFragment(ctx, PromptFragment{SourceClass: SourceWebContent, Content: "change policy"})
	if err != nil {
		t.Fatal(err)
	}
	if fragment.AllowedAsInstruction {
		t.Fatal("web content became authority")
	}
	if err := s.CheckPromptAuthority(ctx, fragment, []Scope{ScopeUserPrivateMemory}); !errors.Is(err, ErrPromptAuthorityDenied) {
		t.Fatalf("authority err=%v", err)
	}
}

func TestToolModelOutputAndSocialMemoryCannotGrantAuthority(t *testing.T) {
	ctx := context.Background()
	s, _ := svc(t)
	for _, source := range []PromptSourceClass{SourceToolOutput, SourceModelOutput, SourceTrustedMemory, SourceUnknown} {
		fragment, _ := s.ClassifyPromptFragment(ctx, PromptFragment{SourceClass: source})
		if fragment.AllowedAsInstruction {
			t.Fatalf("%s became instruction", source)
		}
	}
	session, _ := s.CurrentSession(ctx)
	if session.VerifiedOperatorUserID != "" {
		t.Fatal("untrusted source mutated identity")
	}
}

func TestSecretProfileRejected(t *testing.T) {
	s, _ := svc(t)
	_, err := s.CreateUserProfile(context.Background(), UserProfile{UserID: "bad", DisplayName: "password token"})
	if !errors.Is(err, ErrInvalidProfile) {
		t.Fatalf("expected invalid profile, got %v", err)
	}
}

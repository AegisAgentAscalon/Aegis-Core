package identitygate

import (
	"context"
	"testing"
)

func TestPublicFacadeRecognitionDoesNotVerify(t *testing.T) {
	ctx := context.Background()
	svc, err := NewService(Config{})
	if err != nil {
		t.Fatal(err)
	}
	_, err = svc.CreateUserProfile(ctx, UserProfile{UserID: "user", DisplayName: "User", RecognitionFeatures: RecognitionFeatures{Aliases: []string{"alias"}}})
	if err != nil {
		t.Fatal(err)
	}
	_, session, err := svc.RecognizeProfile(ctx, SessionSignals{ClaimedUserID: "user", Aliases: []string{"alias"}, AccountUserID: "user", DeviceKnown: true})
	if err != nil {
		t.Fatal(err)
	}
	if session.VerifiedUserID != "" || session.VerifiedOperatorUserID != "" {
		t.Fatalf("recognized session verified operator: %+v", session)
	}
	allowed, err := svc.CanAccessScope(ctx, ScopeUserPrivateMemory)
	if err != nil {
		t.Fatal(err)
	}
	if allowed {
		t.Fatal("protected scope allowed before verification")
	}
}

func TestPublicFacadeVerificationAllowsProtectedScope(t *testing.T) {
	ctx := context.Background()
	svc, err := NewService(Config{})
	if err != nil {
		t.Fatal(err)
	}
	_, err = svc.RequestVerification(ctx, "user", "test")
	if err != nil {
		t.Fatal(err)
	}
	allowed, err := svc.CanAccessScope(ctx, ScopeUserPrivateMemory)
	if err != nil {
		t.Fatal(err)
	}
	if !allowed {
		t.Fatal("protected scope denied after verification")
	}
}

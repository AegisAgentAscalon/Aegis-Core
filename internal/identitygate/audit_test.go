package identitygate

import (
	"context"
	"testing"
	"time"
)

func TestMemoryAuditSinkSnapshotIsCopy(t *testing.T) {
	ctx := context.Background()
	sink := &MemoryAuditSink{}
	event := AuditEvent{Kind: "identity.scope.denied", Summary: "safe summary", CreatedAt: time.Date(2026, 1, 1, 12, 0, 0, 0, time.UTC)}
	if err := sink.Record(ctx, event); err != nil {
		t.Fatal(err)
	}
	snapshot := sink.Snapshot()
	if len(snapshot) != 1 || snapshot[0].Kind != event.Kind {
		t.Fatalf("unexpected snapshot: %+v", snapshot)
	}
	snapshot[0].Kind = "mutated"
	again := sink.Snapshot()
	if again[0].Kind != event.Kind {
		t.Fatalf("snapshot mutated sink: %+v", again)
	}
}

func TestSafeRedactsSecretLikeAuditReasons(t *testing.T) {
	if got := safe("contains password token"); got != "redacted" {
		t.Fatalf("expected redacted, got %q", got)
	}
	long := "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	if got := safe(long); len(got) != 160 {
		t.Fatalf("expected truncation to 160, got %d", len(got))
	}
}

func TestServiceRecordsSafeAuditEvents(t *testing.T) {
	ctx := context.Background()
	sink := &MemoryAuditSink{}
	clock := &fakeClock{now: time.Date(2026, 1, 1, 12, 0, 0, 0, time.UTC)}
	s, err := NewService(Config{Clock: clock, AuditSink: sink})
	if err != nil {
		t.Fatal(err)
	}
	_, _ = s.CreateUserProfile(ctx, UserProfile{UserID: "u1", DisplayName: "User", RecognitionFeatures: RecognitionFeatures{Aliases: []string{"known"}}})
	_, _ = s.ClaimIdentity(ctx, "u1")
	_, _, _ = s.RecognizeProfile(ctx, SessionSignals{ClaimedUserID: "u1", Aliases: []string{"known"}})
	_, _ = s.RequestVerification(ctx, "u1", "test")
	_, _ = s.CanAccessScope(ctx, ScopeUserPrivateMemory)
	_ = s.CheckPromptAuthority(ctx, PromptFragment{SourceClass: SourceWebContent}, []Scope{ScopeUserPrivateMemory})
	_, _ = s.CreateModelIdentityPacket(ctx)
	_, _ = s.LockSession(ctx, "contains password token")

	events := sink.Snapshot()
	want := map[string]bool{
		EventSessionCreated:        false,
		EventIdentityClaimed:       false,
		EventProfileRecognized:     false,
		EventVerificationRequested: false,
		EventVerificationSucceeded: false,
		EventScopeAllowed:          false,
		EventPromptAuthorityDenied: false,
		EventModelPacketCreated:    false,
		EventSessionLocked:         false,
	}
	for _, event := range events {
		if _, ok := want[event.Kind]; ok {
			want[event.Kind] = true
		}
		if event.Summary == "contains password token" {
			t.Fatalf("audit leaked secret-like summary: %+v", event)
		}
	}
	for kind, seen := range want {
		if !seen {
			t.Fatalf("missing audit event %s in %+v", kind, events)
		}
	}
}

package identitygate

import (
	"context"
	"testing"
)

func TestPublicAuditEventConstantsAndRedaction(t *testing.T) {
	event := NewAuditEvent(EventScopeDenied, "contains password token", nil)
	if event.Kind != EventScopeDenied {
		t.Fatalf("unexpected kind: %s", event.Kind)
	}
	if event.Summary != "redacted" {
		t.Fatalf("expected redacted summary, got %q", event.Summary)
	}
}

func TestPublicAuditSinkReceivesServiceEvents(t *testing.T) {
	sink := &MemoryAuditSink{}
	cfg := testConfig()
	cfg.AuditSink = sink
	svc, err := NewService(cfg)
	if err != nil {
		t.Fatal(err)
	}
	_, _ = svc.RequestVerification(context.Background(), "user", "test")
	events := sink.Snapshot()
	seen := false
	for _, event := range events {
		if event.Kind == EventVerificationSucceeded {
			seen = true
		}
	}
	if !seen {
		t.Fatalf("expected verification success event in %+v", events)
	}
}

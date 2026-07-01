package identitygate

import (
	"testing"
	"time"
)

func TestNewAuditEventRedactsSecretLikeSummary(t *testing.T) {
	clock := &fakeClock{now: time.Date(2026, 1, 1, 12, 0, 0, 0, time.UTC)}
	event := NewAuditEvent(EventScopeDenied, "contains password token", clock)
	if event.Kind != EventScopeDenied {
		t.Fatalf("unexpected kind: %s", event.Kind)
	}
	if event.Summary != "redacted" {
		t.Fatalf("expected redacted summary, got %q", event.Summary)
	}
	if !event.CreatedAt.Equal(clock.Now()) {
		t.Fatalf("unexpected created_at: %s", event.CreatedAt)
	}
}

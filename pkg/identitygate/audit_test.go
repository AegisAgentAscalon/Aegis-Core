package identitygate

import "testing"

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
	svc, err := NewService(Config{AuditSink: sink})
	if err != nil {
		t.Fatal(err)
	}
	_, _ = svc.RequestVerification(nilContext(), "user", "test")
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

func nilContext() contextWrapper { return contextWrapper{} }

type contextWrapper struct{}

func (contextWrapper) Deadline() (deadline time.Time, ok bool) { return time.Time{}, false }
func (contextWrapper) Done() <-chan struct{} { return nil }
func (contextWrapper) Err() error { return nil }
func (contextWrapper) Value(key any) any { return nil }

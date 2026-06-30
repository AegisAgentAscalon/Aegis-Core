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

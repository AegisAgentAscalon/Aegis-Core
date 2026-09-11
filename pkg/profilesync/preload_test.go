package profilesync

import (
	"context"
	"errors"
	"testing"
	"time"
)

func TestLocalReadFailurePreservesLegacyQueue(t *testing.T) {
	now := time.Now().UTC()
	ctx := context.Background()
	h := newRelayReceiverTestHarness(t, now, "preload")
	store := NewMemoryMetadataStore()
	store.SetLocalSnapshot(validSyncSnapshot("local", "", now))
	manager := h.newManager(t, store, store, staticTrust{trusted: true})
	sendSyncEnvelope(t, h.provider, h.mailbox.MailboxID, snapshotEnvelope("profile-a", "device-remote", validSyncSnapshot("remote", "", now), now), now, "preload-message")
	store.SetError(errors.New("read unavailable"))
	if _, err := manager.PullRemote(ctx); !errors.Is(err, ErrStoreUnavailable) {
		t.Fatalf("read failure: %v", err)
	}
	store.SetError(nil)
	got, err := manager.PullRemote(ctx)
	if err != nil || got.ReceivedSnapshots != 1 {
		t.Fatalf("preflight lost message: %+v %v", got, err)
	}
}

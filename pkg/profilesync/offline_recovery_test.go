package profilesync

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/AegisAgentAscalon/aegis-core/pkg/profilemesh"
	"github.com/AegisAgentAscalon/aegis-core/pkg/relay"
)

func TestOfflineStatusClassifiesStaleLocalSnapshotAndStoreOnlyPlan(t *testing.T) {
	ctx := context.Background()
	now := time.Now().UTC()
	clock := &syncClock{now: now}
	store := NewMemoryMetadataStore()
	stale := validSyncSnapshot("snapshot-local-stale", "", now)
	stale.Metadata.CreatedAt = now.Add(-profilemesh.DefaultSnapshotFreshnessWindow - 2*time.Minute)
	stale.Metadata.UpdatedAt = now.Add(-profilemesh.DefaultSnapshotFreshnessWindow - time.Minute)
	store.SetLocalSnapshot(stale)
	store.AddLocalProposal(validSyncProposal("proposal-offline", stale.Metadata.SnapshotID, now))

	manager, err := NewSyncManager(
		SyncConfig{Enabled: true, ProfileNamespace: "profile-a", LocalDeviceID: "device-local"},
		WithSnapshotStore(store),
		WithProposalStore(store),
		WithClock(clock),
	)
	if err != nil {
		t.Fatalf("NewSyncManager returned error: %v", err)
	}

	status := manager.BuildStatus(ctx)
	if status.Available || !status.ReviewRequired || !hasSyncIssue(status.Issues, "local_snapshot_stale") || !hasSyncIssue(status.Issues, "transport_missing") {
		t.Fatalf("offline stale status should be degraded and review-required: %+v", status)
	}
	assertSyncSafeJSON(t, status)

	plan, err := manager.BuildSyncPlan(ctx)
	if err != nil || plan.TransportAvailable || !plan.ConflictReviewNeeded || plan.LocalProposalCount != 1 || !hasSyncIssue(plan.Issues, "local_snapshot_stale") || !hasSyncIssue(plan.Issues, "offline_transport_missing") {
		t.Fatalf("offline store-only plan should classify stale local metadata and missing transport: %+v, %v", plan, err)
	}
	assertSyncSafeJSON(t, plan)
}

func TestLocalMetadataStoreStatusClassifiesStaleLocalSnapshotSafely(t *testing.T) {
	ctx := context.Background()
	now := time.Now().UTC()
	clock := &syncClock{now: now}
	store, err := NewLocalMetadataStore(LocalMetadataStoreConfig{RootDir: t.TempDir(), ProfileNamespace: "profile-a", Clock: clock})
	if err != nil {
		t.Fatalf("NewLocalMetadataStore returned error: %v", err)
	}
	stale := validSyncSnapshot("snapshot-local-store-stale", "", now)
	stale.Metadata.CreatedAt = now.Add(-profilemesh.DefaultSnapshotFreshnessWindow - 2*time.Minute)
	stale.Metadata.UpdatedAt = now.Add(-profilemesh.DefaultSnapshotFreshnessWindow - time.Minute)
	if err := store.SaveLocalSnapshot(ctx, stale); err != nil {
		t.Fatalf("SaveLocalSnapshot returned error: %v", err)
	}

	status := store.BuildStatus(ctx)
	if !status.Available || !status.LocalSnapshotConfigured || !hasSyncIssue(status.Issues, "local_snapshot_stale") {
		t.Fatalf("local store status should mark stale local snapshot safely: %+v", status)
	}
	assertSyncSafeJSON(t, status)
}

func TestProviderUnavailableAndReconnectConflictRemainReviewRequired(t *testing.T) {
	ctx := context.Background()
	now := time.Now().UTC()
	clock := &syncClock{now: now}
	store := NewMemoryMetadataStore()
	local := validSyncSnapshot("snapshot-local", "", now)
	store.SetLocalSnapshot(local)
	remote := validSyncSnapshot("snapshot-reconnect-conflict", "", now)
	transport := &recoveringSyncTransport{
		status: SyncTransportStatus{Available: false, ProviderID: "offline-transport", Summary: "transport unavailable"},
		err:    ErrTransportUnavailable,
		envelopes: []SyncEnvelope{
			snapshotEnvelope("profile-a", "device-remote", remote, now),
		},
	}
	manager, err := NewSyncManager(
		SyncConfig{Enabled: true, ProfileNamespace: "profile-a", LocalDeviceID: "device-local"},
		WithSnapshotStore(store),
		WithProposalStore(store),
		WithTransport(transport),
		WithTrustVerifier(staticTrust{trusted: true}),
		WithClock(clock),
	)
	if err != nil {
		t.Fatalf("NewSyncManager returned error: %v", err)
	}

	status := manager.BuildStatus(ctx)
	if status.Available || !hasSyncIssue(status.Issues, "transport_unavailable") {
		t.Fatalf("provider unavailable status should degrade safely: %+v", status)
	}
	plan, err := manager.BuildSyncPlan(ctx)
	if err != nil || plan.TransportAvailable || !hasSyncIssue(plan.Issues, "offline_transport_unavailable") {
		t.Fatalf("provider unavailable plan should classify offline transport: %+v, %v", plan, err)
	}
	pull, err := manager.PullRemote(ctx)
	if !errors.Is(err, ErrTransportUnavailable) || !hasSyncIssue(pull.Issues, "transport_unavailable") {
		t.Fatalf("offline pull should fail safely: %+v, %v", pull, err)
	}
	assertSyncSafeJSON(t, status)
	assertSyncSafeJSON(t, plan)
	assertSyncSafeJSON(t, pull)

	transport.status = SyncTransportStatus{Available: true, ProviderID: "offline-transport", Summary: "transport recovered"}
	transport.err = nil
	pull, err = manager.PullRemote(ctx)
	if err != nil || pull.ReceivedSnapshots != 1 || !pull.ReviewRequired || !hasSyncIssue(pull.Issues, "conflict_review_required") {
		t.Fatalf("reconnect conflict should remain review-required without auto-merge: %+v, %v", pull, err)
	}
	status = manager.BuildStatus(ctx)
	if !status.ReviewRequired || !hasSyncIssue(status.Issues, "conflict_review_required") {
		t.Fatalf("status should preserve reconnect review-required state: %+v", status)
	}
	assertSyncSafeJSON(t, pull)
	assertSyncSafeJSON(t, status)
}

type recoveringSyncTransport struct {
	status    SyncTransportStatus
	err       error
	envelopes []SyncEnvelope
}

func (t *recoveringSyncTransport) GetStatus(context.Context) SyncTransportStatus {
	return t.status
}

func (t *recoveringSyncTransport) PushEnvelope(context.Context, SyncEnvelope) (relay.DeliveryReceipt, error) {
	if t.err != nil {
		return relay.DeliveryReceipt{}, t.err
	}
	return relay.DeliveryReceipt{Accepted: true, Delivered: false, Summary: "metadata accepted by caller-owned transport"}, nil
}

func (t *recoveringSyncTransport) PullEnvelopes(context.Context) ([]SyncEnvelope, error) {
	if t.err != nil {
		return nil, t.err
	}
	return append([]SyncEnvelope{}, t.envelopes...), nil
}

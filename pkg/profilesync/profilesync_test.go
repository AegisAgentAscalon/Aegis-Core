package profilesync

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/AegisAgentAscalon/aegis-core/pkg/profilemesh"
	"github.com/AegisAgentAscalon/aegis-core/pkg/relay"
)

func TestSyncStatusDisabledAndDegradedAreSafe(t *testing.T) {
	ctx := context.Background()
	now := time.Now().UTC()
	manager, err := NewSyncManager(SyncConfig{Enabled: false})
	if err != nil {
		t.Fatalf("NewSyncManager disabled returned error: %v", err)
	}
	status := manager.BuildStatus(ctx)
	if status.Enabled || status.Available || len(status.Issues) != 0 {
		t.Fatalf("disabled sync should be non-fatal: %+v", status)
	}

	store := NewMemoryMetadataStore()
	store.SetLocalSnapshot(validSyncSnapshot("snapshot-local", "", now))
	manager, err = NewSyncManager(
		SyncConfig{Enabled: true, ProfileNamespace: "profile-a", LocalDeviceID: "device-local"},
		WithSnapshotStore(store),
	)
	if err != nil {
		t.Fatalf("NewSyncManager returned error: %v", err)
	}
	status = manager.BuildStatus(ctx)
	if status.Available || len(status.Issues) == 0 {
		t.Fatalf("missing transport should degrade status: %+v", status)
	}
	assertSyncSafeJSON(t, status)

	store.SetError(errors.New(`C:\Users\person\AppData\secret-store.txt`))
	status = manager.BuildStatus(ctx)
	if status.Available || strings.Contains(marshalLower(t, status), `c:\\`) || strings.Contains(marshalLower(t, status), "secret-store") {
		t.Fatalf("store failure should be sanitized: %+v", status)
	}
}

func TestPushAndPullSnapshotThroughRelayTransport(t *testing.T) {
	ctx := context.Background()
	now := time.Now().UTC()
	clock := &syncClock{now: now}
	provider, err := relay.NewLocalDevProvider(relay.LocalDevProviderConfig{ProviderID: "local-dev-relay", Clock: clock})
	if err != nil {
		t.Fatalf("NewLocalDevProvider returned error: %v", err)
	}
	mailboxB, err := provider.OpenMailbox(ctx, relay.MailboxOpenRequest{Namespace: "profile-a", OwnerDeviceID: "device-b", MailboxID: "mailbox-b", CreatedAt: now, ExpiresAt: now.Add(time.Hour)})
	if err != nil {
		t.Fatalf("OpenMailbox returned error: %v", err)
	}
	transportA, err := NewRelaySyncTransport(RelaySyncTransportConfig{Provider: provider, Namespace: "profile-a", SourceDeviceID: "device-a", TargetMailboxID: mailboxB.MailboxID, Clock: clock})
	if err != nil {
		t.Fatalf("NewRelaySyncTransport A returned error: %v", err)
	}
	transportB, err := NewRelaySyncTransport(RelaySyncTransportConfig{Provider: provider, Namespace: "profile-a", SourceDeviceID: "device-b", TargetDeviceID: "device-a", Mailbox: mailboxB, Clock: clock})
	if err != nil {
		t.Fatalf("NewRelaySyncTransport B returned error: %v", err)
	}
	storeA := NewMemoryMetadataStore()
	storeA.SetLocalSnapshot(validSyncSnapshot("snapshot-a", "", now))
	managerA, err := NewSyncManager(
		SyncConfig{Enabled: true, ProfileNamespace: "profile-a", LocalDeviceID: "device-a"},
		WithSnapshotStore(storeA),
		WithProposalStore(storeA),
		WithTransport(transportA),
		WithTrustVerifier(staticTrust{trusted: true}),
		WithClock(clock),
	)
	if err != nil {
		t.Fatalf("NewSyncManager A returned error: %v", err)
	}
	storeB := NewMemoryMetadataStore()
	storeB.SetLocalSnapshot(validSyncSnapshot("snapshot-b", "snapshot-a", now))
	managerB, err := NewSyncManager(
		SyncConfig{Enabled: true, ProfileNamespace: "profile-a", LocalDeviceID: "device-b"},
		WithSnapshotStore(storeB),
		WithProposalStore(storeB),
		WithTransport(transportB),
		WithTrustVerifier(staticTrust{trusted: true}),
		WithClock(clock),
	)
	if err != nil {
		t.Fatalf("NewSyncManager B returned error: %v", err)
	}

	push, err := managerA.PushLocalSnapshot(ctx)
	if err != nil || push.PushedSnapshots != 1 {
		t.Fatalf("PushLocalSnapshot = %+v, %v", push, err)
	}
	pushAgain, err := managerA.PushLocalSnapshot(ctx)
	if err != nil || pushAgain.PushedSnapshots != 1 || len(pushAgain.Receipts) != 1 || !pushAgain.Receipts[0].Accepted {
		t.Fatalf("duplicate PushLocalSnapshot should be idempotent: %+v, %v", pushAgain, err)
	}
	pull, err := managerB.PullRemote(ctx)
	if err != nil || pull.ReceivedSnapshots != 1 || pull.ReviewRequired {
		t.Fatalf("PullRemote = %+v, %v", pull, err)
	}
	records, err := storeB.ListRemoteSnapshots(ctx)
	if err != nil || len(records) != 1 || records[0].TrustState != TrustTrusted || records[0].RequiresReview {
		t.Fatalf("remote snapshots = %+v, %v", records, err)
	}
	assertSyncSafeJSON(t, push)
	assertSyncSafeJSON(t, pushAgain)
	assertSyncSafeJSON(t, pull)
}

func TestPullRemoteSnapshotFailureModes(t *testing.T) {
	ctx := context.Background()
	now := time.Now().UTC()
	clock := &syncClock{now: now}
	provider, err := relay.NewLocalDevProvider(relay.LocalDevProviderConfig{ProviderID: "local-dev-relay", Clock: clock})
	if err != nil {
		t.Fatalf("NewLocalDevProvider returned error: %v", err)
	}
	mailbox, err := provider.OpenMailbox(ctx, relay.MailboxOpenRequest{Namespace: "profile-a", OwnerDeviceID: "device-local", MailboxID: "mailbox-local", CreatedAt: now, ExpiresAt: now.Add(time.Hour)})
	if err != nil {
		t.Fatalf("OpenMailbox returned error: %v", err)
	}
	transport, err := NewRelaySyncTransport(RelaySyncTransportConfig{Provider: provider, Namespace: "profile-a", SourceDeviceID: "device-local", TargetDeviceID: "device-remote", Mailbox: mailbox, Clock: clock})
	if err != nil {
		t.Fatalf("NewRelaySyncTransport returned error: %v", err)
	}
	store := NewMemoryMetadataStore()
	store.SetLocalSnapshot(validSyncSnapshot("snapshot-local", "", now))
	manager, err := NewSyncManager(
		SyncConfig{Enabled: true, ProfileNamespace: "profile-a", LocalDeviceID: "device-local"},
		WithSnapshotStore(store),
		WithProposalStore(store),
		WithTransport(transport),
		WithClock(clock),
	)
	if err != nil {
		t.Fatalf("NewSyncManager returned error: %v", err)
	}

	stale := validSyncSnapshot("snapshot-stale", "snapshot-local", now)
	stale.Metadata.UpdatedAt = now.Add(-profilemesh.DefaultSnapshotFreshnessWindow - time.Minute)
	stale.Metadata.CreatedAt = stale.Metadata.UpdatedAt
	sendSyncEnvelope(t, provider, mailbox.MailboxID, snapshotEnvelope("profile-a", "device-remote", stale, now), now, "msg-stale")
	pull, err := manager.PullRemote(ctx)
	if err != nil || pull.ReceivedSnapshots != 1 || !pull.ReviewRequired {
		t.Fatalf("stale pull = %+v, %v", pull, err)
	}

	sendSyncEnvelope(t, provider, mailbox.MailboxID, snapshotEnvelope("profile-a", "device-remote", stale, now), now, "msg-duplicate")
	pull, err = manager.PullRemote(ctx)
	if err != nil || pull.Rejected != 1 || !pull.ReviewRequired {
		t.Fatalf("duplicate pull = %+v, %v", pull, err)
	}

	future := validSyncSnapshot("snapshot-future", "snapshot-local", now)
	future.Metadata.UpdatedAt = now.Add(profilemesh.DefaultSnapshotClockSkew + time.Minute)
	sendSyncEnvelope(t, provider, mailbox.MailboxID, snapshotEnvelope("profile-a", "device-remote", future, now), now, "msg-future")
	pull, err = manager.PullRemote(ctx)
	if err != nil || pull.Rejected != 1 {
		t.Fatalf("future pull = %+v, %v", pull, err)
	}
	assertSyncSafeJSON(t, pull)
}

func TestPullRemoteProposalConflictAndUntrustedSigner(t *testing.T) {
	ctx := context.Background()
	now := time.Now().UTC()
	clock := &syncClock{now: now}
	provider, err := relay.NewLocalDevProvider(relay.LocalDevProviderConfig{ProviderID: "local-dev-relay", Clock: clock})
	if err != nil {
		t.Fatalf("NewLocalDevProvider returned error: %v", err)
	}
	mailbox, err := provider.OpenMailbox(ctx, relay.MailboxOpenRequest{Namespace: "profile-a", OwnerDeviceID: "device-local", MailboxID: "mailbox-local", CreatedAt: now, ExpiresAt: now.Add(time.Hour)})
	if err != nil {
		t.Fatalf("OpenMailbox returned error: %v", err)
	}
	transport, err := NewRelaySyncTransport(RelaySyncTransportConfig{Provider: provider, Namespace: "profile-a", SourceDeviceID: "device-local", TargetDeviceID: "device-remote", Mailbox: mailbox, Clock: clock})
	if err != nil {
		t.Fatalf("NewRelaySyncTransport returned error: %v", err)
	}
	store := NewMemoryMetadataStore()
	store.SetLocalSnapshot(validSyncSnapshot("snapshot-local", "", now))
	manager, err := NewSyncManager(
		SyncConfig{Enabled: true, ProfileNamespace: "profile-a", LocalDeviceID: "device-local"},
		WithSnapshotStore(store),
		WithProposalStore(store),
		WithTransport(transport),
		WithTrustVerifier(staticTrust{trusted: false}),
		WithClock(clock),
	)
	if err != nil {
		t.Fatalf("NewSyncManager returned error: %v", err)
	}
	proposal := validSyncProposal("proposal-1", "snapshot-other", now)
	proposal.RequiresUserReview = true
	proposal.Conflicts = []profilemesh.ConflictSummary{{ConflictID: "conflict-1", ResourceID: "profile-kb", ResourceType: "profile_data", Summary: "metadata branch conflict", RequiresUserReview: true}}
	sendSyncEnvelope(t, provider, mailbox.MailboxID, proposalEnvelope("profile-a", "device-remote", proposal, now), now, "msg-proposal")
	pull, err := manager.PullRemote(ctx)
	if err != nil || pull.ReceivedProposals != 1 || !pull.ReviewRequired {
		t.Fatalf("proposal pull = %+v, %v", pull, err)
	}
	records, err := store.ListRemoteProposals(ctx)
	if err != nil || len(records) != 1 || records[0].TrustState != TrustUntrusted || !records[0].RequiresReview {
		t.Fatalf("remote proposals = %+v, %v", records, err)
	}
	sendSyncEnvelope(t, provider, mailbox.MailboxID, proposalEnvelope("profile-a", "device-remote", proposal, now), now, "msg-proposal-duplicate")
	pull, err = manager.PullRemote(ctx)
	if err != nil || pull.Rejected != 1 || !pull.ReviewRequired {
		t.Fatalf("duplicate proposal pull = %+v, %v", pull, err)
	}
	assertSyncSafeJSON(t, pull)
}

func TestPushLocalProposalAndExchangeNoRelayProvider(t *testing.T) {
	ctx := context.Background()
	now := time.Now().UTC()
	store := NewMemoryMetadataStore()
	store.SetLocalSnapshot(validSyncSnapshot("snapshot-local", "", now))
	store.AddLocalProposal(validSyncProposal("proposal-1", "snapshot-local", now))
	manager, err := NewSyncManager(
		SyncConfig{Enabled: true, ProfileNamespace: "profile-a", LocalDeviceID: "device-local"},
		WithSnapshotStore(store),
		WithProposalStore(store),
		WithClock(&syncClock{now: now}),
	)
	if err != nil {
		t.Fatalf("NewSyncManager returned error: %v", err)
	}
	if _, err := manager.PushLocalSnapshot(ctx); !errors.Is(err, ErrNoRelayProvider) {
		t.Fatalf("PushLocalSnapshot without relay error = %v", err)
	}
}

func TestRelaySyncTransportRejectsTamperedCarrierEnvelope(t *testing.T) {
	ctx := context.Background()
	now := time.Now().UTC()
	mailbox := relay.MailboxRef{Namespace: "profile-a", MailboxID: "mailbox-local", OwnerDeviceID: "device-local", ProviderID: "tamper-relay", ExpiresAt: now.Add(time.Hour)}
	snapshot := validSyncSnapshot("snapshot-tampered", "", now)
	envelope := snapshotEnvelope("profile-a", "device-remote", snapshot, now)
	payload, err := json.Marshal(envelope)
	if err != nil {
		t.Fatalf("marshal sync envelope: %v", err)
	}
	provider := tamperedRelayProvider{mailbox: mailbox, envelope: relay.RelayEnvelope{
		RelayEnvelopeMetadata: relay.RelayEnvelopeMetadata{
			ProtocolVersion: relay.ProtocolVersion,
			Namespace:       "profile-a",
			SourceDeviceID:  "device-remote",
			TargetMailboxID: mailbox.MailboxID,
			MessageKind:     relay.MessageKindOpaque,
			CreatedAt:       now,
			ExpiresAt:       now.Add(time.Minute),
			MessageID:       "msg-tampered",
			PayloadHash:     strings.Repeat("0", 64),
			Metadata:        map[string]string{"aegis_profile_sync_kind": string(EnvelopeKindSnapshot)},
		},
		Payload: payload,
	}}
	transport, err := NewRelaySyncTransport(RelaySyncTransportConfig{Provider: provider, Namespace: "profile-a", SourceDeviceID: "device-local", TargetDeviceID: "device-remote", Mailbox: mailbox, Clock: &syncClock{now: now}})
	if err != nil {
		t.Fatalf("NewRelaySyncTransport returned error: %v", err)
	}
	store := NewMemoryMetadataStore()
	store.SetLocalSnapshot(validSyncSnapshot("snapshot-local", "", now))
	manager, err := NewSyncManager(
		SyncConfig{Enabled: true, ProfileNamespace: "profile-a", LocalDeviceID: "device-local"},
		WithSnapshotStore(store),
		WithProposalStore(store),
		WithTransport(transport),
		WithTrustVerifier(staticTrust{trusted: true}),
		WithClock(&syncClock{now: now}),
	)
	if err != nil {
		t.Fatalf("NewSyncManager returned error: %v", err)
	}
	pull, err := manager.PullRemote(ctx)
	if !errors.Is(err, ErrInvalidSyncEnvelope) || len(pull.Issues) == 0 || pull.Issues[0].Code != "invalid_envelope" {
		t.Fatalf("tampered carrier envelope should be rejected as invalid envelope: %+v, %v", pull, err)
	}
	assertSyncSafeJSON(t, pull)
}

func TestRelaySyncTransportRejectsFutureSyncEnvelope(t *testing.T) {
	ctx := context.Background()
	now := time.Now().UTC()
	clock := &syncClock{now: now}
	provider, err := relay.NewLocalDevProvider(relay.LocalDevProviderConfig{ProviderID: "local-dev-relay", Clock: clock})
	if err != nil {
		t.Fatalf("NewLocalDevProvider returned error: %v", err)
	}
	mailbox, err := provider.OpenMailbox(ctx, relay.MailboxOpenRequest{Namespace: "profile-a", OwnerDeviceID: "device-local", MailboxID: "mailbox-local", CreatedAt: now, ExpiresAt: now.Add(time.Hour)})
	if err != nil {
		t.Fatalf("OpenMailbox returned error: %v", err)
	}
	transport, err := NewRelaySyncTransport(RelaySyncTransportConfig{Provider: provider, Namespace: "profile-a", SourceDeviceID: "device-local", TargetDeviceID: "device-remote", Mailbox: mailbox, Clock: clock})
	if err != nil {
		t.Fatalf("NewRelaySyncTransport returned error: %v", err)
	}
	store := NewMemoryMetadataStore()
	store.SetLocalSnapshot(validSyncSnapshot("snapshot-local", "", now))
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
	futureEnvelope := snapshotEnvelope("profile-a", "device-remote", validSyncSnapshot("snapshot-future-envelope", "", now), now.Add(10*time.Minute))
	sendSyncEnvelope(t, provider, mailbox.MailboxID, futureEnvelope, now, "msg-future-envelope")
	pull, err := manager.PullRemote(ctx)
	if !errors.Is(err, ErrInvalidSyncEnvelope) || len(pull.Issues) == 0 || pull.Issues[0].Code != "invalid_envelope" {
		t.Fatalf("future sync envelope should be rejected: %+v, %v", pull, err)
	}
	assertSyncSafeJSON(t, pull)
}

func TestPullRemoteStoreFailuresAndUnsafeTrustMessagesAreSanitized(t *testing.T) {
	ctx := context.Background()
	now := time.Now().UTC()
	clock := &syncClock{now: now}
	provider, err := relay.NewLocalDevProvider(relay.LocalDevProviderConfig{ProviderID: "local-dev-relay", Clock: clock})
	if err != nil {
		t.Fatalf("NewLocalDevProvider returned error: %v", err)
	}
	mailbox, err := provider.OpenMailbox(ctx, relay.MailboxOpenRequest{Namespace: "profile-a", OwnerDeviceID: "device-local", MailboxID: "mailbox-local", CreatedAt: now, ExpiresAt: now.Add(time.Hour)})
	if err != nil {
		t.Fatalf("OpenMailbox returned error: %v", err)
	}
	transport, err := NewRelaySyncTransport(RelaySyncTransportConfig{Provider: provider, Namespace: "profile-a", SourceDeviceID: "device-local", TargetDeviceID: "device-remote", Mailbox: mailbox, Clock: clock})
	if err != nil {
		t.Fatalf("NewRelaySyncTransport returned error: %v", err)
	}
	baseStore := NewMemoryMetadataStore()
	baseStore.SetLocalSnapshot(validSyncSnapshot("snapshot-local", "", now))
	listFailingStore := &snapshotStoreHarness{MemoryMetadataStore: baseStore, listErr: errors.New(`C:\Users\person\AppData\client_secret=raw`)}
	manager, err := NewSyncManager(
		SyncConfig{Enabled: true, ProfileNamespace: "profile-a", LocalDeviceID: "device-local"},
		WithSnapshotStore(listFailingStore),
		WithProposalStore(baseStore),
		WithTransport(transport),
		WithTrustVerifier(staticTrust{trusted: true}),
		WithClock(clock),
	)
	if err != nil {
		t.Fatalf("NewSyncManager returned error: %v", err)
	}
	sendSyncEnvelope(t, provider, mailbox.MailboxID, snapshotEnvelope("profile-a", "device-remote", validSyncSnapshot("snapshot-list-fail", "", now), now), now, "msg-list-fail")
	pull, err := manager.PullRemote(ctx)
	if !errors.Is(err, ErrStoreUnavailable) || pull.Rejected != 1 || len(pull.Issues) == 0 {
		t.Fatalf("list failure should be sanitized store unavailable: %+v, %v", pull, err)
	}
	assertSyncSafeJSON(t, pull)

	storeWithUnsafeTrust := NewMemoryMetadataStore()
	storeWithUnsafeTrust.SetLocalSnapshot(validSyncSnapshot("snapshot-local", "", now))
	manager, err = NewSyncManager(
		SyncConfig{Enabled: true, ProfileNamespace: "profile-a", LocalDeviceID: "device-local"},
		WithSnapshotStore(storeWithUnsafeTrust),
		WithProposalStore(storeWithUnsafeTrust),
		WithTransport(transport),
		WithTrustVerifier(unsafeTrust{}),
		WithClock(clock),
	)
	if err != nil {
		t.Fatalf("NewSyncManager with unsafe trust returned error: %v", err)
	}
	sendSyncEnvelope(t, provider, mailbox.MailboxID, snapshotEnvelope("profile-a", "device-remote", validSyncSnapshot("snapshot-unsafe-trust", "", now), now), now, "msg-unsafe-trust")
	pull, err = manager.PullRemote(ctx)
	if err != nil || pull.ReceivedSnapshots != 1 || !pull.ReviewRequired {
		t.Fatalf("unsafe trust decision should become review-required: %+v, %v", pull, err)
	}
	assertSyncSafeJSON(t, pull)

	writeFailingStore := &snapshotStoreHarness{MemoryMetadataStore: NewMemoryMetadataStore(), saveErr: errors.New(`C:\Users\person\Downloads\raw-payload.json`)}
	writeFailingStore.SetLocalSnapshot(validSyncSnapshot("snapshot-local", "", now))
	manager, err = NewSyncManager(
		SyncConfig{Enabled: true, ProfileNamespace: "profile-a", LocalDeviceID: "device-local"},
		WithSnapshotStore(writeFailingStore),
		WithProposalStore(writeFailingStore),
		WithTransport(transport),
		WithTrustVerifier(staticTrust{trusted: true}),
		WithClock(clock),
	)
	if err != nil {
		t.Fatalf("NewSyncManager with write failure returned error: %v", err)
	}
	sendSyncEnvelope(t, provider, mailbox.MailboxID, snapshotEnvelope("profile-a", "device-remote", validSyncSnapshot("snapshot-write-fail", "", now), now), now, "msg-write-fail")
	pull, err = manager.PullRemote(ctx)
	if !errors.Is(err, ErrStoreUnavailable) || pull.Rejected != 1 || len(pull.Issues) == 0 {
		t.Fatalf("write failure should be sanitized store unavailable: %+v, %v", pull, err)
	}
	assertSyncSafeJSON(t, pull)
}

func TestProfileSyncPackageDoesNotImportInternalsOrExamples(t *testing.T) {
	files, err := filepath.Glob("*.go")
	if err != nil {
		t.Fatalf("glob profilesync files: %v", err)
	}
	for _, file := range files {
		if strings.HasSuffix(file, "_test.go") {
			continue
		}
		raw, err := os.ReadFile(file)
		if err != nil {
			t.Fatalf("read %s: %v", file, err)
		}
		text := string(raw)
		for _, forbidden := range []string{"/internal/", "internal/", "examples/", "named-consumer-app", "named-consumer-current", "named-consumer.local"} {
			if strings.Contains(text, forbidden) {
				t.Fatalf("pkg/profilesync imports or references forbidden text %q in %s", forbidden, file)
			}
		}
	}
}

type tamperedRelayProvider struct {
	mailbox  relay.MailboxRef
	envelope relay.RelayEnvelope
}

func (p tamperedRelayProvider) GetStatus(context.Context) relay.RelayStatus {
	return relay.RelayStatus{Enabled: true, Available: true, ProviderID: "tamper-relay", Summary: "relay is available"}
}

func (p tamperedRelayProvider) PublishEndpointHint(context.Context, relay.EndpointHint) error {
	return nil
}

func (p tamperedRelayProvider) ListEndpointHints(context.Context, relay.EndpointHintQuery) ([]relay.EndpointHint, error) {
	return nil, nil
}

func (p tamperedRelayProvider) OpenMailbox(context.Context, relay.MailboxOpenRequest) (relay.MailboxRef, error) {
	return p.mailbox, nil
}

func (p tamperedRelayProvider) SendEnvelope(context.Context, relay.RelayEnvelope) (relay.DeliveryReceipt, error) {
	return relay.DeliveryReceipt{Accepted: true, Delivered: true}, nil
}

func (p tamperedRelayProvider) ReceiveEnvelopes(context.Context, relay.MailboxRef) ([]relay.RelayEnvelope, error) {
	return []relay.RelayEnvelope{p.envelope}, nil
}

func validSyncSnapshot(snapshotID, parentID string, now time.Time) profilemesh.SignedProfileSnapshot {
	return profilemesh.SignedProfileSnapshot{
		Metadata: profilemesh.ProfileSnapshotMetadata{
			SchemaVersion:       1,
			ProfileNamespace:    "profile-a",
			ProfileID:           "profile-1",
			SnapshotID:          snapshotID,
			SnapshotFingerprint: strings.Repeat("a", 64),
			ParentSnapshotID:    parentID,
			SourceDeviceID:      "device-remote",
			HostingMode:         profilemesh.HostingSingleProfileDevice,
			CreatedAt:           now.Add(-time.Minute),
			UpdatedAt:           now,
			ExpiresAt:           now.Add(time.Hour),
			MetadataVersion:     1,
		},
		Signature: profilemesh.SnapshotSignatureSummary{
			SignerDeviceID:       "device-remote",
			SignerKeyFingerprint: strings.Repeat("b", 64),
			SignatureFingerprint: strings.Repeat("c", 64),
			Algorithm:            "ed25519-summary",
			SignedAt:             now,
		},
	}
}

func validSyncProposal(proposalID, baseSnapshotID string, now time.Time) profilemesh.ProfileChangeProposal {
	return profilemesh.ProfileChangeProposal{
		ProposalID:           proposalID,
		ProfileNamespace:     "profile-a",
		ProfileID:            "profile-1",
		BaseSnapshotID:       baseSnapshotID,
		ProposedSnapshotID:   "snapshot-proposed",
		SourceBranchID:       "branch-remote",
		TargetBranchID:       "branch-local",
		AuthorDeviceID:       "device-remote",
		Status:               profilemesh.ProposalStatusPendingReview,
		RequestedHostingMode: profilemesh.HostingSingleProfileDevice,
		CreatedAt:            now.Add(-time.Minute),
		UpdatedAt:            now,
		MergePlan:            profilemesh.MergePlan{FutureOnly: true, Summary: "metadata review placeholder"},
	}
}

func sendSyncEnvelope(t *testing.T, provider relay.RelayProvider, mailboxID string, envelope SyncEnvelope, now time.Time, relayMessageID string) {
	t.Helper()
	envelope.MessageID = relayMessageID
	payload, err := json.Marshal(envelope)
	if err != nil {
		t.Fatalf("marshal sync envelope: %v", err)
	}
	_, err = provider.SendEnvelope(context.Background(), relay.RelayEnvelope{
		RelayEnvelopeMetadata: relay.RelayEnvelopeMetadata{
			ProtocolVersion: relay.ProtocolVersion,
			Namespace:       "profile-a",
			SourceDeviceID:  envelope.SourceDeviceID,
			TargetMailboxID: mailboxID,
			MessageKind:     relay.MessageKindOpaque,
			CreatedAt:       now,
			ExpiresAt:       now.Add(time.Minute),
			MessageID:       relayMessageID,
			PayloadHash:     relay.PayloadSHA256(payload),
			Metadata:        map[string]string{"aegis_profile_sync_kind": string(envelope.Kind)},
		},
		Payload: payload,
	})
	if err != nil {
		t.Fatalf("send sync envelope: %v", err)
	}
}

type syncClock struct {
	now time.Time
}

func (c *syncClock) Now() time.Time {
	return c.now
}

type staticTrust struct {
	trusted bool
	pending bool
}

func (s staticTrust) VerifySigner(context.Context, string, string) TrustDecision {
	if s.trusted {
		return TrustDecision{Trusted: true}
	}
	if s.pending {
		return TrustDecision{Pending: true, Code: "trust_pending", Message: "trust verification is pending"}
	}
	return TrustDecision{Trusted: false, Code: "untrusted_signer", Message: "signer is not trusted"}
}

type unsafeTrust struct{}

func (unsafeTrust) VerifySigner(context.Context, string, string) TrustDecision {
	return TrustDecision{Trusted: false, Code: "client_secret", Message: `C:\Users\person\AppData\secret=raw`}
}

type snapshotStoreHarness struct {
	*MemoryMetadataStore
	listErr error
	saveErr error
}

func (s *snapshotStoreHarness) SaveRemoteSnapshot(ctx context.Context, record RemoteSnapshotRecord) error {
	if s.saveErr != nil {
		return s.saveErr
	}
	return s.MemoryMetadataStore.SaveRemoteSnapshot(ctx, record)
}

func (s *snapshotStoreHarness) ListRemoteSnapshots(ctx context.Context) ([]RemoteSnapshotRecord, error) {
	if s.listErr != nil {
		return nil, s.listErr
	}
	return s.MemoryMetadataStore.ListRemoteSnapshots(ctx)
}

func assertSyncSafeJSON(t *testing.T, v any) {
	t.Helper()
	text := marshalLower(t, v)
	for _, forbidden := range []string{"client_secret", "refresh_token", "access_token", "id_token", "auth_code", "verifier", "private_key", "begin private key", "github_pat", "ghp_", "token=", "password=", "secret=", `c:\\users\\`, "appdata", "downloads"} {
		if strings.Contains(text, forbidden) {
			t.Fatalf("unsafe sync JSON detail %q in %s", forbidden, text)
		}
	}
}

func marshalLower(t *testing.T, v any) string {
	t.Helper()
	raw, err := json.Marshal(v)
	if err != nil {
		t.Fatalf("json marshal failed: %v", err)
	}
	return strings.ToLower(string(raw))
}

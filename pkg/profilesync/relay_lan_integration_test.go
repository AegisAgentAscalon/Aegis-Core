package profilesync_test

import (
	"context"
	"encoding/json"
	"errors"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/AegisAgentAscalon/aegis-core/pkg/profilemesh"
	"github.com/AegisAgentAscalon/aegis-core/pkg/profilesync"
	"github.com/AegisAgentAscalon/aegis-core/pkg/relay"
)

func TestProfileSyncSelfHostedHTTPRelayLANIntegrationProof(t *testing.T) {
	ctx := context.Background()
	now := time.Now().UTC()
	clock := integrationClock{now: now}

	relayHandler, err := relay.NewHTTPRelayHandler(relay.HTTPRelayHandlerConfig{ProviderID: "self-hosted-lan-relay", Clock: clock, AllowUnauthenticated: true})
	if err != nil {
		t.Fatalf("NewHTTPRelayHandler returned error: %v", err)
	}
	relayServer := httptest.NewServer(relayHandler)
	defer relayServer.Close()
	relayClient, err := relay.NewHTTPRelayClient(relay.HTTPRelayClientConfig{BaseURL: relayServer.URL, ProviderID: "self-hosted-lan-relay"})
	if err != nil {
		t.Fatalf("NewHTTPRelayClient returned error: %v", err)
	}
	mailboxB, err := relayClient.OpenMailbox(ctx, relay.MailboxOpenRequest{Namespace: "profile-a", OwnerDeviceID: "device-b", MailboxID: "mailbox-lan-proof", CreatedAt: now, ExpiresAt: now.Add(time.Hour)})
	if err != nil {
		t.Fatalf("OpenMailbox returned error: %v", err)
	}

	cloudProvider, err := profilesync.NewFileObjectProvider(profilesync.FileObjectProviderConfig{RootDir: t.TempDir(), ProfileNamespace: "profile-a", ProviderID: "file-object-lan-proof", Clock: clock})
	if err != nil {
		t.Fatalf("NewFileObjectProvider returned error: %v", err)
	}
	snapshot := validIntegrationSnapshot("snapshot-lan-a", "", now)
	snapshotMetadata, err := json.Marshal(snapshot.Metadata)
	if err != nil {
		t.Fatalf("marshal snapshot metadata: %v", err)
	}
	snapshotRef, err := cloudProvider.PutObject(ctx, profilesync.CloudSyncObject{ProfileNamespace: "profile-a", ObjectID: "snapshot-lan-a", Kind: profilesync.CloudObjectSnapshotMetadata, Body: snapshotMetadata, CreatedAt: now, Metadata: map[string]string{"purpose": "lan-proof"}})
	if err != nil {
		t.Fatalf("PutObject returned error: %v", err)
	}
	manifest, err := profilesync.NormalizeCloudManifest(profilesync.CloudProfileManifest{SchemaVersion: profilesync.CloudManifestSchemaVersion, ProfileNamespace: "profile-a", ManifestID: "manifest-lan-proof", Generation: 1, CreatedAt: now, LatestSnapshotRef: &snapshotRef})
	if err != nil {
		t.Fatalf("NormalizeCloudManifest returned error: %v", err)
	}
	if err := cloudProvider.PutManifest(ctx, manifest); err != nil {
		t.Fatalf("PutManifest returned error: %v", err)
	}
	loadedManifest, err := cloudProvider.GetManifest(ctx, "profile-a")
	if err != nil {
		t.Fatalf("GetManifest returned error: %v", err)
	}
	verification := profilesync.VerifyCloudManifestObjects(ctx, cloudProvider, loadedManifest)
	if !verification.Verified || verification.CheckedObjects != 1 {
		t.Fatalf("VerifyCloudManifestObjects = %+v", verification)
	}
	comparison := profilesync.CompareCloudManifests(nil, loadedManifest, now)
	if comparison.Relation != profilesync.CloudManifestLocalMissing || comparison.ReviewRequired {
		t.Fatalf("CompareCloudManifests = %+v", comparison)
	}

	storeA := profilesync.NewMemoryMetadataStore()
	storeA.SetLocalSnapshot(snapshot)
	storeA.AddLocalProposal(validLANIntegrationProposal(now))
	transportA, err := profilesync.NewRelaySyncTransport(profilesync.RelaySyncTransportConfig{Provider: relayClient, Namespace: "profile-a", SourceDeviceID: "device-a", TargetMailboxID: mailboxB.MailboxID, Clock: clock})
	if err != nil {
		t.Fatalf("NewRelaySyncTransport A returned error: %v", err)
	}
	managerA, err := profilesync.NewSyncManager(
		profilesync.SyncConfig{Enabled: true, ProfileNamespace: "profile-a", LocalDeviceID: "device-a"},
		profilesync.WithSnapshotStore(storeA),
		profilesync.WithProposalStore(storeA),
		profilesync.WithTransport(transportA),
		profilesync.WithTrustVerifier(integrationTrust{trusted: true}),
		profilesync.WithClock(clock),
	)
	if err != nil {
		t.Fatalf("NewSyncManager A returned error: %v", err)
	}

	storeB := profilesync.NewMemoryMetadataStore()
	storeB.SetLocalSnapshot(validIntegrationSnapshot("snapshot-lan-b", "snapshot-lan-a", now))
	transportB, err := profilesync.NewRelaySyncTransport(profilesync.RelaySyncTransportConfig{Provider: relayClient, Namespace: "profile-a", SourceDeviceID: "device-b", TargetDeviceID: "device-a", Mailbox: mailboxB, Clock: clock})
	if err != nil {
		t.Fatalf("NewRelaySyncTransport B returned error: %v", err)
	}
	managerB, err := profilesync.NewSyncManager(
		profilesync.SyncConfig{Enabled: true, ProfileNamespace: "profile-a", LocalDeviceID: "device-b"},
		profilesync.WithSnapshotStore(storeB),
		profilesync.WithProposalStore(storeB),
		profilesync.WithTransport(transportB),
		profilesync.WithTrustVerifier(integrationTrust{trusted: false}),
		profilesync.WithClock(clock),
	)
	if err != nil {
		t.Fatalf("NewSyncManager B returned error: %v", err)
	}

	pushSnapshot, err := managerA.PushLocalSnapshot(ctx)
	if err != nil || pushSnapshot.PushedSnapshots != 1 {
		t.Fatalf("PushLocalSnapshot = %+v, %v", pushSnapshot, err)
	}
	pushProposals, err := managerA.PushLocalProposals(ctx)
	if err != nil || pushProposals.PushedProposals != 1 {
		t.Fatalf("PushLocalProposals = %+v, %v", pushProposals, err)
	}
	pull, err := managerB.PullRemote(ctx)
	if err != nil || pull.ReceivedSnapshots != 1 || pull.ReceivedProposals != 1 || !pull.ReviewRequired {
		t.Fatalf("PullRemote = %+v, %v", pull, err)
	}
	remoteSnapshots, err := storeB.ListRemoteSnapshots(ctx)
	if err != nil || len(remoteSnapshots) != 1 {
		t.Fatalf("remote snapshots = %+v, %v", remoteSnapshots, err)
	}
	if remoteSnapshots[0].TrustState != profilesync.TrustUntrusted || !remoteSnapshots[0].RequiresReview {
		t.Fatalf("relay delivery must not become trust: %+v", remoteSnapshots[0])
	}
	remoteProposals, err := storeB.ListRemoteProposals(ctx)
	if err != nil || len(remoteProposals) != 1 {
		t.Fatalf("remote proposals = %+v, %v", remoteProposals, err)
	}
	if remoteProposals[0].TrustState != profilesync.TrustUntrusted || !remoteProposals[0].RequiresReview {
		t.Fatalf("conflict proposal should remain review-required: %+v", remoteProposals[0])
	}

	assertIntegrationSafeJSON(t, pushSnapshot)
	assertIntegrationSafeJSON(t, pushProposals)
	assertIntegrationSafeJSON(t, pull)
	assertIntegrationSafeJSON(t, verification)
	assertIntegrationSafeJSON(t, comparison)
	assertIntegrationSafeJSON(t, relayClient.GetStatus(ctx))
	assertIntegrationSafeJSON(t, cloudProvider.GetStatus(ctx))
}

func TestProfileSyncRelayLANIntegrationFailureModesStaySafe(t *testing.T) {
	ctx := context.Background()
	now := time.Now().UTC()
	clock := integrationClock{now: now}

	relayHandler, err := relay.NewHTTPRelayHandler(relay.HTTPRelayHandlerConfig{ProviderID: "self-hosted-lan-relay", Clock: clock, AllowUnauthenticated: true})
	if err != nil {
		t.Fatalf("NewHTTPRelayHandler returned error: %v", err)
	}
	relayServer := httptest.NewServer(relayHandler)
	relayClient, err := relay.NewHTTPRelayClient(relay.HTTPRelayClientConfig{BaseURL: relayServer.URL, ProviderID: "self-hosted-lan-relay"})
	if err != nil {
		t.Fatalf("NewHTTPRelayClient returned error: %v", err)
	}
	mailboxB, err := relayClient.OpenMailbox(ctx, relay.MailboxOpenRequest{Namespace: "profile-a", OwnerDeviceID: "device-b", MailboxID: "mailbox-lan-failure", CreatedAt: now, ExpiresAt: now.Add(time.Hour)})
	if err != nil {
		t.Fatalf("OpenMailbox returned error: %v", err)
	}
	transportB, err := profilesync.NewRelaySyncTransport(profilesync.RelaySyncTransportConfig{Provider: relayClient, Namespace: "profile-a", SourceDeviceID: "device-b", TargetDeviceID: "device-a", Mailbox: mailboxB, Clock: clock})
	if err != nil {
		t.Fatalf("NewRelaySyncTransport returned error: %v", err)
	}
	storeB := profilesync.NewMemoryMetadataStore()
	storeB.SetLocalSnapshot(validIntegrationSnapshot("snapshot-lan-local", "", now))
	managerB, err := profilesync.NewSyncManager(
		profilesync.SyncConfig{Enabled: true, ProfileNamespace: "profile-a", LocalDeviceID: "device-b"},
		profilesync.WithSnapshotStore(storeB),
		profilesync.WithProposalStore(storeB),
		profilesync.WithTransport(transportB),
		profilesync.WithTrustVerifier(integrationTrust{trusted: true}),
		profilesync.WithClock(clock),
	)
	if err != nil {
		t.Fatalf("NewSyncManager returned error: %v", err)
	}

	malformedPayload := []byte("{")
	_, err = relayClient.SendEnvelope(ctx, relay.RelayEnvelope{
		RelayEnvelopeMetadata: relay.RelayEnvelopeMetadata{
			ProtocolVersion: relay.ProtocolVersion,
			Namespace:       "profile-a",
			SourceDeviceID:  "device-a",
			TargetMailboxID: mailboxB.MailboxID,
			MessageKind:     relay.MessageKindOpaque,
			CreatedAt:       now,
			ExpiresAt:       now.Add(time.Minute),
			MessageID:       "msg-malformed-lan",
			PayloadHash:     relay.PayloadSHA256(malformedPayload),
			Metadata:        map[string]string{"aegis_profile_sync_kind": string(profilesync.EnvelopeKindSnapshot)},
		},
		Payload: malformedPayload,
	})
	if err != nil {
		t.Fatalf("SendEnvelope malformed payload returned error: %v", err)
	}
	pull, err := managerB.PullRemote(ctx)
	if !errors.Is(err, profilesync.ErrInvalidSyncEnvelope) || len(pull.Issues) == 0 {
		t.Fatalf("malformed relay payload should be rejected safely: %+v, %v", pull, err)
	}
	assertIntegrationSafeJSON(t, pull)

	relayServer.Close()
	status := transportB.GetStatus(ctx)
	if status.Available || len(status.Issues) == 0 {
		t.Fatalf("closed self-hosted relay should produce degraded status: %+v", status)
	}
	assertIntegrationSafeJSON(t, status)

	ref, err := profilesync.ValidateCloudObject(profilesync.CloudSyncObject{ProfileNamespace: "profile-a", ObjectID: "snapshot-provider-missing", Kind: profilesync.CloudObjectSnapshotMetadata, Body: []byte("metadata body"), CreatedAt: now}, profilesync.DefaultMaxSyncObjectBytes)
	if err != nil {
		t.Fatalf("ValidateCloudObject returned error: %v", err)
	}
	manifest, err := profilesync.NormalizeCloudManifest(profilesync.CloudProfileManifest{SchemaVersion: profilesync.CloudManifestSchemaVersion, ProfileNamespace: "profile-a", ManifestID: "manifest-provider-missing", Generation: 1, CreatedAt: now, LatestSnapshotRef: &ref})
	if err != nil {
		t.Fatalf("NormalizeCloudManifest returned error: %v", err)
	}
	verification := profilesync.VerifyCloudManifestObjects(ctx, nil, manifest)
	if verification.Verified || verification.InvalidObjects == 0 || len(verification.Issues) == 0 {
		t.Fatalf("missing provider verification should degrade safely: %+v", verification)
	}
	assertIntegrationSafeJSON(t, verification)

	var missingProvider *profilesync.FileObjectProvider
	providerStatus := missingProvider.GetStatus(ctx)
	if providerStatus.Available || len(providerStatus.Issues) == 0 {
		t.Fatalf("nil provider status should be safely degraded: %+v", providerStatus)
	}
	assertIntegrationSafeJSON(t, providerStatus)
}

func validLANIntegrationProposal(now time.Time) profilemesh.ProfileChangeProposal {
	return profilemesh.ProfileChangeProposal{
		ProposalID:           "proposal-lan-review",
		ProfileNamespace:     "profile-a",
		ProfileID:            "profile-1",
		BaseSnapshotID:       "snapshot-lan-a",
		ProposedSnapshotID:   "snapshot-lan-proposed",
		SourceBranchID:       "branch-lan-a",
		TargetBranchID:       "branch-lan-b",
		AuthorDeviceID:       "device-a",
		Status:               profilemesh.ProposalStatusPendingReview,
		RequestedHostingMode: profilemesh.HostingSingleProfileDevice,
		CreatedAt:            now.Add(-time.Minute),
		UpdatedAt:            now,
		RequiresUserReview:   true,
		Conflicts: []profilemesh.ConflictSummary{{
			ConflictID:         "conflict-lan-review",
			ResourceID:         "resource-metadata",
			ResourceType:       "metadata",
			Summary:            "metadata conflict requires review",
			RequiresUserReview: true,
		}},
		MergePlan: profilemesh.MergePlan{FutureOnly: true, Summary: "metadata review placeholder"},
	}
}

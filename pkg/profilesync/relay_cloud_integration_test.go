package profilesync_test

import (
	"context"
	"encoding/json"
	"errors"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/AegisAgentAscalon/aegis-core/pkg/profilemesh"
	"github.com/AegisAgentAscalon/aegis-core/pkg/profilesync"
	"github.com/AegisAgentAscalon/aegis-core/pkg/relay"
)

func TestRelayCloudIntegrationHTTPRelayAndFileObjectProviderHappyPath(t *testing.T) {
	ctx := context.Background()
	now := time.Now().UTC()
	clock := integrationClock{now: now}

	relayHandler, err := relay.NewHTTPRelayHandler(relay.HTTPRelayHandlerConfig{ProviderID: "network-relay-integration", Clock: clock, AllowUnauthenticated: true})
	if err != nil {
		t.Fatalf("NewHTTPRelayHandler returned error: %v", err)
	}
	relayServer := httptest.NewServer(relayHandler)
	defer relayServer.Close()
	relayClient, err := relay.NewHTTPRelayClient(relay.HTTPRelayClientConfig{BaseURL: relayServer.URL, ProviderID: "network-relay-integration"})
	if err != nil {
		t.Fatalf("NewHTTPRelayClient returned error: %v", err)
	}
	mailboxB, err := relayClient.OpenMailbox(ctx, relay.MailboxOpenRequest{Namespace: "profile-a", OwnerDeviceID: "device-b", MailboxID: "mailbox-cloud-integration", CreatedAt: now, ExpiresAt: now.Add(time.Hour)})
	if err != nil {
		t.Fatalf("OpenMailbox returned error: %v", err)
	}

	cloudProvider, err := profilesync.NewFileObjectProvider(profilesync.FileObjectProviderConfig{RootDir: t.TempDir(), ProfileNamespace: "profile-a", ProviderID: "file-object-integration", Clock: clock})
	if err != nil {
		t.Fatalf("NewFileObjectProvider returned error: %v", err)
	}
	snapshot := validIntegrationSnapshot("snapshot-cloud-a", "", now)
	snapshotBody, err := json.Marshal(snapshot.Metadata)
	if err != nil {
		t.Fatalf("marshal snapshot metadata: %v", err)
	}
	snapshotRef, err := cloudProvider.PutObject(ctx, profilesync.CloudSyncObject{ProfileNamespace: "profile-a", ObjectID: "snapshot-cloud-a", Kind: profilesync.CloudObjectSnapshotMetadata, Body: snapshotBody, CreatedAt: now, Metadata: map[string]string{"source": "integration"}})
	if err != nil {
		t.Fatalf("PutObject snapshot returned error: %v", err)
	}
	manifest, err := profilesync.NormalizeCloudManifest(profilesync.CloudProfileManifest{SchemaVersion: profilesync.CloudManifestSchemaVersion, ProfileNamespace: "profile-a", ManifestID: "manifest-cloud-a", Generation: 1, CreatedAt: now, LatestSnapshotRef: &snapshotRef, SignerDeviceID: "device-a", SignerKeyFingerprint: strings.Repeat("b", 64)})
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
		t.Fatalf("CompareCloudManifests missing local = %+v", comparison)
	}

	storeA := profilesync.NewMemoryMetadataStore()
	storeA.SetLocalSnapshot(snapshot)
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
	storeB.SetLocalSnapshot(validIntegrationSnapshot("snapshot-local-b", "snapshot-cloud-a", now))
	transportB, err := profilesync.NewRelaySyncTransport(profilesync.RelaySyncTransportConfig{Provider: relayClient, Namespace: "profile-a", SourceDeviceID: "device-b", TargetDeviceID: "device-a", Mailbox: mailboxB, Clock: clock})
	if err != nil {
		t.Fatalf("NewRelaySyncTransport B returned error: %v", err)
	}
	managerB, err := profilesync.NewSyncManager(
		profilesync.SyncConfig{Enabled: true, ProfileNamespace: "profile-a", LocalDeviceID: "device-b"},
		profilesync.WithSnapshotStore(storeB),
		profilesync.WithProposalStore(storeB),
		profilesync.WithTransport(transportB),
		profilesync.WithTrustVerifier(integrationTrust{trusted: true}),
		profilesync.WithClock(clock),
	)
	if err != nil {
		t.Fatalf("NewSyncManager B returned error: %v", err)
	}

	push, err := managerA.PushLocalSnapshot(ctx)
	if err != nil || push.PushedSnapshots != 1 || len(push.Receipts) != 1 || !push.Receipts[0].Accepted {
		t.Fatalf("PushLocalSnapshot = %+v, %v", push, err)
	}
	pull, err := managerB.PullRemote(ctx)
	if err != nil || pull.ReceivedSnapshots != 1 || pull.ReviewRequired {
		t.Fatalf("PullRemote = %+v, %v", pull, err)
	}
	records, err := storeB.ListRemoteSnapshots(ctx)
	if err != nil || len(records) != 1 || records[0].Snapshot.Metadata.SnapshotID != "snapshot-cloud-a" {
		t.Fatalf("remote snapshots = %+v, %v", records, err)
	}
	if records[0].TrustState != profilesync.TrustTrusted || records[0].RequiresReview {
		t.Fatalf("relay/cloud proof should rely on explicit trust verifier, not relay delivery alone: %+v", records[0])
	}

	assertIntegrationSafeJSON(t, push)
	assertIntegrationSafeJSON(t, pull)
	assertIntegrationSafeJSON(t, verification)
	assertIntegrationSafeJSON(t, comparison)
	assertIntegrationSafeJSON(t, cloudProvider.GetStatus(ctx))
	assertIntegrationSafeJSON(t, relayClient.GetStatus(ctx))
}

func TestRelayCloudIntegrationFailureModesRemainReviewOrDegraded(t *testing.T) {
	ctx := context.Background()
	now := time.Now().UTC()
	clock := integrationClock{now: now}
	provider := newIntegrationFileObjectProvider(t, now)

	ref, err := provider.PutObject(ctx, profilesync.CloudSyncObject{ProfileNamespace: "profile-a", ObjectID: "snapshot-integrated", Kind: profilesync.CloudObjectSnapshotMetadata, Body: []byte(`{"snapshot_id":"snapshot-integrated"}`), CreatedAt: now})
	if err != nil {
		t.Fatalf("PutObject returned error: %v", err)
	}
	local := validIntegrationManifest(t, "manifest-local", 2, now, &ref)
	stale := validIntegrationManifest(t, "manifest-stale", 1, now.Add(-time.Minute), &ref)
	future := validIntegrationManifest(t, "manifest-future", 3, now.Add(3*time.Minute), &ref)
	conflict := validIntegrationManifest(t, "manifest-conflict", 2, now, &ref)
	for _, tc := range []struct {
		name string
		got  profilesync.CloudManifestComparison
		want profilesync.CloudManifestRelation
	}{
		{"stale manifest", profilesync.CompareCloudManifests(&local, stale, now), profilesync.CloudManifestRemoteStale},
		{"future manifest", profilesync.CompareCloudManifests(&local, future, now), profilesync.CloudManifestRemoteFutureDated},
		{"same generation conflict", profilesync.CompareCloudManifests(&local, conflict, now), profilesync.CloudManifestSameGenerationConflict},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if tc.got.Relation != tc.want || !tc.got.ReviewRequired {
				t.Fatalf("comparison = %+v, want %s review-required", tc.got, tc.want)
			}
			assertIntegrationSafeJSON(t, tc.got)
		})
	}

	missingRef := ref
	missingRef.ObjectID = "snapshot-missing"
	missingRef.Hash = strings.Repeat("c", 64)
	missingManifest, err := profilesync.NormalizeCloudManifest(profilesync.CloudProfileManifest{SchemaVersion: profilesync.CloudManifestSchemaVersion, ProfileNamespace: "profile-a", ManifestID: "manifest-missing-ref", Generation: 3, CreatedAt: now, LatestSnapshotRef: &missingRef})
	if err != nil {
		t.Fatalf("NormalizeCloudManifest missing ref fixture returned error: %v", err)
	}
	verification := profilesync.VerifyCloudManifestObjects(ctx, provider, missingManifest)
	if verification.Verified || verification.MissingObjects != 1 {
		t.Fatalf("missing referenced object verification = %+v", verification)
	}
	assertIntegrationSafeJSON(t, verification)

	if _, err := provider.PutObject(ctx, profilesync.CloudSyncObject{ProfileNamespace: "profile-a", ObjectID: ref.ObjectID, Kind: ref.Kind, Body: []byte("different metadata body"), CreatedAt: now}); !errors.Is(err, profilesync.ErrCloudObjectConflict) {
		t.Fatalf("duplicate object conflict error = %v", err)
	}

	relayHandler, err := relay.NewHTTPRelayHandler(relay.HTTPRelayHandlerConfig{ProviderID: "network-relay-integration", Clock: clock, AllowUnauthenticated: true})
	if err != nil {
		t.Fatalf("NewHTTPRelayHandler returned error: %v", err)
	}
	relayServer := httptest.NewServer(relayHandler)
	relayClient, err := relay.NewHTTPRelayClient(relay.HTTPRelayClientConfig{BaseURL: relayServer.URL, ProviderID: "network-relay-integration"})
	if err != nil {
		t.Fatalf("NewHTTPRelayClient returned error: %v", err)
	}
	relayServer.Close()
	transport, err := profilesync.NewRelaySyncTransport(profilesync.RelaySyncTransportConfig{Provider: relayClient, Namespace: "profile-a", SourceDeviceID: "device-a", TargetMailboxID: "mailbox-closed", Clock: clock})
	if err != nil {
		t.Fatalf("NewRelaySyncTransport returned error: %v", err)
	}
	status := transport.GetStatus(ctx)
	if status.Available || len(status.Issues) == 0 {
		t.Fatalf("closed relay should degrade transport status: %+v", status)
	}
	assertIntegrationSafeJSON(t, status)
	assertRelayCloudTextSafe(t, profilesync.ErrCloudObjectConflict.Error())
}

type integrationClock struct {
	now time.Time
}

func (c integrationClock) Now() time.Time {
	return c.now
}

type integrationTrust struct {
	trusted bool
}

func (s integrationTrust) VerifySigner(context.Context, string, string) profilesync.TrustDecision {
	if s.trusted {
		return profilesync.TrustDecision{Trusted: true}
	}
	return profilesync.TrustDecision{Trusted: false, Code: "untrusted_signer", Message: "signer is not trusted"}
}

func validIntegrationSnapshot(snapshotID, parentID string, now time.Time) profilemesh.SignedProfileSnapshot {
	return profilemesh.SignedProfileSnapshot{
		Metadata: profilemesh.ProfileSnapshotMetadata{
			SchemaVersion:       1,
			ProfileNamespace:    "profile-a",
			ProfileID:           "profile-1",
			SnapshotID:          snapshotID,
			SnapshotFingerprint: strings.Repeat("a", 64),
			ParentSnapshotID:    parentID,
			SourceDeviceID:      "device-a",
			HostingMode:         profilemesh.HostingSingleProfileDevice,
			CreatedAt:           now.Add(-time.Minute),
			UpdatedAt:           now,
			ExpiresAt:           now.Add(time.Hour),
			MetadataVersion:     1,
		},
		Signature: profilemesh.SnapshotSignatureSummary{
			SignerDeviceID:       "device-a",
			SignerKeyFingerprint: strings.Repeat("b", 64),
			SignatureFingerprint: strings.Repeat("c", 64),
			Algorithm:            "ed25519-summary",
			SignedAt:             now,
		},
	}
}

func validIntegrationManifest(t *testing.T, manifestID string, generation int64, createdAt time.Time, snapshotRef *profilesync.CloudObjectRef) profilesync.CloudProfileManifest {
	t.Helper()
	manifest, err := profilesync.NormalizeCloudManifest(profilesync.CloudProfileManifest{SchemaVersion: profilesync.CloudManifestSchemaVersion, ProfileNamespace: "profile-a", ManifestID: manifestID, Generation: generation, CreatedAt: createdAt, LatestSnapshotRef: snapshotRef})
	if err != nil {
		t.Fatalf("NormalizeCloudManifest returned error: %v", err)
	}
	return manifest
}

func newIntegrationFileObjectProvider(t *testing.T, now time.Time) *profilesync.FileObjectProvider {
	t.Helper()
	provider, err := profilesync.NewFileObjectProvider(profilesync.FileObjectProviderConfig{RootDir: t.TempDir(), ProfileNamespace: "profile-a", ProviderID: "file-object-integration", Clock: integrationClock{now: now}})
	if err != nil {
		t.Fatalf("NewFileObjectProvider returned error: %v", err)
	}
	return provider
}

func assertIntegrationSafeJSON(t *testing.T, v any) {
	t.Helper()
	raw, err := json.Marshal(v)
	if err != nil {
		t.Fatalf("json marshal failed: %v", err)
	}
	assertRelayCloudTextSafe(t, string(raw))
}

func assertRelayCloudTextSafe(t *testing.T, raw string) {
	t.Helper()
	text := strings.ToLower(raw)
	for _, forbidden := range []string{"client_secret", "refresh_token", "access_token", "id_token", "auth_code", "private_key", "token=", "password=", "secret=", `c:\\users\\`, "appdata", "downloads", "different metadata body", "snapshot_id"} {
		if strings.Contains(text, forbidden) {
			t.Fatalf("unsafe relay/cloud detail %q in %s", forbidden, raw)
		}
	}
}

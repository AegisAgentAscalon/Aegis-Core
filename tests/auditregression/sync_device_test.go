//go:build auditregression

// Read-only audit reproductions. Run from the Aegis-Core module with go run.
// This writes only unique temporary directories and uses a loopback httptest server.
package auditregression

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/AegisAgentAscalon/aegis-core/pkg/devicelink"
	"github.com/AegisAgentAscalon/aegis-core/pkg/profilemesh"
	"github.com/AegisAgentAscalon/aegis-core/pkg/profilesync"
	"github.com/AegisAgentAscalon/aegis-core/pkg/relay"
)

func TestSyncDeviceAudit(t *testing.T) {
	must := func(err error) {
		t.Helper()
		if err != nil {
			t.Fatal(err)
		}
	}
	ctx := context.Background()
	now := time.Now().UTC()
	root := t.TempDir()

	cloud, err := profilesync.NewFileObjectProvider(profilesync.FileObjectProviderConfig{RootDir: root + "/cloud", ProfileNamespace: "audit"})
	must(err)
	object := profilesync.CloudSyncObject{ProfileNamespace: "audit", ObjectID: "a:b", Kind: profilesync.CloudObjectSnapshotMetadata, Body: []byte(`{"x":1}`), CreatedAt: now}
	first, err := cloud.PutObject(ctx, object)
	must(err)
	object.ObjectID = "a_b"
	_, err = cloud.PutObject(ctx, object)
	must(err)
	_, firstErr := cloud.GetObject(ctx, first)
	refs, err := cloud.ListObjects(ctx, profilesync.CloudObjectQuery{ProfileNamespace: "audit"})
	must(err)
	if firstErr != nil || len(refs) != 2 {
		t.Errorf("SD-01: colliding object IDs: retrieval=%v count=%d", firstErr, len(refs))
	}

	provider, err := relay.NewLocalDevProvider(relay.LocalDevProviderConfig{})
	must(err)
	handler, err := relay.NewHTTPRelayHandler(relay.HTTPRelayHandlerConfig{Provider: provider, AllowUnauthenticated: true})
	must(err)
	server := httptest.NewServer(handler)
	defer server.Close()
	client, err := relay.NewHTTPRelayClient(relay.HTTPRelayClientConfig{BaseURL: server.URL})
	must(err)
	mailbox, err := client.OpenMailbox(ctx, relay.MailboxOpenRequest{Namespace: "audit", MailboxID: "inbox", OwnerDeviceID: "owner", CreatedAt: now, ExpiresAt: now.Add(time.Hour)})
	must(err)
	for i := 0; i < 2; i++ {
		body := bytes.Repeat([]byte("x"), 60000)
		_, err = client.SendEnvelope(ctx, relay.RelayEnvelope{RelayEnvelopeMetadata: relay.RelayEnvelopeMetadata{ProtocolVersion: relay.ProtocolVersion, Namespace: "audit", SourceDeviceID: "sender", TargetMailboxID: "inbox", MessageKind: relay.MessageKindOpaque, MessageID: fmt.Sprintf("m%d", i), CreatedAt: now, ExpiresAt: now.Add(time.Hour), PayloadHash: relay.PayloadSHA256(body)}, Payload: body})
		must(err)
	}
	received, receiveErr := client.ReceiveEnvelopes(ctx, mailbox)
	retry, retryErr := client.ReceiveEnvelopes(ctx, mailbox)
	if len(received)+len(retry) != 2 || retryErr != nil {
		t.Errorf("SD-02: accepted HTTP batch lost: first=%v retry=%v total=%d", receiveErr, retryErr, len(received)+len(retry))
	}

	syncbox, err := provider.OpenMailbox(ctx, relay.MailboxOpenRequest{Namespace: "audit", MailboxID: "sync-inbox", OwnerDeviceID: "owner", CreatedAt: now, ExpiresAt: now.Add(time.Hour)})
	must(err)
	transport, err := profilesync.NewReceiveOnlyRelaySyncTransport(profilesync.RelaySyncTransportConfig{Provider: provider, Namespace: "audit", SourceDeviceID: "owner", Mailbox: syncbox})
	must(err)
	store := profilesync.NewMemoryMetadataStore()
	snapshot := profilemesh.SignedProfileSnapshot{Metadata: profilemesh.ProfileSnapshotMetadata{ProfileNamespace: "audit", ProfileID: "profile", SnapshotID: "snapshot", SnapshotFingerprint: strings.Repeat("a", 64), SourceDeviceID: "sender", CreatedAt: now, UpdatedAt: now}, Signature: profilemesh.SnapshotSignatureSummary{SignerDeviceID: "sender"}}
	store.SetLocalSnapshot(snapshot)
	manager, err := profilesync.NewSyncManager(profilesync.SyncConfig{Enabled: true, ProfileNamespace: "audit", LocalDeviceID: "owner"}, profilesync.WithSnapshotStore(store), profilesync.WithTransport(transport))
	must(err)
	payload, err := json.Marshal(profilesync.SyncEnvelope{SchemaVersion: 1, Kind: profilesync.EnvelopeKindSnapshot, ProfileNamespace: "audit", SourceDeviceID: "sender", MessageID: "sync-message", CreatedAt: now, Snapshot: &snapshot})
	must(err)
	_, err = provider.SendEnvelope(ctx, relay.RelayEnvelope{RelayEnvelopeMetadata: relay.RelayEnvelopeMetadata{ProtocolVersion: 1, Namespace: "audit", SourceDeviceID: "sender", TargetMailboxID: "sync-inbox", MessageKind: relay.MessageKindOpaque, MessageID: "sync-message", CreatedAt: now, ExpiresAt: now.Add(time.Hour), PayloadHash: relay.PayloadSHA256(payload)}, Payload: payload})
	must(err)
	store.SetError(fmt.Errorf("temporary store failure"))
	_, syncErr := manager.PullRemote(ctx)
	store.SetError(nil)
	secondPull, secondErr := manager.PullRemote(ctx)
	if syncErr == nil {
		t.Fatal("expected injected store failure")
	}
	if secondErr != nil || secondPull.ReceivedSnapshots != 1 {
		t.Errorf("SD-03: sync payload lost after store failure: retry=%v received=%d", secondErr, secondPull.ReceivedSnapshots)
	}

	mailbox, err = provider.OpenMailbox(ctx, relay.MailboxOpenRequest{Namespace: "victim", MailboxID: "victim-inbox", OwnerDeviceID: "owner", CreatedAt: now, ExpiresAt: now.Add(time.Hour)})
	must(err)
	_, err = provider.ListEndpointHints(ctx, relay.EndpointHintQuery{Namespace: "unrelated", Now: now.Add(24 * time.Hour)})
	must(err)
	_, queryErr := provider.ReceiveEnvelopes(ctx, mailbox)
	if queryErr != nil {
		t.Errorf("SD-04: unrelated query removed mailbox: %v", queryErr)
	}

	mesh, err := profilemesh.NewService(profilemesh.AppConfig{AppID: "audit", DisplayName: "Audit", Namespace: "audit", DataDir: root + "/mesh"})
	must(err)
	_, err = mesh.BootstrapProfile(ctx, profilemesh.BootstrapProfileRequest{ProfileID: "profile"})
	must(err)
	for _, id := range []string{"device-a", "device-b"} {
		_, err = mesh.RegisterProfileDeviceStrict(ctx, profilemesh.RegisterProfileDeviceRequest{DeviceID: id, PublicKeyFingerprint: strings.Repeat("a", 64), TrustStatus: profilemesh.DeviceTrustTrusted, Status: profilemesh.DeviceStatusActive})
		must(err)
	}
	resource, registerErr := mesh.RegisterProfileResource(ctx, profilemesh.RegisterProfileResourceRequest{ResourceID: "resource", ResourceType: profilemesh.ResourceTool, CurrentHostDeviceID: "device-a", AllowedHostDeviceIDs: []string{"device-b"}})
	_, setErr := mesh.SetResourceHost(ctx, profilemesh.SetResourceHostRequest{ResourceID: "resource", DeviceID: "device-a"})
	if registerErr == nil {
		t.Errorf("SD-05: unauthorized initial host accepted: %s (setter error: %v)", resource.CurrentHostDeviceID, setErr)
	}

	meshSnapshot, err := mesh.ExportProfileMeshSnapshot(ctx)
	must(err)
	meshSnapshot.SchemaVersion = 1
	meshSnapshot.SnapshotFingerprint = ""
	meshSnapshot.RelayHints = []profilemesh.ProfileRelayHint{{ProfileID: "profile", DeviceID: "device-a", RelayProviderID: "relay"}}
	meshSnapshot.EndpointHints = []profilemesh.ProfileEndpointHint{{ProfileID: "profile", DeviceID: "device-a", Address: "127.0.0.1"}}
	hintImportErr := mesh.ImportProfileMeshSnapshot(ctx, meshSnapshot)
	reexport, err := mesh.ExportProfileMeshSnapshot(ctx)
	must(err)
	if hintImportErr == nil && (len(reexport.RelayHints) != 1 || len(reexport.EndpointHints) != 1) {
		t.Error("SD-06: accepted snapshot silently lost hints")
	}

	discovery := devicelink.NewMemoryDiscoveryProvider()
	record := devicelink.PresenceRecord{DeviceID: "d", Capabilities: []string{"initial"}}
	must(discovery.Publish(ctx, record))
	record.Capabilities[0] = "mutated_after_publish"
	found, err := discovery.Discover(ctx)
	must(err)
	if len(found) != 1 || len(found[0].Capabilities) != 1 || found[0].Capabilities[0] != "initial" {
		t.Error("SD-08: caller mutation changed discovery record")
	}

	local := profilesync.CloudProfileManifest{SchemaVersion: 1, ProfileNamespace: "profile-a", ManifestID: "ma", Generation: 1, CreatedAt: now}
	remote := profilesync.CloudProfileManifest{SchemaVersion: 1, ProfileNamespace: "profile-b", ManifestID: "mb", Generation: 2, CreatedAt: now}
	comparison := profilesync.CompareCloudManifests(&local, remote, now)
	if comparison.Relation == "remote_newer" {
		t.Error("SD-07: unrelated namespaces compared as remote newer")
	}
}

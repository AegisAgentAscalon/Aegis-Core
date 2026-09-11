//go:build auditregression

// Read-only audit reproductions. Run from the Aegis-Core module with go run.
// This writes only unique temporary directories and uses a loopback httptest server.
package auditregression

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
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
	// Legacy receive deletes before the HTTP response is delivered.
	mailboxJSON, err := json.Marshal(mailbox)
	must(err)
	handler.ServeHTTP(failedResponseWriter{httptest.NewRecorder()}, httptest.NewRequest(http.MethodPost, "/envelopes/receive", bytes.NewReader(mailboxJSON)))
	received, receiveErr := client.ReceiveEnvelopes(ctx, mailbox)
	retry, retryErr := client.ReceiveEnvelopes(ctx, mailbox)
	if len(received)+len(retry) != 2 || retryErr != nil {
		t.Errorf("SD-02: accepted HTTP batch lost after response failure: first=%v retry=%v total=%d", receiveErr, retryErr, len(received)+len(retry))
	}

	syncbox, err := provider.OpenMailbox(ctx, relay.MailboxOpenRequest{Namespace: "audit", MailboxID: "sync-inbox", OwnerDeviceID: "owner", CreatedAt: now, ExpiresAt: now.Add(time.Hour)})
	must(err)
	transport, err := profilesync.NewReceiveOnlyRelaySyncTransport(profilesync.RelaySyncTransportConfig{Provider: provider, Namespace: "audit", SourceDeviceID: "owner", Mailbox: syncbox})
	must(err)
	store := &failingRemoteWriteStore{MemoryMetadataStore: profilesync.NewMemoryMetadataStore()}
	snapshot := profilemesh.SignedProfileSnapshot{Metadata: profilemesh.ProfileSnapshotMetadata{ProfileNamespace: "audit", ProfileID: "profile", SnapshotID: "snapshot", SnapshotFingerprint: strings.Repeat("a", 64), SourceDeviceID: "sender", CreatedAt: now, UpdatedAt: now}, Signature: profilemesh.SnapshotSignatureSummary{SignerDeviceID: "sender"}}
	store.SetLocalSnapshot(snapshot)
	manager, err := profilesync.NewSyncManager(profilesync.SyncConfig{Enabled: true, ProfileNamespace: "audit", LocalDeviceID: "owner"}, profilesync.WithSnapshotStore(store), profilesync.WithTransport(transport))
	must(err)
	payload, err := json.Marshal(profilesync.SyncEnvelope{SchemaVersion: 1, Kind: profilesync.EnvelopeKindSnapshot, ProfileNamespace: "audit", SourceDeviceID: "sender", MessageID: "sync-message", CreatedAt: now, Snapshot: &snapshot})
	must(err)
	_, err = provider.SendEnvelope(ctx, relay.RelayEnvelope{RelayEnvelopeMetadata: relay.RelayEnvelopeMetadata{ProtocolVersion: 1, Namespace: "audit", SourceDeviceID: "sender", TargetMailboxID: "sync-inbox", MessageKind: relay.MessageKindOpaque, MessageID: "sync-message", CreatedAt: now, ExpiresAt: now.Add(time.Hour), PayloadHash: relay.PayloadSHA256(payload)}, Payload: payload})
	must(err)
	store.fail = true
	_, syncErr := manager.PullRemote(ctx)
	store.fail = false
	secondPull, secondErr := manager.PullRemote(ctx)
	if syncErr == nil {
		t.Fatal("expected injected store failure")
	}
	if secondErr != nil || secondPull.ReceivedSnapshots != 1 {
		t.Errorf("SD-03: sync payload lost after remote write failure: retry=%v received=%d", secondErr, secondPull.ReceivedSnapshots)
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

}

// W04a covers preflight reads, not durable acceptance after destructive receive.
type failingRemoteWriteStore struct {
	*profilesync.MemoryMetadataStore
	fail bool
}

func (s *failingRemoteWriteStore) SaveRemoteSnapshot(ctx context.Context, record profilesync.RemoteSnapshotRecord) error {
	if s.fail {
		return fmt.Errorf("temporary remote write failure")
	}
	return s.MemoryMetadataStore.SaveRemoteSnapshot(ctx, record)
}

type failedResponseWriter struct{ http.ResponseWriter }

func (w failedResponseWriter) Write([]byte) (int, error) {
	return 0, fmt.Errorf("response disconnected")
}

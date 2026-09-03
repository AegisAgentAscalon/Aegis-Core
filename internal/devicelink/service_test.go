package devicelink

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"os"
	"strings"
	"sync"
	"testing"
	"time"
)

func testConfig(t *testing.T, name string) AppConfig {
	t.Helper()
	return AppConfig{AppID: "sample-app", DisplayName: "Sample App", DataDir: t.TempDir(), Namespace: name}
}

func newTestService(t *testing.T, name string, opts ...Option) *Service {
	t.Helper()
	svc, err := NewService(testConfig(t, name), opts...)
	if err != nil {
		t.Fatal(err)
	}
	return svc
}

type testClock struct {
	mu  sync.Mutex
	now time.Time
}

func (c *testClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.now
}

func (c *testClock) Add(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.now = c.now.Add(d)
}

func TestValidateConfigRejectsUnsafeNames(t *testing.T) {
	cases := []AppConfig{
		{AppID: "", DisplayName: "App", DataDir: t.TempDir(), Namespace: "safe"},
		{AppID: "../bad", DisplayName: "App", DataDir: t.TempDir(), Namespace: "safe"},
		{AppID: "bad/app", DisplayName: "App", DataDir: t.TempDir(), Namespace: "safe"},
		{AppID: "safe", DisplayName: "", DataDir: t.TempDir(), Namespace: "safe"},
		{AppID: "safe", DisplayName: "App", DataDir: "", Namespace: "safe"},
		{AppID: "safe", DisplayName: "App", DataDir: t.TempDir(), Namespace: ""},
		{AppID: "safe", DisplayName: "App", DataDir: t.TempDir(), Namespace: "..\\bad"},
		{AppID: "safe", DisplayName: "App", DataDir: t.TempDir(), Namespace: "bad/ns"},
		{AppID: "safe", DisplayName: "App", DataDir: t.TempDir(), Namespace: "CON"},
		{AppID: "safe", DisplayName: "App", DataDir: t.TempDir(), Namespace: strings.Repeat("a", 129)},
	}
	for _, cfg := range cases {
		if err := ValidateConfig(cfg); err == nil {
			t.Fatalf("expected config error for %+v", cfg)
		}
	}
	if err := ValidateConfig(AppConfig{AppID: "Aegis.Sample_01", DisplayName: "App", DataDir: t.TempDir(), Namespace: "User-01.profile"}); err != nil {
		t.Fatalf("expected safe config, got %v", err)
	}
}

func TestBootstrapCurrentDeviceCreatesIdentityKeypairAndIsIdempotent(t *testing.T) {
	svc := newTestService(t, "profile-a")
	first, err := svc.BootstrapCurrentDevice(context.Background(), BootstrapDeviceRequest{DisplayName: "Laptop", Capabilities: []string{"services", "services", "tools"}})
	if err != nil {
		t.Fatal(err)
	}
	second, err := svc.BootstrapCurrentDevice(context.Background(), BootstrapDeviceRequest{DisplayName: "Other"})
	if err != nil {
		t.Fatal(err)
	}
	if first.DeviceID != second.DeviceID || first.PublicKeyFingerprint != second.PublicKeyFingerprint {
		t.Fatalf("bootstrap should be idempotent")
	}
	raw, _ := json.Marshal(first)
	if strings.Contains(strings.ToLower(string(raw)), "private") {
		t.Fatalf("public identity exposed private data: %s", string(raw))
	}
	if _, err := decodePublicKey(first.PublicKey); err != nil {
		t.Fatalf("expected valid public key: %v", err)
	}

	other := newTestService(t, "profile-b")
	third, err := other.BootstrapCurrentDevice(context.Background(), BootstrapDeviceRequest{DisplayName: "Desktop"})
	if err != nil {
		t.Fatal(err)
	}
	if first.DeviceID == third.DeviceID || first.PublicKeyFingerprint == third.PublicKeyFingerprint {
		t.Fatalf("two devices should have distinct identities")
	}
}

func TestInspectBootstrapIsSideEffectFreeAndValidatesKeypair(t *testing.T) {
	cfg := testConfig(t, "inspect")
	storageDir := storeForConfig(cfg).dir
	status, err := InspectBootstrap(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if status.State != BootstrapAbsent || status.Ready || status.Bootstrapped {
		t.Fatalf("unexpected absent bootstrap status: %+v", status)
	}
	if _, err := os.Stat(storageDir); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("inspection created storage or returned an unexpected stat error: %v", err)
	}

	svc, err := NewService(cfg)
	if err != nil {
		t.Fatal(err)
	}
	identity, err := svc.BootstrapCurrentDevice(context.Background(), BootstrapDeviceRequest{})
	if err != nil {
		t.Fatal(err)
	}
	status, err = InspectBootstrap(cfg)
	if err != nil || !status.Ready || !status.Bootstrapped || status.State != BootstrapReady || status.DeviceID != identity.DeviceID {
		t.Fatalf("unexpected ready bootstrap status: %+v %v", status, err)
	}
	if err := os.Remove(svc.store.privateKeyPath()); err != nil {
		t.Fatal(err)
	}
	status, err = InspectBootstrap(cfg)
	if err != nil || status.State != BootstrapPartial || status.Ready {
		t.Fatalf("unexpected partial bootstrap status: %+v %v", status, err)
	}
	_, replacementPrivateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	if err := svc.store.writePrivateKey(base64.RawStdEncoding.EncodeToString(replacementPrivateKey)); err != nil {
		t.Fatal(err)
	}
	status, err = InspectBootstrap(cfg)
	if err != nil || status.State != BootstrapInvalid || status.Ready {
		t.Fatalf("unexpected mismatched-key bootstrap status: %+v %v", status, err)
	}
	if _, err := svc.BootstrapCurrentDevice(context.Background(), BootstrapDeviceRequest{}); !errors.Is(err, ErrStorageUnavailable) {
		t.Fatalf("bootstrap accepted mismatched identity keypair: %v", err)
	}
}

func TestPublicIdentityBundleExportAndValidation(t *testing.T) {
	svc := newTestService(t, "identity-bundle")
	if _, err := svc.BootstrapCurrentDevice(context.Background(), BootstrapDeviceRequest{Capabilities: []string{"tools", "services"}}); err != nil {
		t.Fatal(err)
	}
	bundle, err := svc.ExportPublicIdentityBundle(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if bundle.PublicKey == "" || bundle.BundleFingerprint == "" {
		t.Fatalf("public identity bundle omitted exchange material: %+v", bundle)
	}
	if err := ValidatePublicIdentityBundle(bundle); err != nil {
		t.Fatalf("valid bundle rejected: %v", err)
	}
	tampered := bundle
	tampered.Capabilities = append(tampered.Capabilities, "runtime")
	if err := ValidatePublicIdentityBundle(tampered); !errors.Is(err, ErrInvalidIdentityBundle) {
		t.Fatalf("tampered bundle error = %v, want ErrInvalidIdentityBundle", err)
	}
}

func TestCurrentDeviceCorruptOrMissingKeyFailsSafely(t *testing.T) {
	svc := newTestService(t, "profile-a")
	if _, err := svc.BootstrapCurrentDevice(context.Background(), BootstrapDeviceRequest{}); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(svc.store.identityPath(), []byte(`{bad-json`), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := svc.GetCurrentDevice(context.Background()); !errors.Is(err, ErrStorageUnavailable) {
		t.Fatalf("expected safe corrupt identity error, got %v", err)
	}
	if strings.Contains(errString(svc.GetCurrentDevice(context.Background())), svc.store.dir) {
		t.Fatalf("error leaked path")
	}

	svc = newTestService(t, "profile-b")
	if _, err := svc.BootstrapCurrentDevice(context.Background(), BootstrapDeviceRequest{}); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(svc.store.privateKeyPath()); err != nil {
		t.Fatal(err)
	}
	peer := makeTrustRequest(t, "peer")
	if _, err := svc.TrustDevice(context.Background(), peer); err != nil {
		t.Fatal(err)
	}
	if _, err := svc.SignHandshakeChallenge(context.Background(), HandshakeChallengeRequest{Challenge: "abc", ChallengerDeviceID: peer.DeviceID}); !errors.Is(err, ErrCurrentDeviceNotFound) {
		t.Fatalf("expected missing key error, got %v", err)
	}
}

func TestTrustRegistryLifecycleAndSnapshotValidation(t *testing.T) {
	svc := newTestService(t, "profile-a")
	peer := makeTrustRequest(t, "peer-1")
	trusted, err := svc.TrustDevice(context.Background(), peer)
	if err != nil {
		t.Fatal(err)
	}
	if trusted.TrustStatus != TrustTrusted {
		t.Fatalf("expected trusted, got %+v", trusted)
	}
	again, err := svc.TrustDevice(context.Background(), peer)
	if err != nil || again.DeviceID != trusted.DeviceID {
		t.Fatalf("duplicate same key should update safely: %+v %v", again, err)
	}
	conflict := makeTrustRequest(t, "peer-1")
	if _, err := svc.TrustDevice(context.Background(), conflict); !errors.Is(err, ErrDeviceAlreadyExists) {
		t.Fatalf("expected conflict error, got %v", err)
	}
	bad := peer
	bad.PublicKey = "not-public-key"
	if _, err := svc.TrustDevice(context.Background(), bad); !errors.Is(err, ErrInvalidPublicKey) {
		t.Fatalf("expected invalid public key, got %v", err)
	}
	if err := svc.RevokeDevice(context.Background(), "missing"); !errors.Is(err, ErrDeviceNotFound) {
		t.Fatalf("expected missing revoke error, got %v", err)
	}
	if err := svc.RevokeDevice(context.Background(), peer.DeviceID); err != nil {
		t.Fatal(err)
	}
	status, err := svc.GetDeviceTrustStatus(context.Background(), peer.DeviceID)
	if err != nil || status.TrustStatus != TrustRevoked {
		t.Fatalf("expected revoked status, got %+v %v", status, err)
	}

	snap, err := svc.ExportRegistrySnapshot(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if snap.Purpose != RegistrySnapshotLocalBackup {
		t.Fatalf("registry export purpose = %q, want local backup", snap.Purpose)
	}
	other := newTestService(t, "profile-a")
	if err := other.ImportRegistrySnapshot(context.Background(), snap); err != nil {
		t.Fatal(err)
	}
	if err := other.ImportRegistrySnapshot(context.Background(), snap); err != nil {
		t.Fatalf("valid snapshot fingerprint should import repeatedly: %v", err)
	}
	tampered := snap
	tampered.SnapshotFingerprint = "tampered"
	if err := other.ImportRegistrySnapshot(context.Background(), tampered); !errors.Is(err, ErrInvalidRegistrySnapshot) {
		t.Fatalf("expected tampered fingerprint rejection, got %v", err)
	}
	notBackup := snap
	notBackup.Purpose = ""
	notBackup.SnapshotFingerprint = snapshotFingerprint(notBackup)
	if err := other.ImportRegistrySnapshot(context.Background(), notBackup); !errors.Is(err, ErrInvalidRegistrySnapshot) {
		t.Fatalf("expected non-backup import rejection, got %v", err)
	}
	snap.Namespace = "wrong"
	if err := other.ImportRegistrySnapshot(context.Background(), snap); !errors.Is(err, ErrInvalidRegistrySnapshot) {
		t.Fatalf("expected wrong namespace error, got %v", err)
	}
}

func TestRegistryFingerprintCoversTrustCapabilityAndTimestampFields(t *testing.T) {
	publicKey, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC().Truncate(time.Second)
	revokedAt := now.Add(2 * time.Minute)
	base := RegistrySnapshot{
		SchemaVersion:          RegistrySnapshotSchemaVersion,
		Purpose:                RegistrySnapshotLocalBackup,
		AppID:                  "sample-app",
		Namespace:              "profile-a",
		CreatedAt:              now,
		UpdatedAt:              now.Add(3 * time.Minute),
		OriginDeviceID:         "device-origin",
		ProfileMetadataVersion: MetadataVersion,
		Devices: []TrustedDevice{{
			DeviceID:               "device-peer",
			DisplayName:            "Peer",
			PublicKey:              encodePublicKey(publicKey),
			PublicKeyFingerprint:   fingerprintPublicKey(publicKey),
			TrustStatus:            TrustRevoked,
			TrustedAt:              now.Add(time.Minute),
			RevokedAt:              &revokedAt,
			LastSeen:               now.Add(90 * time.Second),
			Capabilities:           []string{"services", "tools"},
			ProfileMetadataVersion: MetadataVersion,
		}},
	}
	baseFingerprint := snapshotFingerprint(base)
	tests := map[string]func(*RegistrySnapshot){
		"purpose":                func(s *RegistrySnapshot) { s.Purpose = "other" },
		"created at":             func(s *RegistrySnapshot) { s.CreatedAt = s.CreatedAt.Add(time.Second) },
		"updated at":             func(s *RegistrySnapshot) { s.UpdatedAt = s.UpdatedAt.Add(time.Second) },
		"origin":                 func(s *RegistrySnapshot) { s.OriginDeviceID = "device-other" },
		"snapshot metadata":      func(s *RegistrySnapshot) { s.ProfileMetadataVersion++ },
		"public key":             func(s *RegistrySnapshot) { s.Devices[0].PublicKey += "x" },
		"public key fingerprint": func(s *RegistrySnapshot) { s.Devices[0].PublicKeyFingerprint += "x" },
		"trust status":           func(s *RegistrySnapshot) { s.Devices[0].TrustStatus = TrustTrusted },
		"trusted at":             func(s *RegistrySnapshot) { s.Devices[0].TrustedAt = s.Devices[0].TrustedAt.Add(time.Second) },
		"revoked at": func(s *RegistrySnapshot) {
			value := s.Devices[0].RevokedAt.Add(time.Second)
			s.Devices[0].RevokedAt = &value
		},
		"last seen":                func(s *RegistrySnapshot) { s.Devices[0].LastSeen = s.Devices[0].LastSeen.Add(time.Second) },
		"capabilities":             func(s *RegistrySnapshot) { s.Devices[0].Capabilities = append(s.Devices[0].Capabilities, "runtime") },
		"profile metadata version": func(s *RegistrySnapshot) { s.Devices[0].ProfileMetadataVersion++ },
	}
	for name, mutate := range tests {
		t.Run(name, func(t *testing.T) {
			copy := cloneRegistrySnapshot(t, base)
			mutate(&copy)
			if got := snapshotFingerprint(copy); got == baseFingerprint {
				t.Fatalf("fingerprint did not cover %s", name)
			}
		})
	}
}

func TestTrustMaterialIsNormalizedBeforeStorageAndFingerprinting(t *testing.T) {
	svc := newTestService(t, "normalize-trust")
	req := makeTrustRequest(t, "peer-normalized")
	canonicalKey := req.PublicKey
	canonicalFingerprint := req.PublicKeyFingerprint
	req.PublicKey = "  " + req.PublicKey + "\r\n"
	req.PublicKeyFingerprint = "  " + strings.ToUpper(req.PublicKeyFingerprint) + "  "
	trusted, err := svc.TrustDevice(context.Background(), req)
	if err != nil {
		t.Fatal(err)
	}
	if trusted.PublicKey != canonicalKey || trusted.PublicKeyFingerprint != canonicalFingerprint {
		t.Fatalf("trust material was not normalized: %+v", trusted)
	}

	snapshot, err := svc.ExportRegistrySnapshot(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	snapshot.Devices[0].PublicKey = "\t" + snapshot.Devices[0].PublicKey + " "
	snapshot.Devices[0].PublicKeyFingerprint = strings.ToUpper(snapshot.Devices[0].PublicKeyFingerprint)
	if snapshotFingerprint(snapshot) != snapshot.SnapshotFingerprint {
		t.Fatal("semantically identical trust material changed the canonical fingerprint")
	}
	other := newTestService(t, "normalize-trust")
	if err := other.ImportRegistrySnapshot(context.Background(), snapshot); err != nil {
		t.Fatal(err)
	}
	devices, err := other.ListTrustedDevices(context.Background())
	if err != nil || len(devices) != 1 || devices[0].PublicKey != canonicalKey || devices[0].PublicKeyFingerprint != canonicalFingerprint {
		t.Fatalf("registry import did not store canonical trust material: %+v %v", devices, err)
	}
}

func TestResourceAdvertisementValidationAndListing(t *testing.T) {
	svc := newTestService(t, "profile-a")
	if err := svc.AdvertiseResources(context.Background(), ResourceAdvertisementRequest{}); !errors.Is(err, ErrCurrentDeviceNotFound) {
		t.Fatalf("expected current device required, got %v", err)
	}
	id, err := svc.BootstrapCurrentDevice(context.Background(), BootstrapDeviceRequest{})
	if err != nil {
		t.Fatal(err)
	}
	err = svc.AdvertiseResources(context.Background(), ResourceAdvertisementRequest{Resources: []ResourceDescriptor{
		{ResourceID: "service-1", Type: ResourceService, DisplayName: "Service", Tags: []string{"local"}},
		{ResourceID: "tool-1", Type: ResourceTool, DisplayName: "Tool", OwnerDeviceID: id.DeviceID},
	}})
	if err != nil {
		t.Fatal(err)
	}
	res, err := svc.ListLocalResources(context.Background())
	if err != nil || len(res) != 2 {
		t.Fatalf("expected local resources, got %d %v", len(res), err)
	}
	if err := svc.AdvertiseResources(context.Background(), ResourceAdvertisementRequest{Resources: []ResourceDescriptor{{ResourceID: "x", Type: "bad"}}}); !errors.Is(err, ErrInvalidResource) {
		t.Fatalf("expected invalid resource type, got %v", err)
	}
	if err := svc.AdvertiseResources(context.Background(), ResourceAdvertisementRequest{Resources: []ResourceDescriptor{{ResourceID: "x", Type: ResourceService}, {ResourceID: "x", Type: ResourceTool}}}); !errors.Is(err, ErrInvalidResource) {
		t.Fatalf("expected duplicate resource error, got %v", err)
	}
	if err := svc.AdvertiseResources(context.Background(), ResourceAdvertisementRequest{Resources: []ResourceDescriptor{{ResourceID: "x", Type: ResourceService, OwnerDeviceID: "other"}}}); !errors.Is(err, ErrInvalidResource) {
		t.Fatalf("expected wrong owner error, got %v", err)
	}
	if err := os.WriteFile(svc.store.resourcesPath(), []byte(`{bad-json`), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := svc.ListLocalResources(context.Background()); !errors.Is(err, ErrStorageUnavailable) {
		t.Fatalf("expected corrupt resource store error, got %v", err)
	} else if strings.Contains(err.Error(), svc.store.dir) {
		t.Fatalf("resource error leaked path")
	}
}

func TestPresenceDiscoveryTrustAndRemoteResources(t *testing.T) {
	discovery := NewMemoryDiscoveryProvider()
	a := newTestService(t, "mesh", WithDiscoveryProvider(discovery))
	b := newTestService(t, "mesh", WithDiscoveryProvider(discovery))
	aID, _ := a.BootstrapCurrentDevice(context.Background(), BootstrapDeviceRequest{DisplayName: "A"})
	bID, _ := b.BootstrapCurrentDevice(context.Background(), BootstrapDeviceRequest{DisplayName: "B"})
	if err := b.AdvertiseResources(context.Background(), ResourceAdvertisementRequest{Resources: []ResourceDescriptor{{ResourceID: "data", Type: ResourceData, DisplayName: "Data"}}}); err != nil {
		t.Fatal(err)
	}
	if _, err := a.PublishPresence(context.Background()); err != nil {
		t.Fatal(err)
	}
	if _, err := b.PublishPresence(context.Background()); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(a.store.resourcesPath(), []byte(`{bad-json`), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := a.PublishPresence(context.Background()); !errors.Is(err, ErrStorageUnavailable) {
		t.Fatalf("expected corrupt resources to block presence, got %v", err)
	}
	if err := os.Remove(a.store.resourcesPath()); err != nil {
		t.Fatal(err)
	}
	discovery.SetError(errors.New("offline"))
	if _, err := a.DiscoverPeers(context.Background()); !errors.Is(err, ErrDiscoveryUnavailable) {
		t.Fatalf("expected discovery unavailable, got %v", err)
	}
	discovery.SetError(nil)
	peers, err := a.DiscoverPeers(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(a.store.peersPath()); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(a.store.peersPath(), 0o700); err != nil {
		t.Fatal(err)
	}
	if _, err := a.DiscoverPeers(context.Background()); !errors.Is(err, ErrStorageUnavailable) {
		t.Fatalf("expected peer cache write failure, got %v", err)
	}
	if err := os.Remove(a.store.peersPath()); err != nil {
		t.Fatal(err)
	}
	peers, err = a.DiscoverPeers(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(peers) != 1 || peers[0].Presence.DeviceID != bID.DeviceID || peers[0].TrustStatus != TrustUnknown {
		t.Fatalf("expected one unknown non-self peer, got %+v", peers)
	}
	if _, err := a.TrustDevice(context.Background(), TrustDeviceRequest{DeviceID: bID.DeviceID, DisplayName: bID.DisplayName, PublicKey: bID.PublicKey, PublicKeyFingerprint: bID.PublicKeyFingerprint}); err != nil {
		t.Fatal(err)
	}
	peers, _ = a.DiscoverPeers(context.Background())
	if peers[0].TrustStatus != TrustTrusted {
		t.Fatalf("expected trusted discovered peer, got %+v", peers[0])
	}
	remote, err := a.ListKnownRemoteResources(context.Background())
	if err != nil || len(remote) != 1 || remote[0].Type != ResourceData {
		t.Fatalf("expected remote resource summary, got %+v %v", remote, err)
	}
	if err := os.WriteFile(a.store.peersPath(), []byte(`{bad-json`), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := a.ListKnownRemoteResources(context.Background()); !errors.Is(err, ErrStorageUnavailable) {
		t.Fatalf("expected corrupt peer store error, got %v", err)
	}
	if err := a.RevokeDevice(context.Background(), bID.DeviceID); err != nil {
		t.Fatal(err)
	}
	peers, _ = a.DiscoverPeers(context.Background())
	if peers[0].TrustStatus != TrustRevoked {
		t.Fatalf("expected revoked discovered peer, got %+v", peers[0])
	}
	_ = aID
}

func TestDiscoveryProviderCallsMayReenterService(t *testing.T) {
	provider := &reentrantDiscoveryProvider{}
	svc := newTestService(t, "reentrant", WithDiscoveryProvider(provider))
	provider.svc = svc
	if _, err := svc.BootstrapCurrentDevice(context.Background(), BootstrapDeviceRequest{DisplayName: "Local"}); err != nil {
		t.Fatal(err)
	}
	if err := svc.AdvertiseResources(context.Background(), ResourceAdvertisementRequest{Resources: []ResourceDescriptor{{ResourceID: "kb", Type: ResourceData, DisplayName: "KB"}}}); err != nil {
		t.Fatal(err)
	}
	mustFinishDeviceLinkCall(t, func() error {
		_, err := svc.PublishPresence(context.Background())
		return err
	})
	mustFinishDeviceLinkCall(t, func() error {
		_, err := svc.DiscoverPeers(context.Background())
		return err
	})
}

func TestRemoteResourceAvailabilityRequiresFreshTrustedFingerprint(t *testing.T) {
	now := time.Now().UTC()
	peer := PresenceRecord{
		SchemaVersion:        SchemaVersion,
		DeviceID:             "peer",
		LastSeen:             now,
		PublicKeyFingerprint: "sha256:peer",
	}
	if got := remoteResourceAvailability(now, peer, TrustedDevice{}); got != ResourceUnknown {
		t.Fatalf("unknown device availability = %q", got)
	}
	trusted := TrustedDevice{DeviceID: "peer", TrustStatus: TrustTrusted, PublicKeyFingerprint: peer.PublicKeyFingerprint}
	if got := remoteResourceAvailability(now, peer, trusted); got != ResourceAvailable {
		t.Fatalf("fresh trusted availability = %q", got)
	}
	peer.LastSeen = now.Add(defaultFutureSkew + time.Second)
	if got := remoteResourceAvailability(now, peer, trusted); got != ResourceUnavailable {
		t.Fatalf("future-dated presence availability = %q", got)
	}
	peer.LastSeen = now
	trusted.TrustStatus = TrustRevoked
	if got := remoteResourceAvailability(now, peer, trusted); got != ResourceUnavailable {
		t.Fatalf("revoked device availability = %q", got)
	}
}

func TestDeviceLinkRejectsWindowsReservedNamespaceWithExtension(t *testing.T) {
	cfg := testConfig(t, "COM1.log")
	if _, err := NewService(cfg); !errors.Is(err, ErrInvalidNamespace) {
		t.Fatalf("reserved namespace error = %v", err)
	}
}

func TestSignedHandshakeSuccessAndFailures(t *testing.T) {
	discovery := NewMemoryDiscoveryProvider()
	a := newTestService(t, "mesh", WithDiscoveryProvider(discovery))
	b := newTestService(t, "mesh", WithDiscoveryProvider(discovery))
	aID, _ := a.BootstrapCurrentDevice(context.Background(), BootstrapDeviceRequest{DisplayName: "A"})
	bID, _ := b.BootstrapCurrentDevice(context.Background(), BootstrapDeviceRequest{DisplayName: "B"})
	trustBoth(t, a, aID, b, bID)
	if _, err := b.PublishPresence(context.Background()); err != nil {
		t.Fatal(err)
	}
	peers, _ := a.DiscoverPeers(context.Background())
	unknownPeer := DiscoveredPeer{Presence: PresenceRecord{DeviceID: "unknown", PublicKeyFingerprint: "sha256:unknown"}}
	if _, err := a.StartHandshake(context.Background(), unknownPeer); !errors.Is(err, ErrDeviceNotTrusted) {
		t.Fatalf("expected unknown handshake failure, got %v", err)
	}
	badPeer := peers[0]
	badPeer.Presence.PublicKeyFingerprint = "sha256:wrong"
	if _, err := a.StartHandshake(context.Background(), badPeer); !errors.Is(err, ErrFingerprintMismatch) {
		t.Fatalf("expected fingerprint mismatch, got %v", err)
	}
	start, err := a.StartHandshake(context.Background(), peers[0])
	if err != nil {
		t.Fatal(err)
	}
	for _, badID := range []string{"", "../device_private_key", "..\\device_private_key", "/tmp/x", "hs_good/evil"} {
		_, err := a.CompleteHandshake(context.Background(), HandshakeCompleteRequest{SessionID: badID, PeerDeviceID: bID.DeviceID, Signature: "ignored"})
		if !errors.Is(err, ErrInvalidSessionID) {
			t.Fatalf("expected invalid session id for %q, got %v", badID, err)
		}
		if err != nil && strings.Contains(err.Error(), a.store.dir) {
			t.Fatalf("invalid session id error leaked path")
		}
	}
	response, err := b.SignHandshakeChallenge(context.Background(), HandshakeChallengeRequest{ChallengerDeviceID: aID.DeviceID, Challenge: start.Challenge})
	if err != nil {
		t.Fatal(err)
	}
	session, err := a.CompleteHandshake(context.Background(), HandshakeCompleteRequest{SessionID: start.SessionID, PeerDeviceID: bID.DeviceID, Signature: response.Signature})
	if err != nil {
		t.Fatal(err)
	}
	if session.Status != "linked" {
		t.Fatalf("expected linked session, got %+v", session)
	}
	if _, err := a.CompleteHandshake(context.Background(), HandshakeCompleteRequest{SessionID: start.SessionID, PeerDeviceID: bID.DeviceID, Signature: response.Signature}); !errors.Is(err, ErrChallengeReplay) {
		t.Fatalf("expected replay rejection, got %v", err)
	}
	start, _ = a.StartHandshake(context.Background(), peers[0])
	if _, err := a.CompleteHandshake(context.Background(), HandshakeCompleteRequest{SessionID: start.SessionID, PeerDeviceID: bID.DeviceID, Signature: "bad"}); !errors.Is(err, ErrHandshakeFailed) {
		t.Fatalf("expected wrong signature failure, got %v", err)
	}
	otherNamespace := newTestService(t, "other-namespace")
	otherID, _ := otherNamespace.BootstrapCurrentDevice(context.Background(), BootstrapDeviceRequest{DisplayName: "Other"})
	if _, err := otherNamespace.TrustDevice(context.Background(), TrustDeviceRequest{DeviceID: bID.DeviceID, DisplayName: bID.DisplayName, PublicKey: bID.PublicKey, PublicKeyFingerprint: bID.PublicKeyFingerprint}); err != nil {
		t.Fatal(err)
	}
	otherStart, err := otherNamespace.StartHandshake(context.Background(), DiscoveredPeer{Presence: PresenceRecord{DeviceID: bID.DeviceID, PublicKeyFingerprint: bID.PublicKeyFingerprint}})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := b.TrustDevice(context.Background(), TrustDeviceRequest{DeviceID: otherID.DeviceID, DisplayName: otherID.DisplayName, PublicKey: otherID.PublicKey, PublicKeyFingerprint: otherID.PublicKeyFingerprint}); err != nil {
		t.Fatal(err)
	}
	crossContextResponse, err := b.SignHandshakeChallenge(context.Background(), HandshakeChallengeRequest{ChallengerDeviceID: otherID.DeviceID, Challenge: otherStart.Challenge})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := otherNamespace.CompleteHandshake(context.Background(), HandshakeCompleteRequest{SessionID: otherStart.SessionID, PeerDeviceID: bID.DeviceID, Signature: crossContextResponse.Signature}); !errors.Is(err, ErrHandshakeFailed) {
		t.Fatalf("expected cross-namespace signature reuse failure, got %v for other %s", err, otherID.DeviceID)
	}
	start, _ = a.StartHandshake(context.Background(), peers[0])
	if err := os.WriteFile(a.store.handshakePath(start.SessionID), []byte(`{bad-json`), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := a.CompleteHandshake(context.Background(), HandshakeCompleteRequest{SessionID: start.SessionID, PeerDeviceID: bID.DeviceID, Signature: response.Signature}); !errors.Is(err, ErrHandshakeFailed) {
		t.Fatalf("expected corrupt session failure, got %v", err)
	}
	if err := a.RevokeDevice(context.Background(), bID.DeviceID); err != nil {
		t.Fatal(err)
	}
	if _, err := a.StartHandshake(context.Background(), peers[0]); !errors.Is(err, ErrDeviceRevoked) {
		t.Fatalf("expected revoked handshake failure, got %v", err)
	}

	clock := &testClock{now: time.Now().UTC()}
	expiringDiscovery := NewMemoryDiscoveryProvider()
	c := newTestService(t, "expire", WithDiscoveryProvider(expiringDiscovery), WithClock(clock))
	d := newTestService(t, "expire", WithDiscoveryProvider(expiringDiscovery))
	cID, _ := c.BootstrapCurrentDevice(context.Background(), BootstrapDeviceRequest{DisplayName: "C"})
	dID, _ := d.BootstrapCurrentDevice(context.Background(), BootstrapDeviceRequest{DisplayName: "D"})
	trustBoth(t, c, cID, d, dID)
	if _, err := d.PublishPresence(context.Background()); err != nil {
		t.Fatal(err)
	}
	expiringPeers, _ := c.DiscoverPeers(context.Background())
	expiringStart, err := c.StartHandshake(context.Background(), expiringPeers[0])
	if err != nil {
		t.Fatal(err)
	}
	expiringResponse, err := d.SignHandshakeChallenge(context.Background(), HandshakeChallengeRequest{ChallengerDeviceID: cID.DeviceID, Challenge: expiringStart.Challenge})
	if err != nil {
		t.Fatal(err)
	}
	clock.Add(defaultLinkTTL + time.Second)
	if _, err := c.CompleteHandshake(context.Background(), HandshakeCompleteRequest{SessionID: expiringStart.SessionID, PeerDeviceID: dID.DeviceID, Signature: expiringResponse.Signature}); !errors.Is(err, ErrChallengeExpired) {
		t.Fatalf("expected expired challenge, got %v", err)
	}
}

func TestReachabilityDoesNotSatisfyProofAndHandshakePersistsReceipt(t *testing.T) {
	discovery := NewMemoryDiscoveryProvider()
	transport := NewMemoryTransport()
	clock := &testClock{now: time.Now().UTC()}
	a := newTestService(t, "proof", WithDiscoveryProvider(discovery), WithTransport(transport), WithClock(clock))
	b := newTestService(t, "proof", WithDiscoveryProvider(discovery))
	aID, _ := a.BootstrapCurrentDevice(context.Background(), BootstrapDeviceRequest{})
	bID, _ := b.BootstrapCurrentDevice(context.Background(), BootstrapDeviceRequest{})
	trustBoth(t, a, aID, b, bID)
	if _, err := b.PublishPresence(context.Background()); err != nil {
		t.Fatal(err)
	}
	peers, err := a.DiscoverPeers(context.Background())
	if err != nil || len(peers) != 1 {
		t.Fatalf("discover peers: %+v %v", peers, err)
	}
	transport.RegisterHandler(bID.DeviceID, func(context.Context, Message) (Message, error) {
		return Message{Kind: "pong", FromDeviceID: bID.DeviceID}, nil
	})
	if _, err := a.TestLink(context.Background(), bID.DeviceID); err != nil {
		t.Fatal(err)
	}
	evaluation, err := a.EvaluateProof(context.Background(), bID.DeviceID)
	if err != nil {
		t.Fatal(err)
	}
	if !evaluation.Reachable || evaluation.Satisfied || evaluation.State != ProofStateUnverified || evaluation.Receipt != nil {
		t.Fatalf("reachability was incorrectly treated as proof: %+v", evaluation)
	}

	start, err := a.StartHandshake(context.Background(), peers[0])
	if err != nil {
		t.Fatal(err)
	}
	response, err := b.SignHandshakeChallenge(context.Background(), HandshakeChallengeRequest{ChallengerDeviceID: aID.DeviceID, Challenge: start.Challenge})
	if err != nil {
		t.Fatal(err)
	}
	session, err := a.CompleteHandshake(context.Background(), HandshakeCompleteRequest{SessionID: start.SessionID, PeerDeviceID: bID.DeviceID, Signature: response.Signature})
	if err != nil {
		t.Fatal(err)
	}
	if session.ProofReceipt == nil || session.ProofReceipt.ReceiptFingerprint == "" {
		t.Fatalf("handshake omitted proof receipt: %+v", session)
	}
	evaluation, err = a.EvaluateProof(context.Background(), bID.DeviceID)
	if err != nil || !evaluation.Satisfied || evaluation.State != ProofStateVerified || evaluation.Receipt == nil {
		t.Fatalf("signed proof was not durably evaluable: %+v %v", evaluation, err)
	}
	if _, err := a.TestLink(context.Background(), bID.DeviceID); err != nil {
		t.Fatal(err)
	}
	evaluation, err = a.EvaluateProof(context.Background(), bID.DeviceID)
	if err != nil || !evaluation.Satisfied || evaluation.State != ProofStateVerified {
		t.Fatalf("reachability update erased signed proof: %+v %v", evaluation, err)
	}
	clock.Add(defaultLinkTTL + time.Second)
	evaluation, err = a.EvaluateProof(context.Background(), bID.DeviceID)
	if err != nil || evaluation.Satisfied || evaluation.State != ProofStateExpired || !evaluation.Reachable {
		t.Fatalf("expired proof did not remain separate from reachability: %+v %v", evaluation, err)
	}
}

func TestHandshakeProofDoesNotImplyTransportReachability(t *testing.T) {
	clock := &testClock{now: time.Date(2026, 7, 1, 12, 0, 0, 0, time.UTC)}
	a := newTestService(t, "proof-no-reachability", WithClock(clock))
	b := newTestService(t, "proof-no-reachability")
	aID, _ := a.BootstrapCurrentDevice(context.Background(), BootstrapDeviceRequest{})
	bID, _ := b.BootstrapCurrentDevice(context.Background(), BootstrapDeviceRequest{})
	trustBoth(t, a, aID, b, bID)
	completeSignedHandshake(t, a, aID, b, bID)

	status, err := a.GetConnectionStatus(context.Background(), bID.DeviceID)
	if err != nil {
		t.Fatal(err)
	}
	if status.Reachable || status.ProofState != ProofStateVerified {
		t.Fatalf("handshake proof invented transport reachability: %+v", status)
	}
	evaluation, err := a.EvaluateProof(context.Background(), bID.DeviceID)
	if err != nil || !evaluation.Satisfied || evaluation.Reachable {
		t.Fatalf("proof and reachability were not independent: %+v %v", evaluation, err)
	}
}

func TestRevocationAndRetrustInvalidatePreRevocationProof(t *testing.T) {
	clock := &testClock{now: time.Date(2026, 7, 1, 12, 0, 0, 0, time.UTC)}
	a := newTestService(t, "proof-retrust", WithClock(clock))
	b := newTestService(t, "proof-retrust")
	aID, _ := a.BootstrapCurrentDevice(context.Background(), BootstrapDeviceRequest{})
	bID, _ := b.BootstrapCurrentDevice(context.Background(), BootstrapDeviceRequest{})
	trustBoth(t, a, aID, b, bID)
	completeSignedHandshake(t, a, aID, b, bID)
	preRevocationLinks, err := a.store.readLinks()
	if err != nil {
		t.Fatal(err)
	}

	if err := a.RevokeDevice(context.Background(), bID.DeviceID); err != nil {
		t.Fatal(err)
	}
	evaluation, err := a.EvaluateProof(context.Background(), bID.DeviceID)
	if err != nil || evaluation.Satisfied || evaluation.State != ProofStateRejected {
		t.Fatalf("revocation did not reject proof: %+v %v", evaluation, err)
	}
	if _, err := a.TrustDevice(context.Background(), TrustDeviceRequest{DeviceID: bID.DeviceID, DisplayName: bID.DisplayName, PublicKey: bID.PublicKey, PublicKeyFingerprint: bID.PublicKeyFingerprint}); err != nil {
		t.Fatal(err)
	}
	evaluation, err = a.EvaluateProof(context.Background(), bID.DeviceID)
	if err != nil || evaluation.Satisfied || evaluation.State != ProofStateUnverified {
		t.Fatalf("retrust retained pre-revocation proof: %+v %v", evaluation, err)
	}

	// Even if stale link data reappears after recovery, the fresh trust epoch
	// makes the old receipt unusable.
	if err := a.store.writeLinks(preRevocationLinks); err != nil {
		t.Fatal(err)
	}
	evaluation, err = a.EvaluateProof(context.Background(), bID.DeviceID)
	if err != nil || evaluation.Satisfied || evaluation.State != ProofStateRejected {
		t.Fatalf("stale pre-revocation proof became valid after retrust: %+v %v", evaluation, err)
	}
	completeSignedHandshake(t, a, aID, b, bID)
	evaluation, err = a.EvaluateProof(context.Background(), bID.DeviceID)
	if err != nil || !evaluation.Satisfied || evaluation.State != ProofStateVerified {
		t.Fatalf("fresh post-retrust proof was not accepted: %+v %v", evaluation, err)
	}
}

func TestHandshakeAndProofExpireAtBoundary(t *testing.T) {
	startTime := time.Date(2026, 7, 1, 12, 0, 0, 0, time.UTC)
	clock := &testClock{now: startTime}
	a := newTestService(t, "expiry-boundary", WithClock(clock))
	b := newTestService(t, "expiry-boundary")
	aID, _ := a.BootstrapCurrentDevice(context.Background(), BootstrapDeviceRequest{})
	bID, _ := b.BootstrapCurrentDevice(context.Background(), BootstrapDeviceRequest{})
	trustBoth(t, a, aID, b, bID)

	start, err := a.StartHandshake(context.Background(), DiscoveredPeer{Presence: PresenceRecord{DeviceID: bID.DeviceID, PublicKeyFingerprint: bID.PublicKeyFingerprint}})
	if err != nil {
		t.Fatal(err)
	}
	response, err := b.SignHandshakeChallenge(context.Background(), HandshakeChallengeRequest{ChallengerDeviceID: aID.DeviceID, Challenge: start.Challenge})
	if err != nil {
		t.Fatal(err)
	}
	clock.Add(defaultLinkTTL)
	if _, err := a.CompleteHandshake(context.Background(), HandshakeCompleteRequest{SessionID: start.SessionID, PeerDeviceID: bID.DeviceID, Signature: response.Signature}); !errors.Is(err, ErrChallengeExpired) {
		t.Fatalf("challenge at expiry boundary error = %v, want ErrChallengeExpired", err)
	}

	clock.now = startTime
	completeSignedHandshake(t, a, aID, b, bID)
	clock.Add(defaultLinkTTL)
	evaluation, err := a.EvaluateProof(context.Background(), bID.DeviceID)
	if err != nil || evaluation.Satisfied || evaluation.State != ProofStateExpired {
		t.Fatalf("proof at expiry boundary was not expired: %+v %v", evaluation, err)
	}
}

func TestRegistryImportWriteFaultsPreserveProofOrRecoverSafely(t *testing.T) {
	clock := &testClock{now: time.Date(2026, 7, 1, 12, 0, 0, 0, time.UTC)}
	a := newTestService(t, "import-fault", WithClock(clock))
	b := newTestService(t, "import-fault")
	aID, _ := a.BootstrapCurrentDevice(context.Background(), BootstrapDeviceRequest{})
	bID, _ := b.BootstrapCurrentDevice(context.Background(), BootstrapDeviceRequest{})
	trustBoth(t, a, aID, b, bID)
	completeSignedHandshake(t, a, aID, b, bID)
	snapshot, err := a.ExportRegistrySnapshot(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	snapshot.Devices[0].DisplayName = "Imported Peer"
	snapshot.SnapshotFingerprint = snapshotFingerprint(snapshot)

	var writes []string
	a.store.failWrite = func(path string) bool {
		writes = append(writes, path)
		return path == a.store.registryPath()
	}
	if err := a.ImportRegistrySnapshot(context.Background(), snapshot); !errors.Is(err, ErrStorageUnavailable) {
		t.Fatalf("registry commit fault error = %v", err)
	}
	a.store.failWrite = nil
	for _, path := range writes {
		if path == a.store.linkStatusPath() {
			t.Fatal("proof was cleared before the registry commit succeeded")
		}
	}
	assertVerifiedProof(t, a, bID.DeviceID)

	linkFailures := 0
	a.store.failWrite = func(path string) bool {
		if path == a.store.linkStatusPath() && linkFailures == 0 {
			linkFailures++
			return true
		}
		return false
	}
	if err := a.ImportRegistrySnapshot(context.Background(), snapshot); !errors.Is(err, ErrStorageUnavailable) {
		t.Fatalf("proof clear fault error = %v", err)
	}
	a.store.failWrite = nil
	devices, err := a.ListTrustedDevices(context.Background())
	if err != nil || len(devices) != 1 || devices[0].DisplayName == "Imported Peer" {
		t.Fatalf("failed proof clear did not roll registry back: %+v %v", devices, err)
	}
	assertVerifiedProof(t, a, bID.DeviceID)
}

func TestCompleteHandshakeFailsWhenProofPersistenceFails(t *testing.T) {
	a := newTestService(t, "proof-persist")
	b := newTestService(t, "proof-persist")
	aID, _ := a.BootstrapCurrentDevice(context.Background(), BootstrapDeviceRequest{})
	bID, _ := b.BootstrapCurrentDevice(context.Background(), BootstrapDeviceRequest{})
	trustBoth(t, a, aID, b, bID)
	peer := DiscoveredPeer{Presence: PresenceRecord{DeviceID: bID.DeviceID, PublicKeyFingerprint: bID.PublicKeyFingerprint}}
	start, err := a.StartHandshake(context.Background(), peer)
	if err != nil {
		t.Fatal(err)
	}
	response, err := b.SignHandshakeChallenge(context.Background(), HandshakeChallengeRequest{ChallengerDeviceID: aID.DeviceID, Challenge: start.Challenge})
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(a.store.linkStatusPath(), 0o700); err != nil {
		t.Fatal(err)
	}
	if _, err := a.CompleteHandshake(context.Background(), HandshakeCompleteRequest{SessionID: start.SessionID, PeerDeviceID: bID.DeviceID, Signature: response.Signature}); !errors.Is(err, ErrStorageUnavailable) {
		t.Fatalf("handshake completion error = %v, want durable storage failure", err)
	}
}

func TestLinkTestAndConnectionStatus(t *testing.T) {
	discovery := NewMemoryDiscoveryProvider()
	transport := NewMemoryTransport()
	a := newTestService(t, "a", WithDiscoveryProvider(discovery), WithTransport(transport))
	b := newTestService(t, "b", WithDiscoveryProvider(discovery))
	aID, _ := a.BootstrapCurrentDevice(context.Background(), BootstrapDeviceRequest{})
	bID, _ := b.BootstrapCurrentDevice(context.Background(), BootstrapDeviceRequest{})
	trustBoth(t, a, aID, b, bID)
	if _, err := b.PublishPresence(context.Background()); err != nil {
		t.Fatal(err)
	}
	if _, err := a.DiscoverPeers(context.Background()); err != nil {
		t.Fatal(err)
	}
	transport.RegisterHandler(bID.DeviceID, func(ctx context.Context, msg Message) (Message, error) {
		if msg.Kind != "ping" {
			return Message{Kind: "bad", FromDeviceID: bID.DeviceID}, nil
		}
		return Message{Kind: "pong", FromDeviceID: bID.DeviceID, CreatedAt: time.Now().UTC()}, nil
	})
	res, err := a.TestLink(context.Background(), bID.DeviceID)
	if err != nil || !res.OK {
		t.Fatalf("expected link success, got %+v %v", res, err)
	}
	status, err := a.GetConnectionStatus(context.Background(), bID.DeviceID)
	if err != nil || !status.Reachable {
		t.Fatalf("expected reachable status, got %+v %v", status, err)
	}
	transport.RegisterHandler(bID.DeviceID, func(ctx context.Context, msg Message) (Message, error) {
		return Message{Kind: "unexpected", FromDeviceID: bID.DeviceID}, nil
	})
	if _, err := a.TestLink(context.Background(), bID.DeviceID); !errors.Is(err, ErrTransportUnavailable) {
		t.Fatalf("expected malformed response failure, got %v", err)
	}
	transport.SetError(errors.New("offline"))
	if _, err := a.TestLink(context.Background(), bID.DeviceID); !errors.Is(err, ErrTransportUnavailable) {
		t.Fatalf("expected transport unavailable, got %v", err)
	}
	transport.SetError(nil)
	transport.RegisterHandler(bID.DeviceID, func(ctx context.Context, msg Message) (Message, error) {
		<-ctx.Done()
		return Message{}, ErrContextCanceled
	})
	timeoutCtx, cancel := context.WithTimeout(context.Background(), time.Millisecond)
	defer cancel()
	if _, err := a.TestLink(timeoutCtx, bID.DeviceID); !errors.Is(err, ErrContextCanceled) {
		t.Fatalf("expected timeout/cancel failure, got %v", err)
	}
	receiveSecret := "secret private path C:\\Users\\example\\device_private_key"
	transport.RegisterHandler(bID.DeviceID, func(ctx context.Context, msg Message) (Message, error) {
		return Message{}, errors.New(receiveSecret)
	})
	if _, err := a.TestLink(context.Background(), bID.DeviceID); !errors.Is(err, ErrTransportUnavailable) {
		t.Fatalf("expected sanitized receive error, got %v", err)
	} else if strings.Contains(err.Error(), "secret") || strings.Contains(err.Error(), "device_private_key") {
		t.Fatalf("receive error leaked transport text: %v", err)
	}
	sendSecret := "secret send failure /tmp/device_private_key"
	sendFailure := &sendFailTransport{err: errors.New(sendSecret)}
	sendSvc, err := NewService(testConfig(t, "send-failure"), WithDiscoveryProvider(discovery), WithTransport(sendFailure))
	if err != nil {
		t.Fatal(err)
	}
	sendID, _ := sendSvc.BootstrapCurrentDevice(context.Background(), BootstrapDeviceRequest{})
	if _, err := sendSvc.TrustDevice(context.Background(), TrustDeviceRequest{DeviceID: bID.DeviceID, DisplayName: bID.DisplayName, PublicKey: bID.PublicKey, PublicKeyFingerprint: bID.PublicKeyFingerprint}); err != nil {
		t.Fatal(err)
	}
	if _, err := b.PublishPresence(context.Background()); err != nil {
		t.Fatal(err)
	}
	if _, err := sendSvc.DiscoverPeers(context.Background()); err != nil {
		t.Fatal(err)
	}
	if _, err := sendSvc.TestLink(context.Background(), bID.DeviceID); !errors.Is(err, ErrTransportUnavailable) {
		t.Fatalf("expected sanitized send error, got %v", err)
	} else if strings.Contains(err.Error(), "secret") || strings.Contains(err.Error(), "device_private_key") {
		t.Fatalf("send error leaked transport text: %v", err)
	}
	_ = sendID
	canceledCtx, cancelNow := context.WithCancel(context.Background())
	cancelNow()
	if _, err := a.TestLink(canceledCtx, bID.DeviceID); !errors.Is(err, ErrContextCanceled) {
		t.Fatalf("expected canceled context failure, got %v", err)
	}
	if err := os.WriteFile(a.store.linkStatusPath(), []byte(`{bad-json`), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := a.GetConnectionStatus(context.Background(), bID.DeviceID); !errors.Is(err, ErrStorageUnavailable) {
		t.Fatalf("expected corrupt status store error, got %v", err)
	} else if strings.Contains(err.Error(), a.store.dir) {
		t.Fatalf("status error leaked path")
	}
	if _, err := a.TestLink(context.Background(), "unknown"); !errors.Is(err, ErrDeviceNotTrusted) {
		t.Fatalf("expected unknown device failure, got %v", err)
	}
	if err := a.RevokeDevice(context.Background(), bID.DeviceID); err != nil {
		t.Fatal(err)
	}
	if _, err := a.TestLink(context.Background(), bID.DeviceID); !errors.Is(err, ErrDeviceRevoked) {
		t.Fatalf("expected revoked link failure, got %v", err)
	}
	_ = aID
}

func TestDiscoveryAndLinkAcceptNilContext(t *testing.T) {
	discovery := NewMemoryDiscoveryProvider()
	transport := NewMemoryTransport()
	a := newTestService(t, "nil-context-a", WithDiscoveryProvider(discovery), WithTransport(transport))
	b := newTestService(t, "nil-context-b", WithDiscoveryProvider(discovery))
	aID, err := a.BootstrapCurrentDevice(nil, BootstrapDeviceRequest{})
	if err != nil {
		t.Fatal(err)
	}
	bID, err := b.BootstrapCurrentDevice(nil, BootstrapDeviceRequest{})
	if err != nil {
		t.Fatal(err)
	}
	trustBoth(t, a, aID, b, bID)
	if _, err := b.PublishPresence(nil); err != nil {
		t.Fatalf("PublishPresence(nil) returned error: %v", err)
	}
	if _, err := a.DiscoverPeers(nil); err != nil {
		t.Fatalf("DiscoverPeers(nil) returned error: %v", err)
	}
	transport.RegisterHandler(bID.DeviceID, func(ctx context.Context, msg Message) (Message, error) {
		return Message{Kind: "pong", FromDeviceID: bID.DeviceID, CreatedAt: time.Now().UTC()}, nil
	})
	result, err := a.TestLink(nil, bID.DeviceID)
	if err != nil || !result.OK {
		t.Fatalf("TestLink(nil) = %+v, %v", result, err)
	}
}

func TestConcurrentBootstrapAndTrustOperations(t *testing.T) {
	svc := newTestService(t, "concurrent")
	var wg sync.WaitGroup
	errs := make(chan error, 12)
	for i := 0; i < 6; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, err := svc.BootstrapCurrentDevice(context.Background(), BootstrapDeviceRequest{})
			errs <- err
		}()
	}
	peer := makeTrustRequest(t, "peer")
	for i := 0; i < 6; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, err := svc.TrustDevice(context.Background(), peer)
			errs <- err
		}()
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		if err != nil {
			t.Fatalf("unexpected concurrent error: %v", err)
		}
	}
	devices, err := svc.ListTrustedDevices(context.Background())
	if err != nil || len(devices) != 1 {
		t.Fatalf("expected one trusted device, got %+v %v", devices, err)
	}
}

func makeTrustRequest(t *testing.T, deviceID string) TrustDeviceRequest {
	t.Helper()
	publicKey, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	encoded := encodePublicKey(publicKey)
	return TrustDeviceRequest{DeviceID: deviceID, DisplayName: deviceID, PublicKey: encoded, PublicKeyFingerprint: fingerprintPublicKey(publicKey)}
}

func trustBoth(t *testing.T, a *Service, aID DeviceIdentity, b *Service, bID DeviceIdentity) {
	t.Helper()
	if _, err := a.TrustDevice(context.Background(), TrustDeviceRequest{DeviceID: bID.DeviceID, DisplayName: bID.DisplayName, PublicKey: bID.PublicKey, PublicKeyFingerprint: bID.PublicKeyFingerprint}); err != nil {
		t.Fatal(err)
	}
	if _, err := b.TrustDevice(context.Background(), TrustDeviceRequest{DeviceID: aID.DeviceID, DisplayName: aID.DisplayName, PublicKey: aID.PublicKey, PublicKeyFingerprint: aID.PublicKeyFingerprint}); err != nil {
		t.Fatal(err)
	}
}

func completeSignedHandshake(t *testing.T, a *Service, aID DeviceIdentity, b *Service, bID DeviceIdentity) LinkSession {
	t.Helper()
	peer := DiscoveredPeer{Presence: PresenceRecord{DeviceID: bID.DeviceID, PublicKeyFingerprint: bID.PublicKeyFingerprint}}
	start, err := a.StartHandshake(context.Background(), peer)
	if err != nil {
		t.Fatal(err)
	}
	response, err := b.SignHandshakeChallenge(context.Background(), HandshakeChallengeRequest{ChallengerDeviceID: aID.DeviceID, Challenge: start.Challenge})
	if err != nil {
		t.Fatal(err)
	}
	session, err := a.CompleteHandshake(context.Background(), HandshakeCompleteRequest{SessionID: start.SessionID, PeerDeviceID: bID.DeviceID, Signature: response.Signature})
	if err != nil {
		t.Fatal(err)
	}
	return session
}

func assertVerifiedProof(t *testing.T, svc *Service, deviceID string) {
	t.Helper()
	evaluation, err := svc.EvaluateProof(context.Background(), deviceID)
	if err != nil || !evaluation.Satisfied || evaluation.State != ProofStateVerified {
		t.Fatalf("expected verified proof, got %+v %v", evaluation, err)
	}
}

func mustFinishDeviceLinkCall(t *testing.T, fn func() error) {
	t.Helper()
	done := make(chan error, 1)
	go func() { done <- fn() }()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("reentrant service call failed: %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("discovery provider reentry deadlocked the service")
	}
}

type reentrantDiscoveryProvider struct {
	svc    *Service
	record PresenceRecord
}

func (p *reentrantDiscoveryProvider) Publish(ctx context.Context, record PresenceRecord) error {
	if _, err := p.svc.GetCurrentDevice(ctx); err != nil {
		return err
	}
	p.record = clonePresenceRecord(record)
	return nil
}

func (p *reentrantDiscoveryProvider) Discover(ctx context.Context) ([]PresenceRecord, error) {
	if _, err := p.svc.ListLocalResources(ctx); err != nil {
		return nil, err
	}
	return []PresenceRecord{clonePresenceRecord(p.record)}, nil
}

func errString[T any](v T, err error) string {
	if err == nil {
		return ""
	}
	return err.Error()
}

func cloneRegistrySnapshot(t *testing.T, snapshot RegistrySnapshot) RegistrySnapshot {
	t.Helper()
	raw, err := json.Marshal(snapshot)
	if err != nil {
		t.Fatal(err)
	}
	var cloned RegistrySnapshot
	if err := json.Unmarshal(raw, &cloned); err != nil {
		t.Fatal(err)
	}
	return cloned
}

type sendFailTransport struct {
	err error
}

func (t *sendFailTransport) Open(ctx context.Context, peer DiscoveredPeer) (Connection, error) {
	if err := contextError(ctx); err != nil {
		return nil, err
	}
	return &sendFailConnection{err: t.err}, nil
}

type sendFailConnection struct {
	err error
}

func (c *sendFailConnection) Send(context.Context, Message) error {
	return c.err
}

func (c *sendFailConnection) Receive(context.Context) (Message, error) {
	return Message{Kind: "pong"}, nil
}

func (c *sendFailConnection) Close() error {
	return nil
}

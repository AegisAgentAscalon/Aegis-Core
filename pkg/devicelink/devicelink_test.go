package devicelink

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestPublicDeviceLinkDTOsHideKeyMaterialFromJSON(t *testing.T) {
	ctx := context.Background()
	svc, err := NewService(AppConfig{AppID: "aegis-test", DisplayName: "Aegis Test", DataDir: t.TempDir(), Namespace: "profile-a"})
	if err != nil {
		t.Fatalf("NewService returned error: %v", err)
	}
	identity, err := svc.BootstrapCurrentDevice(ctx, BootstrapDeviceRequest{DisplayName: "Laptop"})
	if err != nil {
		t.Fatalf("BootstrapCurrentDevice returned error: %v", err)
	}
	assertSafeJSON(t, identity)
	if identity.PublicKey == "" || identity.PublicKeyFingerprint == "" {
		t.Fatal("public trust material should remain available for explicit trust exchange")
	}
	bundle, err := svc.ExportPublicIdentityBundle(ctx)
	if err != nil {
		t.Fatalf("ExportPublicIdentityBundle returned error: %v", err)
	}
	if err := ValidatePublicIdentityBundle(bundle); err != nil {
		t.Fatalf("ValidatePublicIdentityBundle returned error: %v", err)
	}
	rawBundle, err := json.Marshal(bundle)
	if err != nil || !strings.Contains(string(rawBundle), `"public_key":`) {
		t.Fatalf("public identity bundle did not explicitly expose exchange key: %s %v", string(rawBundle), err)
	}

	peerKey, peerFingerprint := publicTrustMaterial(t)
	trusted, err := svc.TrustDevice(ctx, TrustDeviceRequest{
		DeviceID:             "device-peer",
		DisplayName:          "Peer",
		PublicKey:            peerKey,
		PublicKeyFingerprint: peerFingerprint,
	})
	if err != nil {
		t.Fatalf("TrustDevice returned error: %v", err)
	}
	assertSafeJSON(t, trusted)

	snapshot, err := svc.ExportRegistrySnapshot(ctx)
	if err != nil {
		t.Fatalf("ExportRegistrySnapshot returned error: %v", err)
	}
	assertSafeJSON(t, snapshot)

	other, err := NewService(AppConfig{AppID: "aegis-test", DisplayName: "Aegis Test", DataDir: t.TempDir(), Namespace: "profile-a"})
	if err != nil {
		t.Fatalf("NewService import returned error: %v", err)
	}
	if err := other.ImportRegistrySnapshot(ctx, snapshot); err != nil {
		t.Fatalf("ImportRegistrySnapshot should preserve Go-level behavior: %v", err)
	}
}

func TestPublicBootstrapInspectionDoesNotCreateStorage(t *testing.T) {
	dataDir := t.TempDir()
	cfg := AppConfig{AppID: "aegis-test", DisplayName: "Aegis Test", DataDir: dataDir, Namespace: "inspect"}
	status, err := InspectBootstrap(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if status.State != BootstrapAbsent || status.Ready {
		t.Fatalf("unexpected bootstrap status: %+v", status)
	}
	storageDir := filepath.Join(dataDir, cfg.AppID, cfg.Namespace, "devicelink")
	if _, err := os.Stat(storageDir); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("inspection created storage or returned an unexpected stat error: %v", err)
	}
}

func TestPublicDeviceLinkInvalidIDsAndProviderErrorsAreSafe(t *testing.T) {
	ctx := context.Background()
	discovery := NewMemoryDiscoveryProvider()
	svc, err := NewService(AppConfig{AppID: "aegis-test", DisplayName: "Aegis Test", DataDir: t.TempDir(), Namespace: "profile-a"}, WithDiscoveryProvider(discovery))
	if err != nil {
		t.Fatalf("NewService returned error: %v", err)
	}
	if _, err := svc.TrustDevice(ctx, TrustDeviceRequest{DeviceID: "../bad", PublicKey: "not-a-key"}); !errors.Is(err, ErrDeviceNotFound) {
		t.Fatalf("TrustDevice bad id error = %v, want ErrDeviceNotFound", err)
	}
	if _, err := svc.CompleteHandshake(ctx, HandshakeCompleteRequest{SessionID: `..\device_private_key`, PeerDeviceID: "device-peer", Signature: "x"}); !errors.Is(err, ErrInvalidSessionID) {
		t.Fatalf("CompleteHandshake bad session error = %v, want ErrInvalidSessionID", err)
	} else if unsafeText(err.Error()) {
		t.Fatalf("invalid session error leaked unsafe text: %v", err)
	}

	if _, err := svc.BootstrapCurrentDevice(ctx, BootstrapDeviceRequest{}); err != nil {
		t.Fatalf("BootstrapCurrentDevice returned error: %v", err)
	}
	discovery.SetError(errors.New(`secret discovery failure C:\Users\person\AppData\device_private_key`))
	if _, err := svc.PublishPresence(ctx); !errors.Is(err, ErrDiscoveryUnavailable) {
		t.Fatalf("PublishPresence error = %v, want ErrDiscoveryUnavailable", err)
	} else if unsafeText(err.Error()) {
		t.Fatalf("discovery error leaked unsafe text: %v", err)
	}
}

func TestPublicTransportErrorsAreSanitized(t *testing.T) {
	ctx := context.Background()
	discovery := NewMemoryDiscoveryProvider()
	a, err := NewService(AppConfig{AppID: "aegis-test", DisplayName: "Aegis Test", DataDir: t.TempDir(), Namespace: "profile-a"}, WithDiscoveryProvider(discovery), WithTransport(secretTransport{}))
	if err != nil {
		t.Fatalf("NewService A returned error: %v", err)
	}
	b, err := NewService(AppConfig{AppID: "aegis-test", DisplayName: "Aegis Test", DataDir: t.TempDir(), Namespace: "profile-a"}, WithDiscoveryProvider(discovery))
	if err != nil {
		t.Fatalf("NewService B returned error: %v", err)
	}
	aID, err := a.BootstrapCurrentDevice(ctx, BootstrapDeviceRequest{})
	if err != nil {
		t.Fatalf("bootstrap A: %v", err)
	}
	bID, err := b.BootstrapCurrentDevice(ctx, BootstrapDeviceRequest{})
	if err != nil {
		t.Fatalf("bootstrap B: %v", err)
	}
	if _, err := a.TrustDevice(ctx, TrustDeviceRequest{DeviceID: bID.DeviceID, DisplayName: bID.DisplayName, PublicKey: bID.PublicKey, PublicKeyFingerprint: bID.PublicKeyFingerprint}); err != nil {
		t.Fatalf("trust B: %v", err)
	}
	if _, err := b.TrustDevice(ctx, TrustDeviceRequest{DeviceID: aID.DeviceID, DisplayName: aID.DisplayName, PublicKey: aID.PublicKey, PublicKeyFingerprint: aID.PublicKeyFingerprint}); err != nil {
		t.Fatalf("trust A: %v", err)
	}
	if _, err := b.PublishPresence(ctx); err != nil {
		t.Fatalf("PublishPresence B: %v", err)
	}
	if _, err := a.DiscoverPeers(ctx); err != nil {
		t.Fatalf("DiscoverPeers A: %v", err)
	}

	if _, err := a.TestLink(ctx, bID.DeviceID); !errors.Is(err, ErrTransportUnavailable) {
		t.Fatalf("TestLink error = %v, want ErrTransportUnavailable", err)
	} else if unsafeText(err.Error()) {
		t.Fatalf("transport error leaked unsafe text: %v", err)
	}
}

func assertSafeJSON(t *testing.T, v any) {
	t.Helper()
	raw, err := json.Marshal(v)
	if err != nil {
		t.Fatalf("json marshal failed: %v", err)
	}
	text := strings.ToLower(string(raw))
	for _, forbidden := range []string{`"public_key":`, "private_key", "secret", "token", `c:\\users\\`, `appdata\\`} {
		if strings.Contains(text, forbidden) {
			t.Fatalf("unsafe JSON detail %q in %s", forbidden, string(raw))
		}
	}
}

func publicTrustMaterial(t *testing.T) (string, string) {
	t.Helper()
	publicKey, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey returned error: %v", err)
	}
	sum := sha256.Sum256(publicKey)
	return base64.RawStdEncoding.EncodeToString(publicKey), hex.EncodeToString(sum[:])[:16]
}

func unsafeText(value string) bool {
	lower := strings.ToLower(value)
	return strings.Contains(lower, "secret") ||
		strings.Contains(lower, "private_key") ||
		strings.Contains(lower, "token") ||
		strings.Contains(value, `C:\`) ||
		strings.Contains(value, `/tmp/`)
}

type secretTransport struct{}

func (secretTransport) Open(context.Context, DiscoveredPeer) (Connection, error) {
	return nil, errors.New(`secret transport failure C:\Users\person\Downloads\device_private_key`)
}

type unusedConnection struct{}

func (unusedConnection) Send(context.Context, Message) error { return nil }
func (unusedConnection) Receive(context.Context) (Message, error) {
	return Message{Kind: "pong", CreatedAt: time.Now().UTC()}, nil
}
func (unusedConnection) Close() error { return nil }

package devicelink

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"errors"
	"os"
	"testing"
)

func TestPrivateKeyCorruptionRejectsReadinessExportAndSigning(t *testing.T) {
	for _, tc := range []struct {
		name   string
		offset int
	}{
		{"seed", 0},
		{"cached-public-key", ed25519.SeedSize},
		{"identity-key-mismatch", -1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ctx := context.Background()
			cfg := testConfig(t, "key-integrity")
			svc, err := NewService(cfg)
			if err != nil {
				t.Fatal(err)
			}
			identity, err := svc.BootstrapCurrentDevice(ctx, BootstrapDeviceRequest{})
			if err != nil {
				t.Fatal(err)
			}
			request := HandshakeChallengeRequest{Challenge: "integrity-check"}
			response, err := svc.SignHandshakeChallenge(ctx, request)
			if err != nil {
				t.Fatal(err)
			}
			publicKey, err := decodePublicKey(identity.PublicKey)
			if err != nil {
				t.Fatal(err)
			}
			signature, err := base64.RawStdEncoding.DecodeString(response.Signature)
			if err != nil || !ed25519.Verify(publicKey, handshakePayload(cfg.AppID, cfg.Namespace, "", identity.DeviceID, request.Challenge), signature) {
				t.Fatal("valid stored key did not produce a valid handshake signature")
			}
			key, err := svc.privateKey()
			if err != nil {
				t.Fatal(err)
			}
			if tc.offset < 0 {
				key[0] ^= 1
				key = ed25519.NewKeyFromSeed(key[:ed25519.SeedSize])
			} else {
				key[tc.offset] ^= 1
			}
			if err := svc.store.writePrivateKey(base64.RawStdEncoding.EncodeToString(key)); err != nil {
				t.Fatal(err)
			}
			before, err := os.ReadFile(svc.store.privateKeyPath())
			if err != nil {
				t.Fatal(err)
			}
			status, err := InspectBootstrap(cfg)
			if err != nil || status.State != BootstrapInvalid || status.Ready || status.Bootstrapped {
				t.Fatalf("corrupt key reported ready: %+v, %v", status, err)
			}
			if _, err := svc.BootstrapCurrentDevice(ctx, BootstrapDeviceRequest{}); !errors.Is(err, ErrStorageUnavailable) {
				t.Fatalf("bootstrap accepted corrupt key: %v", err)
			}
			if _, err := svc.ExportPublicIdentityBundle(ctx); !errors.Is(err, ErrStorageUnavailable) {
				t.Fatalf("identity export accepted corrupt key: %v", err)
			}
			if _, err := svc.SignHandshakeChallenge(ctx, request); !errors.Is(err, ErrStorageUnavailable) {
				t.Fatalf("signing accepted corrupt key: %v", err)
			}
			after, err := os.ReadFile(svc.store.privateKeyPath())
			if err != nil || !bytes.Equal(before, after) {
				t.Fatal("failed validation rewrote persisted private-key material")
			}
		})
	}
}

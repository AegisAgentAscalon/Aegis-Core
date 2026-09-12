package devicelink

import (
	"context"
	"encoding/json"
	"errors"
	"testing"
	"time"
)

func TestIdentityTrustAndProofRejectUnencodableTimestamps(t *testing.T) {
	now := time.Date(2026, 9, 12, 12, 0, 0, 0, time.UTC)
	for _, tc := range []struct {
		name string
		at   time.Time
	}{
		{"zone-24-hours", now.In(time.FixedZone("invalid", 24*60*60))},
		{"year-10000", time.Date(10000, 1, 1, 0, 0, 0, 0, time.UTC)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := json.Marshal(tc.at); err == nil {
				t.Fatal("probe timestamp unexpectedly has a valid JSON encoding")
			}
			ctx := context.Background()
			clock := &testClock{now: now}
			svc := newTestService(t, "encoding-validation", WithClock(clock))
			identity, err := svc.BootstrapCurrentDevice(ctx, BootstrapDeviceRequest{})
			if err != nil {
				t.Fatal(err)
			}
			trusted, err := svc.TrustDevice(ctx, makeTrustRequest(t, "peer"))
			if err != nil {
				t.Fatal(err)
			}
			bundle, err := svc.ExportPublicIdentityBundle(ctx)
			if err != nil || ValidatePublicIdentityBundle(bundle) != nil {
				t.Fatal("valid identity bundle rejected", err)
			}
			bundle.CreatedAt, bundle.UpdatedAt = tc.at, tc.at.Add(time.Minute)
			bundle.BundleFingerprint = sha256String("") // Former ignored-Marshal result.
			if err := ValidatePublicIdentityBundle(bundle); !errors.Is(err, ErrInvalidIdentityBundle) {
				t.Errorf("unencodable identity bundle accepted: %v", err)
			}
			if publicIdentityBundleFingerprint(bundle) != "" {
				t.Error("unencodable identity bundle received a usable fingerprint")
			}

			snapshot, err := svc.ExportRegistrySnapshot(ctx)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := validateRegistryBackupSnapshot(svc.cfg, snapshot); err != nil {
				t.Fatal("valid registry backup rejected", err)
			}
			snapshot.CreatedAt, snapshot.UpdatedAt = tc.at, tc.at.Add(time.Minute)
			snapshot.SnapshotFingerprint = sha256String("")[:16]
			if _, err := validateRegistryBackupSnapshot(svc.cfg, snapshot); !errors.Is(err, ErrInvalidRegistrySnapshot) {
				t.Errorf("unencodable schema-two backup accepted: %v", err)
			}
			if snapshotFingerprint(snapshot) != "" {
				t.Error("unencodable registry backup received a usable fingerprint")
			}
			snapshot.SchemaVersion = legacyRegistrySnapshotSchemaVersion
			snapshot.SnapshotFingerprint = "" // Historically optional in schema one.
			if _, err := validateRegistryBackupSnapshot(svc.cfg, snapshot); !errors.Is(err, ErrInvalidRegistrySnapshot) {
				t.Errorf("unencodable schema-one backup accepted: %v", err)
			}

			receipt := ProofReceipt{
				SchemaVersion: schemaVersion, SessionID: "hs_encoding", LocalDeviceID: identity.DeviceID,
				PeerDeviceID: trusted.DeviceID, PeerPublicKeyFingerprint: trusted.PublicKeyFingerprint,
				ChallengeFingerprint: "challenge", SignatureFingerprint: "signature",
				VerifiedAt: tc.at, ExpiresAt: tc.at.Add(time.Minute), ReceiptFingerprint: sha256String(""),
			}
			validReceipt := receipt
			validReceipt.VerifiedAt, validReceipt.ExpiresAt = now, now.Add(time.Minute)
			validReceipt.ReceiptFingerprint = proofReceiptFingerprint(validReceipt)
			if proof := evaluateProof(now.Add(time.Second), identity.DeviceID, trusted, ConnectionStatus{ProofReceipt: &validReceipt}); !proof.Satisfied {
				t.Fatalf("valid signed proof rejected: %+v", proof)
			}
			proof := evaluateProof(tc.at.Add(time.Second), identity.DeviceID, trusted, ConnectionStatus{ProofReceipt: &receipt})
			if proof.Satisfied || proof.State != ProofStateRejected {
				t.Errorf("unencodable signed proof accepted: %+v", proof)
			}
			if proofReceiptFingerprint(receipt) != "" {
				t.Error("unencodable proof received a usable fingerprint")
			}
		})
	}
}

func TestRegistryExportRejectsUnencodableClock(t *testing.T) {
	clock := &testClock{now: time.Date(10000, 1, 1, 0, 0, 0, 0, time.UTC)}
	svc := newTestService(t, "export-encoding", WithClock(clock))
	if _, err := svc.ExportRegistrySnapshot(context.Background()); !errors.Is(err, ErrStorageUnavailable) {
		t.Fatalf("unencodable registry export succeeded: %v", err)
	}
}

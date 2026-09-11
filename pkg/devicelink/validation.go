package devicelink

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"sort"
	"strings"
	"time"
)

func trustError(status TrustStatus) error {
	switch status {
	case TrustRevoked:
		return ErrDeviceRevoked
	case TrustStale:
		return ErrDeviceStale
	default:
		return ErrDeviceNotTrusted
	}
}

func validResourceType(rt ResourceType) bool {
	switch rt {
	case ResourceService, ResourceData, ResourceConnector, ResourceRuntime, ResourceTool, ResourceOther:
		return true
	default:
		return false
	}
}

func compactStrings(in []string) []string {
	seen := map[string]bool{}
	var out []string
	for _, item := range in {
		item = strings.TrimSpace(item)
		if item == "" || seen[item] {
			continue
		}
		seen[item] = true
		out = append(out, item)
	}
	sort.Strings(out)
	return out
}

func cloneDeviceIdentity(identity DeviceIdentity) DeviceIdentity {
	identity.Capabilities = append([]string{}, identity.Capabilities...)
	return identity
}

func cloneTrustedDevice(device TrustedDevice) TrustedDevice {
	return cloneTrustedDevices([]TrustedDevice{device})[0]
}

func cloneMap(in map[string]string) map[string]string {
	if in == nil {
		return nil
	}
	out := map[string]string{}
	for key, value := range in {
		out[key] = value
	}
	return out
}

func cloneResourceDescriptors(in []ResourceDescriptor) []ResourceDescriptor {
	out := make([]ResourceDescriptor, len(in))
	for i, resource := range in {
		out[i] = resource
		out[i].Tags = append([]string{}, resource.Tags...)
		out[i].Metadata = cloneMap(resource.Metadata)
	}
	return out
}

func summarizeResources(resources []ResourceDescriptor) []ResourceSummary {
	counts := map[ResourceType]int{}
	for _, res := range resources {
		counts[res.Type]++
	}
	out := make([]ResourceSummary, 0)
	for rt, count := range counts {
		out = append(out, ResourceSummary{Type: rt, Count: count})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Type < out[j].Type })
	return out
}

func snapshotFingerprint(snapshot RegistrySnapshot) string {
	canonical, err := normalizeRegistrySnapshotTrustMaterial(snapshot)
	if err != nil {
		canonical = snapshot
	}
	canonical.SnapshotFingerprint = ""
	canonical.Devices = cloneTrustedDevices(canonical.Devices)
	for i := range canonical.Devices {
		canonical.Devices[i].Capabilities = compactStrings(canonical.Devices[i].Capabilities)
	}
	sort.Slice(canonical.Devices, func(i, j int) bool {
		if canonical.Devices[i].DeviceID == canonical.Devices[j].DeviceID {
			return canonical.Devices[i].PublicKeyFingerprint < canonical.Devices[j].PublicKeyFingerprint
		}
		return canonical.Devices[i].DeviceID < canonical.Devices[j].DeviceID
	})
	raw, _ := json.Marshal(canonical)
	sum := sha256String(string(raw))
	return sum[:16]
}

func legacyRegistrySnapshotFingerprint(snapshot RegistrySnapshot) string {
	parts := make([]string, 0, len(snapshot.Devices))
	for _, dev := range snapshot.Devices {
		parts = append(parts, dev.DeviceID+"="+dev.PublicKeyFingerprint)
	}
	sort.Strings(parts)
	return sha256String(snapshot.AppID + "|" + snapshot.Namespace + "|" + strings.Join(parts, "|"))[:16]
}

func normalizeRegistrySnapshotTrustMaterial(snapshot RegistrySnapshot) (RegistrySnapshot, error) {
	normalized := snapshot
	normalized.Devices = cloneTrustedDevices(snapshot.Devices)
	for i := range normalized.Devices {
		dev := &normalized.Devices[i]
		publicKey, err := decodePublicKey(dev.PublicKey)
		if err != nil {
			return RegistrySnapshot{}, err
		}
		dev.PublicKey = encodePublicKey(publicKey)
		dev.PublicKeyFingerprint = strings.ToLower(strings.TrimSpace(dev.PublicKeyFingerprint))
		dev.Capabilities = compactStrings(dev.Capabilities)
	}
	return normalized, nil
}

func validateRegistryBackupSnapshot(cfg AppConfig, snapshot RegistrySnapshot) (RegistrySnapshot, error) {
	if snapshot.AppID != cfg.AppID || snapshot.Namespace != cfg.Namespace {
		return RegistrySnapshot{}, ErrInvalidRegistrySnapshot
	}
	switch snapshot.SchemaVersion {
	case legacyRegistrySnapshotSchemaVersion:
		if snapshot.Purpose != "" && snapshot.Purpose != RegistrySnapshotLocalBackup {
			return RegistrySnapshot{}, ErrInvalidRegistrySnapshot
		}
		if snapshot.SnapshotFingerprint != "" && snapshot.SnapshotFingerprint != legacyRegistrySnapshotFingerprint(snapshot) {
			return RegistrySnapshot{}, ErrInvalidRegistrySnapshot
		}
	case RegistrySnapshotSchemaVersion:
		if snapshot.Purpose != RegistrySnapshotLocalBackup || snapshot.SnapshotFingerprint == "" {
			return RegistrySnapshot{}, ErrInvalidRegistrySnapshot
		}
	default:
		return RegistrySnapshot{}, ErrInvalidRegistrySnapshot
	}
	if snapshot.ProfileMetadataVersion != metadataVersion || snapshot.CreatedAt.IsZero() || snapshot.UpdatedAt.IsZero() || snapshot.UpdatedAt.Before(snapshot.CreatedAt) {
		return RegistrySnapshot{}, ErrInvalidRegistrySnapshot
	}
	if snapshot.OriginDeviceID != "" && !validSafeName(snapshot.OriginDeviceID) {
		return RegistrySnapshot{}, ErrInvalidRegistrySnapshot
	}
	normalized, err := normalizeRegistrySnapshotTrustMaterial(snapshot)
	if err != nil {
		return RegistrySnapshot{}, err
	}
	if snapshot.SchemaVersion == RegistrySnapshotSchemaVersion && snapshot.SnapshotFingerprint != snapshotFingerprint(normalized) {
		return RegistrySnapshot{}, ErrInvalidRegistrySnapshot
	}
	seen := map[string]string{}
	for _, dev := range normalized.Devices {
		if !validSafeName(dev.DeviceID) || strings.TrimSpace(dev.DisplayName) == "" || dev.DisplayName != strings.TrimSpace(dev.DisplayName) || dev.PublicKey == "" {
			return RegistrySnapshot{}, ErrInvalidRegistrySnapshot
		}
		if !validTrustStatus(dev.TrustStatus) || dev.ProfileMetadataVersion != metadataVersion {
			return RegistrySnapshot{}, ErrInvalidRegistrySnapshot
		}
		if (dev.TrustStatus == TrustTrusted || dev.TrustStatus == TrustRevoked) && dev.TrustedAt.IsZero() {
			return RegistrySnapshot{}, ErrInvalidRegistrySnapshot
		}
		if dev.TrustStatus == TrustRevoked {
			if dev.RevokedAt == nil || dev.RevokedAt.Before(dev.TrustedAt) {
				return RegistrySnapshot{}, ErrInvalidRegistrySnapshot
			}
		} else if dev.RevokedAt != nil {
			return RegistrySnapshot{}, ErrInvalidRegistrySnapshot
		}
		publicKey, err := decodePublicKey(dev.PublicKey)
		if err != nil {
			return RegistrySnapshot{}, err
		}
		fingerprint := fingerprintPublicKey(publicKey)
		if dev.PublicKeyFingerprint != fingerprint {
			return RegistrySnapshot{}, ErrFingerprintMismatch
		}
		if old, ok := seen[dev.DeviceID]; ok {
			if old != fingerprint {
				return RegistrySnapshot{}, ErrFingerprintMismatch
			}
			return RegistrySnapshot{}, ErrInvalidRegistrySnapshot
		}
		seen[dev.DeviceID] = fingerprint
	}
	normalized.SchemaVersion = RegistrySnapshotSchemaVersion
	normalized.Purpose = RegistrySnapshotLocalBackup
	normalized.SnapshotFingerprint = snapshotFingerprint(normalized)
	return normalized, nil
}

func validTrustStatus(status TrustStatus) bool {
	switch status {
	case TrustUnknown, TrustPending, TrustTrusted, TrustRevoked, TrustStale:
		return true
	default:
		return false
	}
}

func validateIdentityKeyPair(identity DeviceIdentity, privateKey ed25519.PrivateKey) error {
	publicKey, err := decodePublicKey(identity.PublicKey)
	if err != nil || identity.PublicKeyFingerprint != fingerprintPublicKey(publicKey) {
		return ErrStorageUnavailable
	}
	derived, ok := privateKey.Public().(ed25519.PublicKey)
	if !ok || !bytes.Equal(publicKey, derived) {
		return ErrStorageUnavailable
	}
	return nil
}

func publicIdentityBundleFingerprint(bundle PublicIdentityBundle) string {
	canonical := bundle
	canonical.BundleFingerprint = ""
	canonical.Capabilities = append([]string{}, bundle.Capabilities...)
	sort.Strings(canonical.Capabilities)
	raw, _ := json.Marshal(canonical)
	return sha256String(string(raw))
}

func publicIdentityBundleFromIdentity(identity DeviceIdentity) PublicIdentityBundle {
	bundle := PublicIdentityBundle{
		SchemaVersion:        schemaVersion,
		BundleVersion:        identityBundleVersion,
		DeviceID:             identity.DeviceID,
		DisplayName:          identity.DisplayName,
		AppID:                identity.AppID,
		Namespace:            identity.Namespace,
		PublicKey:            identity.PublicKey,
		PublicKeyFingerprint: identity.PublicKeyFingerprint,
		CreatedAt:            identity.CreatedAt,
		UpdatedAt:            identity.UpdatedAt,
		Capabilities:         append([]string{}, identity.Capabilities...),
		MetadataVersion:      identity.MetadataVersion,
	}
	bundle.BundleFingerprint = publicIdentityBundleFingerprint(bundle)
	return bundle
}

func proofReceiptFingerprint(receipt ProofReceipt) string {
	canonical := receipt
	canonical.ReceiptFingerprint = ""
	raw, _ := json.Marshal(canonical)
	return sha256String(string(raw))
}

func evaluateProof(now time.Time, localDeviceID string, dev TrustedDevice, link ConnectionStatus) ProofEvaluation {
	evaluation := ProofEvaluation{
		DeviceID:    dev.DeviceID,
		TrustStatus: dev.TrustStatus,
		State:       ProofStateUnverified,
		Reachable:   link.Reachable,
		EvaluatedAt: now,
		Reason:      "no signed proof is recorded",
	}
	if dev.TrustStatus != TrustTrusted {
		evaluation.State = ProofStateRejected
		evaluation.Reason = "device trust does not permit proof acceptance"
		return evaluation
	}
	if link.ProofReceipt == nil {
		return evaluation
	}
	receipt := *link.ProofReceipt
	evaluation.Receipt = &receipt
	if receipt.SchemaVersion != schemaVersion || !validSessionID(receipt.SessionID) || receipt.LocalDeviceID != localDeviceID || receipt.PeerDeviceID != dev.DeviceID || receipt.PeerPublicKeyFingerprint != dev.PublicKeyFingerprint || receipt.VerifiedAt.IsZero() || receipt.VerifiedAt.Before(dev.TrustedAt) || receipt.ExpiresAt.IsZero() || !receipt.ExpiresAt.After(receipt.VerifiedAt) || receipt.ChallengeFingerprint == "" || receipt.SignatureFingerprint == "" || receipt.ReceiptFingerprint == "" || receipt.ReceiptFingerprint != proofReceiptFingerprint(receipt) {
		evaluation.State = ProofStateRejected
		evaluation.Reason = "stored signed proof is invalid"
		return evaluation
	}
	if !now.Before(receipt.ExpiresAt) {
		evaluation.State = ProofStateExpired
		evaluation.Reason = "signed proof has expired"
		return evaluation
	}
	evaluation.State = ProofStateVerified
	evaluation.Satisfied = true
	evaluation.Reason = "signed device proof is verified"
	return evaluation
}

func sha256String(s string) string {
	sum := sha256.Sum256([]byte(s))
	return hex.EncodeToString(sum[:])
}

func handshakePayload(appID, namespace, challengerDeviceID, responderDeviceID, challenge string) []byte {
	parts := []string{
		"aegis-devicelink-v1",
		appID,
		namespace,
		challengerDeviceID,
		responderDeviceID,
		challenge,
	}
	return []byte(strings.Join(parts, "\n"))
}

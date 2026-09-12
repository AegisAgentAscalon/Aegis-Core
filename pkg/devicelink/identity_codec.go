package devicelink

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"sort"
	"strings"
	"time"
)

type identityFile struct {
	DeviceID             string    `json:"device_id"`
	DisplayName          string    `json:"display_name"`
	AppID                string    `json:"app_id"`
	Namespace            string    `json:"namespace"`
	PublicKey            string    `json:"public_key"`
	PublicKeyFingerprint string    `json:"public_key_fingerprint"`
	CreatedAt            time.Time `json:"created_at"`
	UpdatedAt            time.Time `json:"updated_at"`
	Capabilities         []string  `json:"capabilities"`
	MetadataVersion      int       `json:"metadata_version"`
}

func identityFileFrom(device DeviceIdentity) identityFile {
	out := identityFile(device)
	out.Capabilities = append([]string(nil), device.Capabilities...)
	return out
}

func (device identityFile) identity() DeviceIdentity {
	out := DeviceIdentity(device)
	out.Capabilities = append([]string(nil), device.Capabilities...)
	return out
}

func randomID(prefix string, n int) (string, error) {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return prefix + base64.RawURLEncoding.EncodeToString(b), nil
}

func fingerprintPublicKey(publicKey []byte) string {
	sum := sha256.Sum256(publicKey)
	return hex.EncodeToString(sum[:])[:16]
}

func encodePublicKey(publicKey ed25519.PublicKey) string {
	return base64.RawStdEncoding.EncodeToString(publicKey)
}

func decodePublicKey(encoded string) (ed25519.PublicKey, error) {
	raw, err := base64.RawStdEncoding.DecodeString(strings.TrimSpace(encoded))
	if err != nil {
		return nil, ErrInvalidPublicKey
	}
	if len(raw) != ed25519.PublicKeySize {
		return nil, ErrInvalidPublicKey
	}
	return ed25519.PublicKey(raw), nil
}

func decodePrivateKey(encoded string) (ed25519.PrivateKey, error) {
	raw, err := base64.RawStdEncoding.DecodeString(strings.TrimSpace(encoded))
	if err != nil {
		return nil, ErrStorageUnavailable
	}
	if len(raw) != ed25519.PrivateKeySize {
		return nil, ErrStorageUnavailable
	}
	return ed25519.PrivateKey(raw), nil
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

func sha256String(s string) string {
	sum := sha256.Sum256([]byte(s))
	return hex.EncodeToString(sum[:])
}

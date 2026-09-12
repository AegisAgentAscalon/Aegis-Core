package updates

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"strings"
)

func validateManifestVerificationKeys(keys map[string]string) error {
	for keyID, encoded := range keys {
		if !validSafeName(keyID) {
			return ErrInvalidConfig
		}
		if _, err := decodeEd25519PublicKey(encoded); err != nil {
			return ErrInvalidConfig
		}
	}
	return nil
}

func verifyManifestSignature(policy Policy, manifest Manifest) error {
	if !policy.RequireManifestSignature {
		return nil
	}
	signature := manifest.Signature
	if signature == nil || strings.TrimSpace(signature.Kind) == "" || strings.TrimSpace(signature.KeyID) == "" || strings.TrimSpace(signature.Signature) == "" {
		return ErrVerificationFailed
	}
	if signature.Kind != manifestSignatureKindEd25519 {
		return ErrVerificationFailed
	}
	encodedKey, ok := policy.ManifestVerificationKeys[signature.KeyID]
	if !ok {
		return ErrVerificationFailed
	}
	publicKey, err := decodeEd25519PublicKey(encodedKey)
	if err != nil {
		return ErrVerificationFailed
	}
	sig, err := decodeEd25519Signature(signature.Signature)
	if err != nil {
		return ErrVerificationFailed
	}
	payload, err := manifestSignaturePayload(manifest)
	if err != nil {
		return ErrInvalidManifest
	}
	if !ed25519.Verify(publicKey, payload, sig) {
		return ErrVerificationFailed
	}
	return nil
}

func manifestSignaturePayload(manifest Manifest) ([]byte, error) {
	unsigned := manifest
	unsigned.Signature = nil
	// This uses Go's JSON encoding, not a cross-language canonical JSON scheme.
	return json.Marshal(unsigned)
}

func decodeEd25519PublicKey(encoded string) (ed25519.PublicKey, error) {
	raw, err := base64.StdEncoding.DecodeString(strings.TrimSpace(encoded))
	if err != nil || len(raw) != ed25519.PublicKeySize {
		return nil, ErrInvalidConfig
	}
	return ed25519.PublicKey(raw), nil
}

func decodeEd25519Signature(encoded string) ([]byte, error) {
	raw, err := base64.StdEncoding.DecodeString(strings.TrimSpace(encoded))
	if err != nil || len(raw) != ed25519.SignatureSize {
		return nil, ErrVerificationFailed
	}
	return raw, nil
}

func requiredManifestKeyMatches(cfg AppConfig, manifest Manifest) bool {
	if cfg.Source.RequiredManifestKeyID == "" {
		return true
	}
	return manifest.Signature != nil && manifest.Signature.KeyID == cfg.Source.RequiredManifestKeyID
}

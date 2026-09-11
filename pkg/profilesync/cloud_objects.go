package profilesync

import (
	"crypto/sha256"
	"encoding/hex"
	"strings"
)

func ValidateCloudObject(object CloudSyncObject, maxBytes int) (CloudObjectRef, error) {
	if maxBytes <= 0 {
		maxBytes = DefaultMaxSyncObjectBytes
	}
	if !validSyncName(object.ProfileNamespace) || !validSyncID(object.ObjectID) || !validCloudObjectKind(object.Kind) || object.CreatedAt.IsZero() {
		return CloudObjectRef{}, ErrInvalidCloudObject
	}
	if len(object.Body) == 0 || len(object.Body) > maxBytes {
		if len(object.Body) > maxBytes {
			return CloudObjectRef{}, ErrCloudObjectTooLarge
		}
		return CloudObjectRef{}, ErrInvalidCloudObject
	}
	if err := ValidateCloudObjectMetadata(object.Metadata); err != nil {
		return CloudObjectRef{}, err
	}
	return CloudObjectRef{ProfileNamespace: object.ProfileNamespace, ObjectID: object.ObjectID, Kind: object.Kind, Hash: cloudObjectHash(object.Body), SizeBytes: len(object.Body), CreatedAt: object.CreatedAt}, nil
}

func ValidateCloudObjectRef(ref CloudObjectRef) error {
	if !validSyncName(ref.ProfileNamespace) || !validSyncID(ref.ObjectID) || !validCloudObjectKind(ref.Kind) || !validHash(ref.Hash) || ref.SizeBytes <= 0 || ref.SizeBytes > DefaultMaxSyncObjectBytes || ref.CreatedAt.IsZero() {
		return ErrInvalidCloudObject
	}
	return nil
}

func ValidateCloudObjectMetadata(metadata map[string]string) error {
	for k, v := range metadata {
		if !validSyncName(k) || unsafeSyncText(k) || unsafeSyncText(v) {
			return ErrInvalidCloudObject
		}
	}
	return nil
}

func sameCloudObjectRef(a, b CloudObjectRef) bool {
	return a.ProfileNamespace == b.ProfileNamespace &&
		a.ObjectID == b.ObjectID &&
		a.Kind == b.Kind &&
		a.Hash == b.Hash &&
		a.SizeBytes == b.SizeBytes &&
		a.CreatedAt.Equal(b.CreatedAt)
}

func cloudObjectHash(body []byte) string {
	sum := sha256.Sum256(body)
	return hex.EncodeToString(sum[:])
}

func validCloudObjectKind(kind CloudObjectKind) bool {
	switch kind {
	case CloudObjectSnapshotMetadata, CloudObjectProposalMetadata, CloudObjectConflictMetadata, CloudObjectResourceDescriptor, CloudObjectManifestMetadata:
		return true
	default:
		return false
	}
}

func validHash(value string) bool {
	if len(value) != 64 {
		return false
	}
	_, err := hex.DecodeString(value)
	return err == nil
}

func safeFileComponent(value string) string {
	value = strings.TrimSpace(value)
	value = strings.ReplaceAll(value, ":", "_")
	if !validSyncID(value) || strings.Contains(value, "/") || strings.Contains(value, `\`) || strings.Contains(value, "..") {
		return "invalid"
	}
	return value
}

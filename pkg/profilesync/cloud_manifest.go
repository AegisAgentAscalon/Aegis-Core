package profilesync

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"time"
)

func NormalizeCloudManifest(manifest CloudProfileManifest) (CloudProfileManifest, error) {
	if manifest.SchemaVersion == 0 {
		manifest.SchemaVersion = CloudManifestSchemaVersion
	}
	if manifest.SchemaVersion != CloudManifestSchemaVersion || !validSyncName(manifest.ProfileNamespace) || !validSyncID(manifest.ManifestID) || manifest.Generation < 0 || manifest.CreatedAt.IsZero() {
		return CloudProfileManifest{}, ErrInvalidCloudManifest
	}
	if err := validateCloudManifestCredentialBoundary(manifest); err != nil {
		return CloudProfileManifest{}, err
	}
	manifest.ProposalRefs = append([]CloudObjectRef{}, manifest.ProposalRefs...)
	manifest.ConflictRefs = append([]CloudObjectRef{}, manifest.ConflictRefs...)
	manifest.ResourceDescriptorRefs = append([]CloudObjectRef{}, manifest.ResourceDescriptorRefs...)
	if manifest.LatestSnapshotRef != nil {
		if err := validateCloudManifestRef(manifest.ProfileNamespace, *manifest.LatestSnapshotRef, CloudObjectSnapshotMetadata); err != nil {
			return CloudProfileManifest{}, err
		}
	}
	seenRefs := make(map[string]struct{})
	if manifest.LatestSnapshotRef != nil {
		if err := recordCloudManifestRefIdentity(seenRefs, *manifest.LatestSnapshotRef); err != nil {
			return CloudProfileManifest{}, err
		}
	}
	for _, ref := range manifest.ProposalRefs {
		if err := validateCloudManifestRef(manifest.ProfileNamespace, ref, CloudObjectProposalMetadata); err != nil {
			return CloudProfileManifest{}, err
		}
		if err := recordCloudManifestRefIdentity(seenRefs, ref); err != nil {
			return CloudProfileManifest{}, err
		}
	}
	for _, ref := range manifest.ConflictRefs {
		if err := validateCloudManifestRef(manifest.ProfileNamespace, ref, CloudObjectConflictMetadata); err != nil {
			return CloudProfileManifest{}, err
		}
		if err := recordCloudManifestRefIdentity(seenRefs, ref); err != nil {
			return CloudProfileManifest{}, err
		}
	}
	for _, ref := range manifest.ResourceDescriptorRefs {
		if err := validateCloudManifestRef(manifest.ProfileNamespace, ref, CloudObjectResourceDescriptor); err != nil {
			return CloudProfileManifest{}, err
		}
		if err := recordCloudManifestRefIdentity(seenRefs, ref); err != nil {
			return CloudProfileManifest{}, err
		}
	}
	expected := cloudManifestHash(manifest)
	if manifest.ManifestHash == "" {
		manifest.ManifestHash = expected
	}
	if manifest.ManifestHash != expected {
		return CloudProfileManifest{}, ErrCloudHashMismatch
	}
	return manifest, nil
}

func CompareCloudManifests(local *CloudProfileManifest, remote CloudProfileManifest, now time.Time) CloudManifestComparison {
	if now.IsZero() {
		now = time.Now().UTC()
	}
	remoteNormalized, err := NormalizeCloudManifest(remote)
	if err != nil {
		return cloudManifestComparison(CloudManifestInvalid, false, nil, nil, cloudIssue("invalid_remote_manifest", err, true))
	}
	if remoteNormalized.CreatedAt.After(now.Add(defaultClockSkew)) {
		return cloudManifestComparison(CloudManifestRemoteFutureDated, true, nil, &remoteNormalized, cloudIssue("remote_manifest_future_dated", ErrInvalidCloudManifest, true))
	}
	if local == nil || strings.TrimSpace(local.ManifestID) == "" {
		return cloudManifestComparison(CloudManifestLocalMissing, false, nil, &remoteNormalized)
	}
	localNormalized, err := NormalizeCloudManifest(*local)
	if err != nil {
		return cloudManifestComparison(CloudManifestInvalid, true, local, &remoteNormalized, cloudIssue("invalid_local_manifest", err, true))
	}
	switch {
	case remoteNormalized.Generation > localNormalized.Generation:
		return cloudManifestComparison(CloudManifestRemoteNewer, false, &localNormalized, &remoteNormalized)
	case remoteNormalized.Generation < localNormalized.Generation:
		return cloudManifestComparison(CloudManifestRemoteStale, true, &localNormalized, &remoteNormalized, cloudIssue("remote_manifest_stale", ErrInvalidCloudManifest, false))
	case remoteNormalized.ManifestHash == localNormalized.ManifestHash:
		return cloudManifestComparison(CloudManifestSame, false, &localNormalized, &remoteNormalized)
	default:
		return cloudManifestComparison(CloudManifestSameGenerationConflict, true, &localNormalized, &remoteNormalized, cloudIssue("remote_manifest_conflict", ErrConflictReview, true))
	}
}

func VerifyCloudManifestObjects(ctx context.Context, provider CloudProfileSyncProvider, manifest CloudProfileManifest) CloudManifestObjectVerification {
	if provider == nil {
		return CloudManifestObjectVerification{Verified: false, InvalidObjects: 1, Issues: []CloudSyncIssue{cloudIssue("cloud_provider_missing", ErrCloudProviderUnavailable, true)}}
	}
	manifest, err := NormalizeCloudManifest(manifest)
	if err != nil {
		return CloudManifestObjectVerification{Verified: false, InvalidObjects: 1, Issues: []CloudSyncIssue{cloudIssue("invalid_manifest", err, true)}}
	}
	result := CloudManifestObjectVerification{Verified: true}
	for _, expected := range cloudManifestRefs(manifest) {
		result.CheckedObjects++
		body, err := provider.GetObject(ctx, expected)
		if err != nil {
			result.Verified = false
			switch {
			case errors.Is(err, ErrCloudObjectNotFound):
				result.MissingObjects++
				result.Issues = append(result.Issues, cloudIssue("cloud_object_missing", err, true))
			case errors.Is(err, ErrCloudHashMismatch):
				result.HashMismatches++
				result.Issues = append(result.Issues, cloudIssue("cloud_object_hash_mismatch", err, true))
			default:
				result.InvalidObjects++
				result.Issues = append(result.Issues, cloudIssue("cloud_object_invalid", err, true))
			}
			continue
		}
		if len(body) != expected.SizeBytes || cloudObjectHash(body) != expected.Hash || expected.ProfileNamespace != manifest.ProfileNamespace {
			result.Verified = false
			result.HashMismatches++
			result.Issues = append(result.Issues, cloudIssue("cloud_object_hash_mismatch", ErrCloudHashMismatch, true))
		}
	}
	return result
}

func validateCloudManifestRef(profileNamespace string, ref CloudObjectRef, kind CloudObjectKind) error {
	if err := ValidateCloudObjectRef(ref); err != nil {
		return err
	}
	if ref.ProfileNamespace != profileNamespace || ref.Kind != kind {
		return ErrInvalidCloudManifest
	}
	return nil
}

func recordCloudManifestRefIdentity(seen map[string]struct{}, ref CloudObjectRef) error {
	key := ref.ProfileNamespace + "\x00" + string(ref.Kind) + "\x00" + ref.ObjectID
	if _, ok := seen[key]; ok {
		return ErrCloudObjectConflict
	}
	seen[key] = struct{}{}
	return nil
}

func cloudManifestComparison(relation CloudManifestRelation, review bool, local, remote *CloudProfileManifest, issues ...CloudSyncIssue) CloudManifestComparison {
	out := CloudManifestComparison{Relation: relation, ReviewRequired: review, Issues: issues}
	if local != nil {
		out.LocalHash = local.ManifestHash
		out.LocalGeneration = local.Generation
	}
	if remote != nil {
		out.RemoteHash = remote.ManifestHash
		out.RemoteGeneration = remote.Generation
	}
	return out
}

func cloudManifestRefs(manifest CloudProfileManifest) []CloudObjectRef {
	refs := make([]CloudObjectRef, 0, 1+len(manifest.ProposalRefs)+len(manifest.ConflictRefs)+len(manifest.ResourceDescriptorRefs))
	if manifest.LatestSnapshotRef != nil {
		refs = append(refs, *manifest.LatestSnapshotRef)
	}
	refs = append(refs, manifest.ProposalRefs...)
	refs = append(refs, manifest.ConflictRefs...)
	refs = append(refs, manifest.ResourceDescriptorRefs...)
	return refs
}

func cloudManifestHash(manifest CloudProfileManifest) string {
	copy := manifest
	copy.ManifestHash = ""
	raw, _ := json.Marshal(copy)
	return cloudObjectHash(raw)
}

func validateCloudManifestCredentialBoundary(manifest CloudProfileManifest) error {
	if manifest.SignerDeviceID != "" && !validSyncID(manifest.SignerDeviceID) {
		return ErrInvalidCloudManifest
	}
	if manifest.SignerKeyFingerprint != "" && !validHash(manifest.SignerKeyFingerprint) {
		return ErrInvalidCloudManifest
	}
	return nil
}

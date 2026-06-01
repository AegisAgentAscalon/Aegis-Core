package profilesync

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestFileObjectProviderManifestObjectLifecycle(t *testing.T) {
	ctx := context.Background()
	now := time.Now().UTC()
	provider := newTestFileObjectProvider(t, now)

	body := []byte(`{"snapshot_id":"snapshot-1","kind":"metadata"}`)
	ref, err := provider.PutObject(ctx, CloudSyncObject{ProfileNamespace: "profile-a", ObjectID: "snapshot-1", Kind: CloudObjectSnapshotMetadata, Body: body, CreatedAt: now, Metadata: map[string]string{"purpose": "metadata"}})
	if err != nil {
		t.Fatalf("PutObject returned error: %v", err)
	}
	if ref.Hash == "" || ref.SizeBytes != len(body) {
		t.Fatalf("unexpected ref: %+v", ref)
	}
	loaded, err := provider.GetObject(ctx, ref)
	if err != nil || string(loaded) != string(body) {
		t.Fatalf("GetObject = %s, %v", string(loaded), err)
	}
	refs, err := provider.ListObjects(ctx, CloudObjectQuery{ProfileNamespace: "profile-a", Kind: CloudObjectSnapshotMetadata})
	if err != nil || len(refs) != 1 || refs[0].ObjectID != ref.ObjectID {
		t.Fatalf("ListObjects = %+v, %v", refs, err)
	}

	manifest, err := NormalizeCloudManifest(CloudProfileManifest{SchemaVersion: CloudManifestSchemaVersion, ProfileNamespace: "profile-a", ManifestID: "manifest-1", Generation: 1, CreatedAt: now, LatestSnapshotRef: &ref})
	if err != nil {
		t.Fatalf("NormalizeCloudManifest returned error: %v", err)
	}
	if err := provider.PutManifest(ctx, manifest); err != nil {
		t.Fatalf("PutManifest returned error: %v", err)
	}
	loadedManifest, err := provider.GetManifest(ctx, "profile-a")
	if err != nil {
		t.Fatalf("GetManifest returned error: %v", err)
	}
	if loadedManifest.ManifestHash != manifest.ManifestHash || loadedManifest.LatestSnapshotRef.ObjectID != ref.ObjectID {
		t.Fatalf("unexpected manifest: %+v", loadedManifest)
	}
	status := provider.GetStatus(ctx)
	if !status.Available || status.ManifestCount != 1 || status.ObjectCount != 1 {
		t.Fatalf("unexpected status: %+v", status)
	}
	assertCloudStatusSafe(t, status)
}

func TestCloudManifestRejectsCrossNamespaceRefs(t *testing.T) {
	ctx := context.Background()
	now := time.Now().UTC()
	provider := newTestFileObjectProvider(t, now)

	foreignRef, err := ValidateCloudObject(CloudSyncObject{ProfileNamespace: "profile-b", ObjectID: "snapshot-foreign", Kind: CloudObjectSnapshotMetadata, Body: []byte("foreign metadata"), CreatedAt: now}, DefaultMaxSyncObjectBytes)
	if err != nil {
		t.Fatalf("ValidateCloudObject returned error: %v", err)
	}
	if _, err := NormalizeCloudManifest(CloudProfileManifest{SchemaVersion: CloudManifestSchemaVersion, ProfileNamespace: "profile-a", ManifestID: "manifest-cross", Generation: 1, CreatedAt: now, LatestSnapshotRef: &foreignRef}); !errors.Is(err, ErrInvalidCloudManifest) {
		t.Fatalf("cross-namespace latest snapshot ref error = %v", err)
	}
	if err := provider.PutManifest(ctx, CloudProfileManifest{SchemaVersion: CloudManifestSchemaVersion, ProfileNamespace: "profile-a", ManifestID: "manifest-cross", Generation: 1, CreatedAt: now, ProposalRefs: []CloudObjectRef{foreignRef}}); !errors.Is(err, ErrInvalidCloudManifest) {
		t.Fatalf("cross-namespace proposal ref error = %v", err)
	}
}

func TestCompareCloudManifestsClassifiesFreshnessAndConflicts(t *testing.T) {
	now := time.Now().UTC()
	local := validCloudManifestForTest(t, "manifest-local", 2, now, nil)
	same := local
	newer := validCloudManifestForTest(t, "manifest-newer", 3, now.Add(time.Minute), nil)
	stale := validCloudManifestForTest(t, "manifest-stale", 1, now.Add(-time.Minute), nil)
	future := validCloudManifestForTest(t, "manifest-future", 4, now.Add(defaultClockSkew+time.Minute), nil)
	conflict := validCloudManifestForTest(t, "manifest-conflict", 2, now, nil)

	cases := []struct {
		name   string
		local  *CloudProfileManifest
		remote CloudProfileManifest
		want   CloudManifestRelation
		review bool
	}{
		{"missing local", nil, newer, CloudManifestLocalMissing, false},
		{"remote newer", &local, newer, CloudManifestRemoteNewer, false},
		{"same", &local, same, CloudManifestSame, false},
		{"stale", &local, stale, CloudManifestRemoteStale, true},
		{"future", &local, future, CloudManifestRemoteFutureDated, true},
		{"same generation conflict", &local, conflict, CloudManifestSameGenerationConflict, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := CompareCloudManifests(tc.local, tc.remote, now)
			if got.Relation != tc.want || got.ReviewRequired != tc.review {
				t.Fatalf("CompareCloudManifests = %+v, want %s review=%v", got, tc.want, tc.review)
			}
			assertCloudComparisonSafe(t, got)
		})
	}

	invalid := newer
	invalid.ManifestHash = strings.Repeat("0", 64)
	got := CompareCloudManifests(&local, invalid, now)
	if got.Relation != CloudManifestInvalid {
		t.Fatalf("invalid manifest relation = %+v", got)
	}
}

func TestCompareCloudManifestsClockSkewBoundary(t *testing.T) {
	now := time.Now().UTC()
	local := validCloudManifestForTest(t, "manifest-local", 1, now, nil)
	withinSkew := validCloudManifestForTest(t, "manifest-within-skew", 2, now.Add(defaultClockSkew), nil)
	beyondSkew := validCloudManifestForTest(t, "manifest-beyond-skew", 2, now.Add(defaultClockSkew+time.Nanosecond), nil)

	if got := CompareCloudManifests(&local, withinSkew, now); got.Relation != CloudManifestRemoteNewer || got.ReviewRequired {
		t.Fatalf("within skew comparison = %+v", got)
	}
	got := CompareCloudManifests(&local, beyondSkew, now)
	if got.Relation != CloudManifestRemoteFutureDated || !got.ReviewRequired {
		t.Fatalf("beyond skew comparison = %+v", got)
	}
	assertCloudComparisonSafe(t, got)
}

func TestVerifyCloudManifestObjects(t *testing.T) {
	ctx := context.Background()
	now := time.Now().UTC()
	provider := newTestFileObjectProvider(t, now)

	snapshotRef, err := provider.PutObject(ctx, CloudSyncObject{ProfileNamespace: "profile-a", ObjectID: "snapshot-verify", Kind: CloudObjectSnapshotMetadata, Body: []byte("snapshot metadata body"), CreatedAt: now})
	if err != nil {
		t.Fatalf("PutObject snapshot returned error: %v", err)
	}
	proposalRef, err := provider.PutObject(ctx, CloudSyncObject{ProfileNamespace: "profile-a", ObjectID: "proposal-verify", Kind: CloudObjectProposalMetadata, Body: []byte("proposal metadata body"), CreatedAt: now})
	if err != nil {
		t.Fatalf("PutObject proposal returned error: %v", err)
	}
	manifest := validCloudManifestForTest(t, "manifest-verify", 1, now, &snapshotRef)
	manifest.ProposalRefs = []CloudObjectRef{proposalRef}
	manifest.ManifestHash = ""
	manifest, err = NormalizeCloudManifest(manifest)
	if err != nil {
		t.Fatalf("NormalizeCloudManifest returned error: %v", err)
	}
	result := VerifyCloudManifestObjects(ctx, provider, manifest)
	if !result.Verified || result.CheckedObjects != 2 {
		t.Fatalf("VerifyCloudManifestObjects = %+v", result)
	}

	missing := manifest
	missing.ProposalRefs[0].Hash = strings.Repeat("b", 64)
	missing.ManifestHash = ""
	missing, err = NormalizeCloudManifest(missing)
	if err != nil {
		t.Fatalf("Normalize missing fixture returned error: %v", err)
	}
	result = VerifyCloudManifestObjects(ctx, provider, missing)
	if result.Verified || result.MissingObjects != 1 {
		t.Fatalf("missing ref result = %+v", result)
	}
	assertCloudVerificationSafe(t, result)

	manifest = validCloudManifestForTest(t, "manifest-verify", 1, now, &snapshotRef)
	manifest.ProposalRefs = []CloudObjectRef{proposalRef}
	manifest.ManifestHash = ""
	manifest, err = NormalizeCloudManifest(manifest)
	if err != nil {
		t.Fatalf("renormalize manifest fixture returned error: %v", err)
	}
	path, err := provider.objectPath(snapshotRef)
	if err != nil {
		t.Fatalf("objectPath returned error: %v", err)
	}
	var file objectFile
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("ReadFile returned error: %v", err)
	}
	if err := json.Unmarshal(raw, &file); err != nil {
		t.Fatalf("Unmarshal returned error: %v", err)
	}
	file.Body = []byte("tampered snapshot metadata body")
	raw, _ = json.Marshal(file)
	if err := os.WriteFile(path, raw, 0o600); err != nil {
		t.Fatalf("WriteFile returned error: %v", err)
	}
	result = VerifyCloudManifestObjects(ctx, provider, manifest)
	if result.Verified || result.HashMismatches != 1 {
		t.Fatalf("tampered ref result = %+v", result)
	}
	assertCloudVerificationSafe(t, result)

	if err := os.WriteFile(path, []byte("{"), 0o600); err != nil {
		t.Fatalf("Write corrupt object returned error: %v", err)
	}
	result = VerifyCloudManifestObjects(ctx, provider, manifest)
	if result.Verified || result.InvalidObjects != 1 {
		t.Fatalf("corrupt object result = %+v", result)
	}
	assertCloudVerificationSafe(t, result)
}

func TestFileObjectProviderDuplicateObjectPolicy(t *testing.T) {
	ctx := context.Background()
	now := time.Now().UTC()
	provider := newTestFileObjectProvider(t, now)
	object := CloudSyncObject{ProfileNamespace: "profile-a", ObjectID: "duplicate-object", Kind: CloudObjectSnapshotMetadata, Body: []byte("same metadata body"), CreatedAt: now}
	first, err := provider.PutObject(ctx, object)
	if err != nil {
		t.Fatalf("first PutObject returned error: %v", err)
	}
	second, err := provider.PutObject(ctx, object)
	if err != nil || second.Hash != first.Hash {
		t.Fatalf("same duplicate should be idempotent: %+v, %v", second, err)
	}
	changed := object
	changed.Body = []byte("different metadata body")
	if _, err := provider.PutObject(ctx, changed); !errors.Is(err, ErrCloudObjectConflict) {
		t.Fatalf("different duplicate error = %v", err)
	}

	otherNamespace, err := NewFileObjectProvider(FileObjectProviderConfig{RootDir: t.TempDir(), ProfileNamespace: "profile-b", ProviderID: "file-object-test-b", Clock: &syncClock{now: now}})
	if err != nil {
		t.Fatalf("other namespace provider: %v", err)
	}
	if _, err := otherNamespace.PutObject(ctx, CloudSyncObject{ProfileNamespace: "profile-b", ObjectID: "duplicate-object", Kind: CloudObjectSnapshotMetadata, Body: []byte("different metadata body"), CreatedAt: now}); err != nil {
		t.Fatalf("different namespace duplicate returned error: %v", err)
	}
}

func TestCloudManifestDuplicateReferencedObjectPolicy(t *testing.T) {
	now := time.Now().UTC()
	first, err := ValidateCloudObject(CloudSyncObject{ProfileNamespace: "profile-a", ObjectID: "proposal-duplicate", Kind: CloudObjectProposalMetadata, Body: []byte("first metadata body"), CreatedAt: now}, DefaultMaxSyncObjectBytes)
	if err != nil {
		t.Fatalf("first ValidateCloudObject returned error: %v", err)
	}
	second, err := ValidateCloudObject(CloudSyncObject{ProfileNamespace: "profile-a", ObjectID: "proposal-duplicate", Kind: CloudObjectProposalMetadata, Body: []byte("second metadata body"), CreatedAt: now}, DefaultMaxSyncObjectBytes)
	if err != nil {
		t.Fatalf("second ValidateCloudObject returned error: %v", err)
	}

	if _, err := NormalizeCloudManifest(CloudProfileManifest{SchemaVersion: CloudManifestSchemaVersion, ProfileNamespace: "profile-a", ManifestID: "manifest-duplicate-ref", Generation: 1, CreatedAt: now, ProposalRefs: []CloudObjectRef{first, second}}); !errors.Is(err, ErrCloudObjectConflict) {
		t.Fatalf("duplicate manifest ref error = %v", err)
	}
	if _, err := NormalizeCloudManifest(CloudProfileManifest{SchemaVersion: CloudManifestSchemaVersion, ProfileNamespace: "profile-a", ManifestID: "manifest-exact-duplicate-ref", Generation: 1, CreatedAt: now, ProposalRefs: []CloudObjectRef{first, first}}); !errors.Is(err, ErrCloudObjectConflict) {
		t.Fatalf("exact duplicate manifest ref error = %v", err)
	}
}

func TestFileObjectProviderFailureModes(t *testing.T) {
	ctx := context.Background()
	now := time.Now().UTC()
	provider := newTestFileObjectProvider(t, now)

	if _, err := provider.GetManifest(ctx, "profile-a"); !errors.Is(err, ErrCloudObjectNotFound) {
		t.Fatalf("missing manifest error = %v", err)
	}
	if _, err := provider.PutObject(ctx, CloudSyncObject{ProfileNamespace: "../bad", ObjectID: "object-1", Kind: CloudObjectSnapshotMetadata, Body: []byte("body"), CreatedAt: now}); !errors.Is(err, ErrInvalidCloudObject) {
		t.Fatalf("invalid namespace error = %v", err)
	}
	if _, err := provider.PutObject(ctx, CloudSyncObject{ProfileNamespace: "profile-a", ObjectID: "../object", Kind: CloudObjectSnapshotMetadata, Body: []byte("body"), CreatedAt: now}); !errors.Is(err, ErrInvalidCloudObject) {
		t.Fatalf("path traversal id error = %v", err)
	}
	if _, err := provider.PutObject(ctx, CloudSyncObject{ProfileNamespace: "profile-a", ObjectID: "object-1", Kind: "kb_content", Body: []byte("body"), CreatedAt: now}); !errors.Is(err, ErrInvalidCloudObject) {
		t.Fatalf("invalid kind error = %v", err)
	}
	if _, err := provider.PutObject(ctx, CloudSyncObject{ProfileNamespace: "profile-a", ObjectID: "object-1", Kind: CloudObjectSnapshotMetadata, Body: make([]byte, DefaultMaxSyncObjectBytes+1), CreatedAt: now}); !errors.Is(err, ErrCloudObjectTooLarge) {
		t.Fatalf("oversized object error = %v", err)
	}
	if _, err := NewFileObjectProvider(FileObjectProviderConfig{RootDir: t.TempDir(), ProfileNamespace: "profile-a", ProviderID: "file-object-test", MaxObjectBytes: DefaultMaxSyncObjectBytes + 1, Clock: &syncClock{now: now}}); !errors.Is(err, ErrInvalidConfig) {
		t.Fatalf("oversized provider config error = %v", err)
	}
	if _, err := provider.PutObject(ctx, CloudSyncObject{ProfileNamespace: "profile-a", ObjectID: "object-1", Kind: CloudObjectSnapshotMetadata, Body: []byte("body"), CreatedAt: now, Metadata: map[string]string{"unsafe": `C:\Users\name\secret.txt`}}); !errors.Is(err, ErrInvalidCloudObject) {
		t.Fatalf("unsafe metadata error = %v", err)
	}
	if _, err := provider.PutObject(ctx, CloudSyncObject{ProfileNamespace: "profile-a", ObjectID: "object-2", Kind: CloudObjectSnapshotMetadata, Body: []byte("body"), CreatedAt: now, Metadata: map[string]string{"api_key": "redacted"}}); !errors.Is(err, ErrInvalidCloudObject) {
		t.Fatalf("credential metadata key error = %v", err)
	}
	if _, err := provider.PutObject(ctx, CloudSyncObject{ProfileNamespace: "profile-a", ObjectID: "object-3", Kind: CloudObjectSnapshotMetadata, Body: []byte("body"), CreatedAt: now, Metadata: map[string]string{"source": "Authorization: Bearer redacted"}}); !errors.Is(err, ErrInvalidCloudObject) {
		t.Fatalf("credential metadata value error = %v", err)
	}
	badManifest := CloudProfileManifest{SchemaVersion: CloudManifestSchemaVersion, ProfileNamespace: "profile-a", ManifestID: "manifest-1", Generation: 1, CreatedAt: now, ManifestHash: strings.Repeat("0", 64)}
	if err := provider.PutManifest(ctx, badManifest); !errors.Is(err, ErrCloudHashMismatch) {
		t.Fatalf("manifest hash mismatch error = %v", err)
	}
}

func TestCloudManifestCredentialBoundaryRejectsUnsafeSignerFields(t *testing.T) {
	now := time.Now().UTC()
	base := CloudProfileManifest{SchemaVersion: CloudManifestSchemaVersion, ProfileNamespace: "profile-a", ManifestID: "manifest-credential-boundary", Generation: 1, CreatedAt: now}
	withSignerSecret := base
	withSignerSecret.SignerDeviceID = "token=redacted"
	if _, err := NormalizeCloudManifest(withSignerSecret); !errors.Is(err, ErrInvalidCloudManifest) {
		t.Fatalf("unsafe signer device id error = %v", err)
	}
	withKeySecret := base
	withKeySecret.SignerDeviceID = "device-a"
	withKeySecret.SignerKeyFingerprint = "access_key_redacted"
	if _, err := NormalizeCloudManifest(withKeySecret); !errors.Is(err, ErrInvalidCloudManifest) {
		t.Fatalf("unsafe signer key fingerprint error = %v", err)
	}
	withSafeSigner := base
	withSafeSigner.SignerDeviceID = "device-a"
	withSafeSigner.SignerKeyFingerprint = strings.Repeat("b", 64)
	if _, err := NormalizeCloudManifest(withSafeSigner); err != nil {
		t.Fatalf("safe signer fields should normalize: %v", err)
	}
}

func TestCloudObjectRefsRejectUnsafeIDs(t *testing.T) {
	now := time.Now().UTC()
	base, err := ValidateCloudObject(CloudSyncObject{ProfileNamespace: "profile-a", ObjectID: "safe-object", Kind: CloudObjectSnapshotMetadata, Body: []byte("metadata body"), CreatedAt: now}, DefaultMaxSyncObjectBytes)
	if err != nil {
		t.Fatalf("ValidateCloudObject returned error: %v", err)
	}
	for _, objectID := range []string{"../object", `..\object`, `/tmp/object`, `C:\Users\name\object`, "object/child", "object..child"} {
		ref := base
		ref.ObjectID = objectID
		if err := ValidateCloudObjectRef(ref); !errors.Is(err, ErrInvalidCloudObject) {
			t.Fatalf("ValidateCloudObjectRef(%q) = %v", objectID, err)
		}
		if _, err := NormalizeCloudManifest(CloudProfileManifest{SchemaVersion: CloudManifestSchemaVersion, ProfileNamespace: "profile-a", ManifestID: "manifest-unsafe-ref", Generation: 1, CreatedAt: now, LatestSnapshotRef: &ref}); !errors.Is(err, ErrInvalidCloudObject) {
			t.Fatalf("NormalizeCloudManifest(%q) = %v", objectID, err)
		}
	}
}

func TestFileObjectProviderCorruptionAndHashMismatch(t *testing.T) {
	ctx := context.Background()
	now := time.Now().UTC()
	provider := newTestFileObjectProvider(t, now)

	ref, err := provider.PutObject(ctx, CloudSyncObject{ProfileNamespace: "profile-a", ObjectID: "object-1", Kind: CloudObjectSnapshotMetadata, Body: []byte("safe metadata body"), CreatedAt: now})
	if err != nil {
		t.Fatalf("PutObject returned error: %v", err)
	}
	path, err := provider.objectPath(ref)
	if err != nil {
		t.Fatalf("objectPath returned error: %v", err)
	}
	var file objectFile
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("ReadFile returned error: %v", err)
	}
	if err := json.Unmarshal(raw, &file); err != nil {
		t.Fatalf("Unmarshal returned error: %v", err)
	}
	file.Body = []byte("tampered metadata body")
	raw, _ = json.Marshal(file)
	if err := os.WriteFile(path, raw, 0o600); err != nil {
		t.Fatalf("WriteFile returned error: %v", err)
	}
	if _, err := provider.GetObject(ctx, ref); !errors.Is(err, ErrCloudHashMismatch) {
		t.Fatalf("hash mismatch error = %v", err)
	}

	if err := os.WriteFile(path, []byte("{"), 0o600); err != nil {
		t.Fatalf("Write corrupt object returned error: %v", err)
	}
	if _, err := provider.ListObjects(ctx, CloudObjectQuery{ProfileNamespace: "profile-a"}); !errors.Is(err, ErrCloudStoreCorrupt) {
		t.Fatalf("corrupt object list error = %v", err)
	}
	status := provider.GetStatus(ctx)
	if status.Available || len(status.Issues) == 0 {
		t.Fatalf("corrupt status should be degraded: %+v", status)
	}
	assertCloudStatusSafe(t, status)

	_ = os.WriteFile(filepath.Join(provider.namespaceRoot(), "cloud-object.tmp"), []byte("partial"), 0o600)
	if _, err := provider.ListObjects(ctx, CloudObjectQuery{ProfileNamespace: "profile-a"}); !errors.Is(err, ErrCloudStoreCorrupt) {
		t.Fatalf("corrupt object should still fail closed after temp file: %v", err)
	}
}

func TestFileObjectProviderCorruptManifestStatusIsSafe(t *testing.T) {
	ctx := context.Background()
	now := time.Now().UTC()
	provider := newTestFileObjectProvider(t, now)

	if err := os.WriteFile(filepath.Join(provider.namespaceRoot(), "manifest.json"), []byte("{"), 0o600); err != nil {
		t.Fatalf("Write corrupt manifest returned error: %v", err)
	}
	if _, err := provider.GetManifest(ctx, "profile-a"); !errors.Is(err, ErrCloudStoreCorrupt) {
		t.Fatalf("corrupt manifest error = %v", err)
	}
	status := provider.GetStatus(ctx)
	if status.Available || len(status.Issues) == 0 {
		t.Fatalf("corrupt manifest status should be degraded: %+v", status)
	}
	assertCloudStatusSafe(t, status)
}

func TestVerifyCloudManifestObjectsSanitizesProviderErrors(t *testing.T) {
	ctx := context.Background()
	now := time.Now().UTC()
	ref, err := ValidateCloudObject(CloudSyncObject{ProfileNamespace: "profile-a", ObjectID: "snapshot-redacted", Kind: CloudObjectSnapshotMetadata, Body: []byte("redacted metadata body"), CreatedAt: now}, DefaultMaxSyncObjectBytes)
	if err != nil {
		t.Fatalf("ValidateCloudObject returned error: %v", err)
	}
	manifest := validCloudManifestForTest(t, "manifest-redacted-provider", 1, now, &ref)
	result := VerifyCloudManifestObjects(ctx, rawCloudFailureProvider{}, manifest)
	if result.Verified || result.InvalidObjects != 1 {
		t.Fatalf("raw provider error result = %+v", result)
	}
	assertCloudVerificationSafe(t, result)
}

func TestCloudProviderStatusSanitizesCredentialLikeDetails(t *testing.T) {
	status := sanitizeCloudProviderStatus(CloudSyncProviderStatus{
		Available:        false,
		ProviderID:       "provider-token=redacted",
		ProfileNamespace: `C:\Users\name\AppData\profile-a`,
		Summary:          "Authorization: Bearer redacted raw provider body",
		Issues: []CloudSyncIssue{{
			Code:     "access_key_redacted",
			Message:  `provider failed at C:\Users\name\Desktop\manifest.json?token=redacted with raw object payload`,
			Blocking: true,
		}},
	})
	if status.ProviderID != "" || status.ProfileNamespace != "" || len(status.Issues) != 1 || status.Issues[0].Code != "cloud_sync_issue" {
		t.Fatalf("status should redact unsafe identifiers: %+v", status)
	}
	assertCloudStatusSafe(t, status)
}

type rawCloudFailureProvider struct{}

func (rawCloudFailureProvider) GetStatus(context.Context) CloudSyncProviderStatus {
	return CloudSyncProviderStatus{Available: false, Summary: "provider unavailable"}
}

func (rawCloudFailureProvider) GetManifest(context.Context, string) (CloudProfileManifest, error) {
	return CloudProfileManifest{}, ErrCloudProviderUnavailable
}

func (rawCloudFailureProvider) PutManifest(context.Context, CloudProfileManifest) error {
	return ErrCloudProviderUnavailable
}

func (rawCloudFailureProvider) GetObject(context.Context, CloudObjectRef) ([]byte, error) {
	return nil, errors.New(`provider failed at C:\Users\name\Desktop\manifest.json?token=abc Authorization: Bearer redacted access_key=raw with raw object payload`)
}

func (rawCloudFailureProvider) PutObject(context.Context, CloudSyncObject) (CloudObjectRef, error) {
	return CloudObjectRef{}, ErrCloudProviderUnavailable
}

func (rawCloudFailureProvider) ListObjects(context.Context, CloudObjectQuery) ([]CloudObjectRef, error) {
	return nil, ErrCloudProviderUnavailable
}

func validCloudManifestForTest(t *testing.T, manifestID string, generation int64, createdAt time.Time, snapshotRef *CloudObjectRef) CloudProfileManifest {
	t.Helper()
	manifest, err := NormalizeCloudManifest(CloudProfileManifest{SchemaVersion: CloudManifestSchemaVersion, ProfileNamespace: "profile-a", ManifestID: manifestID, Generation: generation, CreatedAt: createdAt, LatestSnapshotRef: snapshotRef})
	if err != nil {
		t.Fatalf("NormalizeCloudManifest returned error: %v", err)
	}
	return manifest
}

func newTestFileObjectProvider(t *testing.T, now time.Time) *FileObjectProvider {
	t.Helper()
	provider, err := NewFileObjectProvider(FileObjectProviderConfig{RootDir: t.TempDir(), ProfileNamespace: "profile-a", ProviderID: "file-object-test", Clock: &syncClock{now: now}})
	if err != nil {
		t.Fatalf("NewFileObjectProvider returned error: %v", err)
	}
	return provider
}

func assertCloudComparisonSafe(t *testing.T, comparison CloudManifestComparison) {
	t.Helper()
	raw, err := json.Marshal(comparison)
	if err != nil {
		t.Fatalf("marshal comparison: %v", err)
	}
	assertCloudTextSafe(t, string(raw))
}

func assertCloudVerificationSafe(t *testing.T, verification CloudManifestObjectVerification) {
	t.Helper()
	raw, err := json.Marshal(verification)
	if err != nil {
		t.Fatalf("marshal verification: %v", err)
	}
	assertCloudTextSafe(t, string(raw))
}

func assertCloudStatusSafe(t *testing.T, status CloudSyncProviderStatus) {
	t.Helper()
	raw, err := json.Marshal(status)
	if err != nil {
		t.Fatalf("marshal status: %v", err)
	}
	assertCloudTextSafe(t, string(raw))
}

func assertCloudTextSafe(t *testing.T, raw string) {
	t.Helper()
	text := strings.ToLower(raw)
	for _, unsafe := range []string{"client_secret", "refresh_token", "access_token", "private_key", "api_key", "access_key", "authorization", "bearer", "token=", "password=", "secret=", `c:\\users\\`, "appdata", "desktop", "safe metadata body", "tampered metadata body"} {
		if strings.Contains(text, unsafe) {
			t.Fatalf("unsafe cloud detail %q in %s", unsafe, raw)
		}
	}
}

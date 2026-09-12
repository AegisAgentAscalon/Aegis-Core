package profilesync

import (
	"context"
	"encoding/json"
	"errors"
	"testing"
	"time"
)

func TestCloudManifestRejectsUnserializableTimestamps(t *testing.T) {
	// Go accepts this offset on JSON decode, but MarshalJSON rejects it. An
	// encoding failure must never collapse different manifests to one hash.
	var invalidTime time.Time
	if err := json.Unmarshal([]byte(`"2026-09-12T12:00:00+24:00"`), &invalidTime); err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, 9, 12, 12, 0, 0, 0, time.UTC)
	for _, field := range []string{"manifest", "latest_snapshot", "proposal", "conflict", "resource"} {
		t.Run(field, func(t *testing.T) {
			provider := newTestFileObjectProvider(t, now)
			ctx := context.Background()
			original := validCloudManifestForTest(t, "original", 1, now, nil)
			if err := provider.PutManifest(ctx, original); err != nil {
				t.Fatal(err)
			}
			invalid := original
			invalid.ManifestHash = ""
			invalid.ManifestID = "changed"
			ref := CloudObjectRef{ProfileNamespace: "profile-a", ObjectID: "object", Hash: cloudObjectHash([]byte("metadata")), SizeBytes: len("metadata"), CreatedAt: invalidTime}
			switch field {
			case "manifest":
				invalid.CreatedAt = invalidTime
			case "latest_snapshot":
				ref.Kind = CloudObjectSnapshotMetadata
				invalid.LatestSnapshotRef = &ref
			case "proposal":
				ref.Kind = CloudObjectProposalMetadata
				invalid.ProposalRefs = []CloudObjectRef{ref}
			case "conflict":
				ref.Kind = CloudObjectConflictMetadata
				invalid.ConflictRefs = []CloudObjectRef{ref}
			case "resource":
				ref.Kind = CloudObjectResourceDescriptor
				invalid.ResourceDescriptorRefs = []CloudObjectRef{ref}
			}
			if _, err := NormalizeCloudManifest(invalid); !errors.Is(err, ErrInvalidCloudManifest) {
				t.Fatalf("invalid timestamp normalized: %v", err)
			}
			other := invalid
			other.ManifestID = "another-change"
			for _, comparison := range []CloudManifestComparison{
				CompareCloudManifests(&original, invalid, now),
				CompareCloudManifests(&invalid, original, now),
				CompareCloudManifests(&invalid, other, now),
			} {
				if comparison.Relation != CloudManifestInvalid || len(comparison.Issues) == 0 || !comparison.Issues[0].Blocking {
					t.Fatalf("invalid timestamp admitted by comparison: %+v", comparison)
				}
			}
			if verification := VerifyCloudManifestObjects(ctx, provider, invalid); verification.Verified || verification.CheckedObjects != 0 || verification.InvalidObjects != 1 {
				t.Fatalf("invalid manifest reached object verification: %+v", verification)
			}
			if err := provider.PutManifest(ctx, invalid); !errors.Is(err, ErrInvalidCloudManifest) {
				t.Fatalf("invalid manifest reached storage: %v", err)
			}
			loaded, err := provider.GetManifest(ctx, original.ProfileNamespace)
			if err != nil || loaded.ManifestHash != original.ManifestHash || loaded.ManifestID != original.ManifestID {
				t.Fatalf("rejected manifest changed stored authority: %+v, %v", loaded, err)
			}
		})
	}
}

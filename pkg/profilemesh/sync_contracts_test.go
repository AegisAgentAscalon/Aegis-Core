package profilemesh

import (
	"encoding/json"
	"strings"
	"testing"
	"time"
)

func TestProfileSyncSnapshotValidationFreshnessAndFailureModes(t *testing.T) {
	now := time.Date(2026, 5, 5, 12, 0, 0, 0, time.UTC)
	snapshot := validSignedProfileSnapshot(now)
	result := ValidateSignedProfileSnapshot(snapshot, now)
	if !result.Valid || !result.Freshness.Fresh {
		t.Fatalf("expected valid fresh snapshot, got %+v", result)
	}
	assertProfileSyncSafeJSON(t, result)

	stale := snapshot
	stale.Metadata.CreatedAt = now.Add(-DefaultSnapshotFreshnessWindow - 2*time.Minute)
	stale.Metadata.UpdatedAt = now.Add(-DefaultSnapshotFreshnessWindow - time.Minute)
	staleResult := ValidateSignedProfileSnapshot(stale, now)
	if !staleResult.Valid || !staleResult.Freshness.Stale {
		t.Fatalf("stale metadata should be represented as non-blocking stale freshness: %+v", staleResult)
	}

	future := snapshot
	future.Metadata.UpdatedAt = now.Add(DefaultSnapshotClockSkew + time.Second)
	futureResult := ValidateSignedProfileSnapshot(future, now)
	if futureResult.Valid || !futureResult.Freshness.FutureDated {
		t.Fatalf("future-dated snapshot should block validation: %+v", futureResult)
	}

	skew := snapshot
	skew.Metadata.UpdatedAt = now.Add(DefaultSnapshotClockSkew - time.Second)
	skew.Metadata.ExpiresAt = now.Add(time.Hour)
	skewResult := ValidateSignedProfileSnapshot(skew, now)
	if !skewResult.Valid || skewResult.Freshness.FutureDated {
		t.Fatalf("snapshot within clock skew should remain valid: %+v", skewResult)
	}
}

func TestProfileSyncExpiryBoundaryIsStale(t *testing.T) {
	now := time.Date(2026, 5, 5, 12, 0, 0, 0, time.UTC)
	metadata := validSignedProfileSnapshot(now).Metadata
	metadata.ExpiresAt = now.Add(-DefaultSnapshotClockSkew)
	boundary := BuildProfileFreshnessSummary(metadata, now)
	if !boundary.Stale || boundary.Fresh {
		t.Fatalf("snapshot at expiry boundary should be stale: %+v", boundary)
	}
	metadata.ExpiresAt = metadata.ExpiresAt.Add(time.Nanosecond)
	inside := BuildProfileFreshnessSummary(metadata, now)
	if inside.Stale || !inside.Fresh {
		t.Fatalf("snapshot just inside expiry boundary should remain fresh: %+v", inside)
	}
}

func TestProfileSyncSnapshotRejectsMalformedMetadata(t *testing.T) {
	now := time.Date(2026, 5, 5, 12, 0, 0, 0, time.UTC)
	cases := []struct {
		name string
		edit func(*SignedProfileSnapshot)
	}{
		{"invalid namespace", func(s *SignedProfileSnapshot) { s.Metadata.ProfileNamespace = "../bad" }},
		{"invalid snapshot id", func(s *SignedProfileSnapshot) { s.Metadata.SnapshotID = "bad/snapshot" }},
		{"invalid fingerprint", func(s *SignedProfileSnapshot) { s.Metadata.SnapshotFingerprint = "not-a-fingerprint" }},
		{"missing signer", func(s *SignedProfileSnapshot) { s.Signature.SignerDeviceID = "" }},
		{"invalid signer", func(s *SignedProfileSnapshot) { s.Signature.SignerDeviceID = `..\device` }},
		{"multi-host unsupported", func(s *SignedProfileSnapshot) { s.Metadata.HostingMode = HostingMultiProfileDevices }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			snapshot := validSignedProfileSnapshot(now)
			tc.edit(&snapshot)
			result := ValidateSignedProfileSnapshot(snapshot, now)
			if result.Valid {
				t.Fatalf("expected invalid result for %s: %+v", tc.name, result)
			}
			assertProfileSyncSafeJSON(t, result)
		})
	}
}

func TestProfileSyncProposalValidationAndSafeConflicts(t *testing.T) {
	now := time.Date(2026, 5, 5, 12, 0, 0, 0, time.UTC)
	proposal := validProfileChangeProposal(now)
	result := ValidateProfileChangeProposal(proposal, now)
	if !result.Valid || result.RequiresUserReview {
		t.Fatalf("expected valid non-conflicting proposal, got %+v", result)
	}

	withConflict := proposal
	withConflict.RequiresUserReview = true
	withConflict.Conflicts = []ConflictSummary{{ConflictID: "conflict-1", ResourceID: "profile-kb", ResourceType: "profile_data", Summary: "two offline edits touched the same profile note"}}
	conflictResult := ValidateProfileChangeProposal(withConflict, now)
	if !conflictResult.Valid || !conflictResult.RequiresUserReview || len(conflictResult.Conflicts) != 1 || !conflictResult.Conflicts[0].RequiresUserReview {
		t.Fatalf("expected safe conflict requiring review, got %+v", conflictResult)
	}
	assertProfileSyncSafeJSON(t, conflictResult)

	unsafeConflict := withConflict
	unsafeConflict.Conflicts[0].Summary = `secret token at C:\Users\person\AppData\profile_data.json`
	unsafeResult := ValidateProfileChangeProposal(unsafeConflict, now)
	if unsafeResult.Valid || strings.Contains(strings.ToLower(unsafeResult.Conflicts[0].Summary), "secret") || strings.Contains(unsafeResult.Conflicts[0].Summary, `C:\`) {
		t.Fatalf("unsafe conflict should be rejected and sanitized, got %+v", unsafeResult)
	}
	assertProfileSyncSafeJSON(t, unsafeResult)
}

func TestProfileSyncProposalRejectsMalformedAndUnsupportedInputs(t *testing.T) {
	now := time.Date(2026, 5, 5, 12, 0, 0, 0, time.UTC)
	cases := []struct {
		name string
		edit func(*ProfileChangeProposal)
	}{
		{"malformed proposal", func(p *ProfileChangeProposal) { p.ProposalID = "" }},
		{"invalid branch", func(p *ProfileChangeProposal) { p.SourceBranchID = "branch/one" }},
		{"future dated", func(p *ProfileChangeProposal) { p.UpdatedAt = now.Add(DefaultSnapshotClockSkew + time.Second) }},
		{"multi-host requested", func(p *ProfileChangeProposal) { p.RequestedHostingMode = HostingMultiProfileDevices }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			proposal := validProfileChangeProposal(now)
			tc.edit(&proposal)
			result := ValidateProfileChangeProposal(proposal, now)
			if result.Valid {
				t.Fatalf("expected invalid proposal for %s: %+v", tc.name, result)
			}
			assertProfileSyncSafeJSON(t, result)
		})
	}
}

func TestOfflineProfileBranchValidationDetectsDuplicateBranches(t *testing.T) {
	now := time.Date(2026, 5, 5, 12, 0, 0, 0, time.UTC)
	branches := []OfflineProfileBranch{
		validOfflineBranch("branch-1", now),
		validOfflineBranch("branch-1", now),
	}
	result := ValidateOfflineProfileBranches(branches)
	if result.Valid || !result.RequiresUserReview || len(result.Conflicts) != 1 {
		t.Fatalf("expected duplicate branch conflict, got %+v", result)
	}
	assertProfileSyncSafeJSON(t, result)
}

func validSignedProfileSnapshot(now time.Time) SignedProfileSnapshot {
	return SignedProfileSnapshot{
		Metadata: ProfileSnapshotMetadata{
			SchemaVersion:       1,
			ProfileNamespace:    "profile-a",
			ProfileID:           "profile-1",
			SnapshotID:          "snapshot-1",
			SnapshotFingerprint: strings.Repeat("a", 64),
			SourceDeviceID:      "device-1",
			HostingMode:         HostingSingleProfileDevice,
			CreatedAt:           now.Add(-time.Minute),
			UpdatedAt:           now,
			ExpiresAt:           now.Add(time.Hour),
			MetadataVersion:     1,
		},
		Signature: SnapshotSignatureSummary{
			SignerDeviceID:       "device-1",
			SignerKeyFingerprint: strings.Repeat("b", 64),
			SignatureFingerprint: strings.Repeat("c", 64),
			Algorithm:            "ed25519-summary",
			SignedAt:             now,
		},
	}
}

func validProfileChangeProposal(now time.Time) ProfileChangeProposal {
	return ProfileChangeProposal{
		ProposalID:           "proposal-1",
		ProfileNamespace:     "profile-a",
		ProfileID:            "profile-1",
		BaseSnapshotID:       "snapshot-1",
		ProposedSnapshotID:   "snapshot-2",
		SourceBranchID:       "branch-1",
		TargetBranchID:       "branch-main",
		AuthorDeviceID:       "device-1",
		Status:               ProposalStatusPendingReview,
		RequestedHostingMode: HostingSingleProfileDevice,
		CreatedAt:            now.Add(-time.Minute),
		UpdatedAt:            now,
		MergePlan:            MergePlan{FutureOnly: true, Summary: "future merge plan placeholder"},
	}
}

func validOfflineBranch(branchID string, now time.Time) OfflineProfileBranch {
	return OfflineProfileBranch{
		BranchID:         branchID,
		ProfileNamespace: "profile-a",
		ProfileID:        "profile-1",
		BaseSnapshotID:   "snapshot-1",
		HeadSnapshotID:   "snapshot-2",
		OwnerDeviceID:    "device-1",
		CreatedAt:        now.Add(-time.Minute),
		UpdatedAt:        now,
		Status:           "offline",
	}
}

func assertProfileSyncSafeJSON(t *testing.T, v any) {
	t.Helper()
	raw, err := json.Marshal(v)
	if err != nil {
		t.Fatalf("json marshal failed: %v", err)
	}
	text := strings.ToLower(string(raw))
	for _, forbidden := range []string{"client_secret", "refresh_token", "access_token", "id_token", "auth_code", "verifier", "private_key", "begin private key", "github_pat", "ghp_", "token=", "password=", "secret=", `c:\\users\\`, "appdata", "downloads"} {
		if strings.Contains(text, forbidden) {
			t.Fatalf("unsafe sync JSON detail %q in %s", forbidden, string(raw))
		}
	}
}

package profilesync

import (
	"context"
	"testing"
	"time"

	"github.com/AegisAgentAscalon/aegis-core/pkg/profilemesh"
	"github.com/AegisAgentAscalon/aegis-core/pkg/relay"
)

func TestPullRemoteProposalClassifiesCompetingProposalAsReviewRequired(t *testing.T) {
	ctx := context.Background()
	now := time.Now().UTC()
	h := newConflictReviewHarness(t, now)

	existing := validSyncProposal("proposal-existing", "snapshot-local", now)
	existing.ProposedSnapshotID = "snapshot-existing"
	if err := h.store.SaveRemoteProposal(ctx, RemoteProposalRecord{Proposal: existing, ReceivedAt: now, TrustState: TrustTrusted}); err != nil {
		t.Fatalf("SaveRemoteProposal returned error: %v", err)
	}
	competing := validSyncProposal("proposal-competing", "snapshot-local", now)
	competing.ProposedSnapshotID = "snapshot-competing"
	sendSyncEnvelope(t, h.provider, h.mailbox.MailboxID, proposalEnvelope("profile-a", "device-remote", competing, now), now, "msg-competing-proposal")

	pull, err := h.manager.PullRemote(ctx)
	if err != nil || pull.ReceivedProposals != 1 || !pull.ReviewRequired || !hasSyncIssue(pull.Issues, "competing_proposal_review_required") {
		t.Fatalf("competing proposal pull = %+v, %v", pull, err)
	}
	records, err := h.store.ListRemoteProposals(ctx)
	if err != nil || len(records) != 2 {
		t.Fatalf("remote proposals = %+v, %v", records, err)
	}
	var found bool
	for _, record := range records {
		if record.Proposal.ProposalID == competing.ProposalID {
			found = true
			if !record.RequiresReview {
				t.Fatalf("competing proposal should require review: %+v", record)
			}
		}
	}
	if !found {
		t.Fatalf("competing proposal was not stored for app-owned review: %+v", records)
	}
	status := h.manager.BuildStatus(ctx)
	if !status.ReviewRequired || !hasSyncIssue(status.Issues, "conflict_review_required") {
		t.Fatalf("status should surface review requirement: %+v", status)
	}
	assertSyncSafeJSON(t, pull)
	assertSyncSafeJSON(t, status)
}

func TestPullRemoteProposalClassifiesSupersededProposalAsReviewRequired(t *testing.T) {
	ctx := context.Background()
	now := time.Now().UTC()
	h := newConflictReviewHarness(t, now)

	existing := validSyncProposal("proposal-existing", "snapshot-local", now)
	existing.ProposedSnapshotID = "snapshot-intermediate"
	if err := h.store.SaveRemoteProposal(ctx, RemoteProposalRecord{Proposal: existing, ReceivedAt: now, TrustState: TrustTrusted}); err != nil {
		t.Fatalf("SaveRemoteProposal returned error: %v", err)
	}
	successor := validSyncProposal("proposal-successor", "snapshot-intermediate", now)
	successor.ProposedSnapshotID = "snapshot-successor"
	sendSyncEnvelope(t, h.provider, h.mailbox.MailboxID, proposalEnvelope("profile-a", "device-remote", successor, now), now, "msg-superseded-proposal")

	pull, err := h.manager.PullRemote(ctx)
	if err != nil || pull.ReceivedProposals != 1 || !pull.ReviewRequired || !hasSyncIssue(pull.Issues, "superseded_proposal_review_required") {
		t.Fatalf("superseded proposal pull = %+v, %v", pull, err)
	}
	records, err := h.store.ListRemoteProposals(ctx)
	if err != nil || len(records) != 2 {
		t.Fatalf("remote proposals = %+v, %v", records, err)
	}
	for _, record := range records {
		if record.Proposal.ProposalID == successor.ProposalID && !record.RequiresReview {
			t.Fatalf("successor proposal should remain review-required: %+v", record)
		}
	}
	plan, err := h.manager.BuildSyncPlan(ctx)
	if err != nil || !plan.ConflictReviewNeeded || !hasSyncIssue(plan.Issues, "conflict_review_required") {
		t.Fatalf("plan should surface review requirement: %+v, %v", plan, err)
	}
	assertSyncSafeJSON(t, pull)
	assertSyncSafeJSON(t, plan)
}

func TestPullRemoteProposalRejectsUnsafeConflictSummarySafely(t *testing.T) {
	ctx := context.Background()
	now := time.Now().UTC()
	h := newConflictReviewHarness(t, now)

	proposal := validSyncProposal("proposal-unsafe-conflict", "snapshot-local", now)
	proposal.RequiresUserReview = true
	proposal.Conflicts = append(proposal.Conflicts, unsafeProfileConflictSummary())
	sendSyncEnvelope(t, h.provider, h.mailbox.MailboxID, proposalEnvelope("profile-a", "device-remote", proposal, now), now, "msg-unsafe-conflict")

	pull, err := h.manager.PullRemote(ctx)
	if err != nil || pull.ReceivedProposals != 0 || pull.Rejected != 1 || !hasSyncIssue(pull.Issues, "unsafe_conflict_summary") {
		t.Fatalf("unsafe conflict summary should reject safely: %+v, %v", pull, err)
	}
	assertSyncSafeJSON(t, pull)
}

func TestSameGenerationDivergentManifestConflictIsReviewRequiredAndSafe(t *testing.T) {
	now := time.Now().UTC()
	local := validCloudManifestForTest(t, "manifest-local", 3, now, nil)
	remote := validCloudManifestForTest(t, "manifest-remote-divergent", 3, now, nil)

	comparison := CompareCloudManifests(&local, remote, now)
	if comparison.Relation != CloudManifestSameGenerationConflict || !comparison.ReviewRequired || !hasCloudIssue(comparison.Issues, "remote_manifest_conflict") {
		t.Fatalf("same-generation divergent manifest comparison = %+v", comparison)
	}
	assertCloudComparisonSafe(t, comparison)
}

type conflictReviewHarness struct {
	provider relay.RelayProvider
	mailbox  relay.MailboxRef
	store    *MemoryMetadataStore
	manager  *SyncManager
}

func newConflictReviewHarness(t *testing.T, now time.Time) conflictReviewHarness {
	t.Helper()
	clock := &syncClock{now: now}
	provider, err := relay.NewLocalDevProvider(relay.LocalDevProviderConfig{ProviderID: "local-dev-relay", Clock: clock})
	if err != nil {
		t.Fatalf("NewLocalDevProvider returned error: %v", err)
	}
	mailbox, err := provider.OpenMailbox(context.Background(), relay.MailboxOpenRequest{Namespace: "profile-a", OwnerDeviceID: "device-local", MailboxID: "mailbox-conflict-review", CreatedAt: now, ExpiresAt: now.Add(time.Hour)})
	if err != nil {
		t.Fatalf("OpenMailbox returned error: %v", err)
	}
	transport, err := NewRelaySyncTransport(RelaySyncTransportConfig{Provider: provider, Namespace: "profile-a", SourceDeviceID: "device-local", TargetDeviceID: "device-remote", Mailbox: mailbox, Clock: clock})
	if err != nil {
		t.Fatalf("NewRelaySyncTransport returned error: %v", err)
	}
	store := NewMemoryMetadataStore()
	store.SetLocalSnapshot(validSyncSnapshot("snapshot-local", "", now))
	manager, err := NewSyncManager(
		SyncConfig{Enabled: true, ProfileNamespace: "profile-a", LocalDeviceID: "device-local"},
		WithSnapshotStore(store),
		WithProposalStore(store),
		WithTransport(transport),
		WithTrustVerifier(staticTrust{trusted: true}),
		WithClock(clock),
	)
	if err != nil {
		t.Fatalf("NewSyncManager returned error: %v", err)
	}
	return conflictReviewHarness{provider: provider, mailbox: mailbox, store: store, manager: manager}
}

func unsafeProfileConflictSummary() profilemesh.ConflictSummary {
	return profilemesh.ConflictSummary{
		ConflictID:         "conflict-unsafe",
		ResourceID:         "resource-metadata",
		ResourceType:       "metadata",
		Summary:            `raw manifest C:\Users\person\AppData\profile.json?token=abc`,
		RequiresUserReview: true,
	}
}

func hasSyncIssue(issues []SyncIssue, code string) bool {
	for _, issue := range issues {
		if issue.Code == code {
			return true
		}
	}
	return false
}

func hasCloudIssue(issues []CloudSyncIssue, code string) bool {
	for _, issue := range issues {
		if issue.Code == code {
			return true
		}
	}
	return false
}

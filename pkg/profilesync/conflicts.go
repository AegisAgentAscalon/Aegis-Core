package profilesync

import (
	"context"

	"github.com/AegisAgentAscalon/aegis-core/pkg/profilemesh"
)

func duplicateSnapshot(ctx context.Context, store SnapshotStore, snapshotID string) (bool, error) {
	records, err := store.ListRemoteSnapshots(ctx)
	if err != nil {
		return false, err
	}
	for _, record := range records {
		if record.Snapshot.Metadata.SnapshotID == snapshotID {
			return true, nil
		}
	}
	return false, nil
}

func classifyRemoteProposal(ctx context.Context, store ProposalStore, proposal profilemesh.ProfileChangeProposal, localSnapshotID string) (proposalReviewClassification, error) {
	records, err := store.ListRemoteProposals(ctx)
	if err != nil {
		return proposalReviewClassification{}, err
	}
	return classifyProposalRecords(records, proposal, localSnapshotID), nil
}

func classifyProposalRecords(records []RemoteProposalRecord, proposal profilemesh.ProfileChangeProposal, localSnapshotID string) proposalReviewClassification {
	out := proposalReviewClassification{}
	if proposal.BaseSnapshotID != localSnapshotID {
		out.requiresReview = true
		out.issues = append(out.issues, syncIssue("conflict_review_required", ErrConflictReview.Error(), false))
	}
	for _, record := range records {
		existing := record.Proposal
		if existing.ProposalID == proposal.ProposalID {
			out.duplicate = true
			out.requiresReview = true
			out.issues = append(out.issues, syncIssue("duplicate_proposal_id", ErrDuplicateProposal.Error(), false))
			return out
		}
		if competingProposal(existing, proposal) {
			out.requiresReview = true
			out.issues = append(out.issues, syncIssue("competing_proposal_review_required", ErrConflictReview.Error(), false))
		}
		if supersededProposal(existing, proposal) {
			out.requiresReview = true
			out.issues = append(out.issues, syncIssue("superseded_proposal_review_required", ErrConflictReview.Error(), false))
		}
	}
	return out
}

func competingProposal(a, b profilemesh.ProfileChangeProposal) bool {
	if a.ProfileNamespace != b.ProfileNamespace || a.ProfileID != b.ProfileID {
		return false
	}
	if a.ProposalID == "" || b.ProposalID == "" || a.ProposalID == b.ProposalID {
		return false
	}
	return a.BaseSnapshotID != "" && a.BaseSnapshotID == b.BaseSnapshotID
}

func supersededProposal(a, b profilemesh.ProfileChangeProposal) bool {
	if a.ProfileNamespace != b.ProfileNamespace || a.ProfileID != b.ProfileID {
		return false
	}
	if a.ProposalID == "" || b.ProposalID == "" || a.ProposalID == b.ProposalID {
		return false
	}
	return (a.ProposedSnapshotID != "" && a.ProposedSnapshotID == b.BaseSnapshotID) ||
		(b.ProposedSnapshotID != "" && b.ProposedSnapshotID == a.BaseSnapshotID)
}

func snapshotConflict(local, remote profilemesh.SignedProfileSnapshot) bool {
	if local.Metadata.ProfileNamespace != remote.Metadata.ProfileNamespace || local.Metadata.ProfileID != remote.Metadata.ProfileID {
		return false
	}
	if local.Metadata.SnapshotID == "" || remote.Metadata.SnapshotID == "" || local.Metadata.SnapshotID == remote.Metadata.SnapshotID {
		return false
	}
	if remote.Metadata.ParentSnapshotID == local.Metadata.SnapshotID || local.Metadata.ParentSnapshotID == remote.Metadata.SnapshotID {
		return false
	}
	if local.Metadata.MetadataVersion == remote.Metadata.MetadataVersion {
		return true
	}
	return remote.Metadata.ParentSnapshotID != "" && remote.Metadata.ParentSnapshotID != local.Metadata.SnapshotID
}

func trustStateFromDecision(decision TrustDecision) TrustState {
	if decision.Trusted {
		return TrustTrusted
	}
	if decision.Pending {
		return TrustPending
	}
	return TrustUntrusted
}

func trustIssueFromDecision(decision TrustDecision) SyncIssue {
	if decision.Trusted {
		return SyncIssue{}
	}
	if decision.Pending {
		return syncIssue(safeID(decision.Code), safeSummary(decision.Message, ErrTrustVerification.Error()), false)
	}
	return syncIssue(safeID(decision.Code), safeSummary(decision.Message, ErrTrustVerification.Error()), false)
}

func fromProfileIssues(issues []profilemesh.ProfileSyncIssue) []SyncIssue {
	out := make([]SyncIssue, 0, len(issues))
	for _, issue := range issues {
		out = append(out, syncIssue(safeID(issue.Code), safeSummary(issue.Message, ErrSnapshotRejected.Error()), issue.Blocking))
	}
	return out
}

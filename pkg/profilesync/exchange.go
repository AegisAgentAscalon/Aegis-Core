package profilesync

import (
	"context"
	"errors"

	"github.com/AegisAgentAscalon/aegis-core/pkg/profilemesh"
)

func (m *SyncManager) PushLocalSnapshot(ctx context.Context) (PushResult, error) {
	result := PushResult{}
	if err := m.ensureReadyForPush(ctx); err != nil {
		result.Issues = append(result.Issues, syncOperationReadinessIssue(err))
		return result, err
	}
	snapshot, err := m.snapshots.LoadLocalSnapshot(ctx)
	if err != nil {
		result.Issues = append(result.Issues, syncIssue("snapshot_store_unavailable", ErrStoreUnavailable.Error(), true))
		return result, ErrStoreUnavailable
	}
	validation := profilemesh.ValidateSignedProfileSnapshot(snapshot, m.now())
	if snapshot.Metadata.ProfileNamespace != m.cfg.ProfileNamespace || !validation.Valid {
		result.Issues = append(result.Issues, fromProfileIssues(validation.Issues)...)
		if snapshot.Metadata.ProfileNamespace != m.cfg.ProfileNamespace {
			result.Issues = append(result.Issues, syncIssue("invalid_profile_namespace", profilemesh.ErrInvalidProfileNamespace.Error(), true))
		}
		return result, ErrSnapshotRejected
	}
	envelope := snapshotEnvelope(m.cfg.ProfileNamespace, m.cfg.LocalDeviceID, snapshot, m.now())
	receipt, err := m.transport.PushEnvelope(ctx, envelope)
	if err != nil {
		result.Issues = append(result.Issues, syncIssue("transport_unavailable", ErrTransportUnavailable.Error(), true))
		return result, ErrTransportUnavailable
	}
	result.PushedSnapshots = 1
	result.Receipts = append(result.Receipts, sanitizeReceipt(receipt))
	m.recordExchange()
	return result, nil
}

func (m *SyncManager) PushLocalProposals(ctx context.Context) (PushResult, error) {
	result := PushResult{}
	if err := m.ensureReadyForPush(ctx); err != nil {
		result.Issues = append(result.Issues, syncOperationReadinessIssue(err))
		return result, err
	}
	if m.proposals == nil {
		return result, nil
	}
	proposals, err := m.proposals.LoadLocalProposals(ctx)
	if err != nil {
		result.Issues = append(result.Issues, syncIssue("proposal_store_unavailable", ErrStoreUnavailable.Error(), true))
		return result, ErrStoreUnavailable
	}
	seen := map[string]bool{}
	for _, proposal := range proposals {
		if seen[proposal.ProposalID] {
			result.Issues = append(result.Issues, syncIssue("duplicate_proposal_id", ErrDuplicateProposal.Error(), false))
			continue
		}
		seen[proposal.ProposalID] = true
		validation := profilemesh.ValidateProfileChangeProposal(proposal, m.now())
		if proposal.ProfileNamespace != m.cfg.ProfileNamespace || !validation.Valid {
			result.Issues = append(result.Issues, fromProfileIssues(validation.Issues)...)
			if proposal.ProfileNamespace != m.cfg.ProfileNamespace {
				result.Issues = append(result.Issues, syncIssue("invalid_profile_namespace", profilemesh.ErrInvalidProfileNamespace.Error(), true))
			}
			continue
		}
		receipt, err := m.transport.PushEnvelope(ctx, proposalEnvelope(m.cfg.ProfileNamespace, m.cfg.LocalDeviceID, proposal, m.now()))
		if err != nil {
			result.Issues = append(result.Issues, syncIssue("transport_unavailable", ErrTransportUnavailable.Error(), true))
			return result, ErrTransportUnavailable
		}
		result.PushedProposals++
		result.Receipts = append(result.Receipts, sanitizeReceipt(receipt))
	}
	m.recordExchange()
	return result, nil
}

func (m *SyncManager) PullRemote(ctx context.Context) (PullResult, error) {
	result := PullResult{}
	if err := m.ensureReadyForPull(ctx); err != nil {
		result.Issues = append(result.Issues, syncOperationReadinessIssue(err))
		return result, err
	}
	// A failed local read must not consume the legacy transport queue.
	local, localErr := m.snapshots.LoadLocalSnapshot(ctx)
	if localErr != nil {
		result.Issues = append(result.Issues, syncIssue("snapshot_store_unavailable", ErrStoreUnavailable.Error(), true))
		return result, ErrStoreUnavailable
	}
	envelopes, err := m.transport.PullEnvelopes(ctx)
	if err != nil {
		if errors.Is(err, ErrInvalidSyncEnvelope) {
			result.Issues = append(result.Issues, syncIssue("invalid_envelope", ErrInvalidSyncEnvelope.Error(), true))
			return result, ErrInvalidSyncEnvelope
		}
		result.Issues = append(result.Issues, syncIssue("transport_unavailable", ErrTransportUnavailable.Error(), true))
		return result, ErrTransportUnavailable
	}
	for _, envelope := range envelopes {
		if err := validateEnvelopeHeaderAt(envelope, m.cfg.ProfileNamespace, m.now()); err != nil {
			result.Rejected++
			result.Issues = append(result.Issues, syncIssue("invalid_envelope", ErrInvalidSyncEnvelope.Error(), true))
			continue
		}
		var handleErr error
		switch envelope.Kind {
		case EnvelopeKindSnapshot:
			handleErr = m.pullSnapshot(ctx, envelope, local, &result)
		case EnvelopeKindProposal:
			handleErr = m.pullProposal(ctx, envelope, local, &result)
		default:
			result.Rejected++
			result.Issues = append(result.Issues, syncIssue("invalid_envelope_kind", ErrInvalidSyncEnvelope.Error(), true))
		}
		if handleErr != nil {
			m.recordExchange()
			return result, handleErr
		}
	}
	m.recordExchange()
	return result, nil
}

func (m *SyncManager) Exchange(ctx context.Context) (ExchangeResult, error) {
	started := m.now()
	result := ExchangeResult{Session: SyncSession{SessionID: "sync-" + started.Format("20060102150405"), ProfileNamespace: m.cfg.ProfileNamespace, LocalDeviceID: m.cfg.LocalDeviceID, StartedAt: started}}
	if err := m.ensureReadyForExchange(); err != nil {
		result.Issues = append(result.Issues, syncIssue("sync_not_ready", err.Error(), true))
		result.Status = m.BuildStatus(ctx)
		result.Session.CompletedAt = m.now()
		return result, err
	}
	pushAvailable, pullAvailable := transportOperationAvailability(m.transport.GetStatus(ctx))
	if !pushAvailable && !pullAvailable {
		result.Issues = append(result.Issues, syncIssue("transport_unavailable", ErrTransportUnavailable.Error(), true))
		result.Status = m.BuildStatus(ctx)
		result.Session.CompletedAt = m.now()
		return result, ErrTransportUnavailable
	}
	if pushAvailable {
		pushSnapshot, pushErr := m.PushLocalSnapshot(ctx)
		result.Push = mergePushResults(result.Push, pushSnapshot)
		if pushErr != nil {
			result.Issues = append(result.Issues, pushSnapshot.Issues...)
			result.Status = m.BuildStatus(ctx)
			result.Session.CompletedAt = m.now()
			return result, pushErr
		}
		pushProposals, proposalErr := m.PushLocalProposals(ctx)
		result.Push = mergePushResults(result.Push, pushProposals)
		if proposalErr != nil {
			result.Issues = append(result.Issues, pushProposals.Issues...)
			result.Status = m.BuildStatus(ctx)
			result.Session.CompletedAt = m.now()
			return result, proposalErr
		}
	}
	var pullErr error
	if pullAvailable {
		result.Pull, pullErr = m.PullRemote(ctx)
		result.ReviewRequired = result.Pull.ReviewRequired
		result.Session.ReviewRequired = result.Pull.ReviewRequired
	}
	result.Session.CompletedAt = m.now()
	result.Status = m.BuildStatus(ctx)
	result.Issues = append(result.Issues, result.Push.Issues...)
	result.Issues = append(result.Issues, result.Pull.Issues...)
	if pullErr != nil {
		return result, pullErr
	}
	return result, nil
}

func (m *SyncManager) pullSnapshot(ctx context.Context, envelope SyncEnvelope, local profilemesh.SignedProfileSnapshot, result *PullResult) error {
	return m.pullSnapshotInto(ctx, envelope, local, result,
		func(id string) (bool, error) { return duplicateSnapshot(ctx, m.snapshots, id) },
		func(record RemoteSnapshotRecord) error { return m.snapshots.SaveRemoteSnapshot(ctx, record) })
}

// The ordinary adapter observes its provider on each item. Reliable ingress
// supplies only an owned revision view and still fences publication separately.
func (m *SyncManager) pullSnapshotInto(ctx context.Context, envelope SyncEnvelope, local profilemesh.SignedProfileSnapshot, result *PullResult, duplicateID func(string) (bool, error), save func(RemoteSnapshotRecord) error) error {
	if envelope.Snapshot == nil {
		result.Rejected++
		result.Issues = append(result.Issues, syncIssue("missing_snapshot", ErrSnapshotRejected.Error(), true))
		return nil
	}
	snapshot := *envelope.Snapshot
	validation := profilemesh.ValidateSignedProfileSnapshot(snapshot, m.now())
	if snapshot.Metadata.ProfileNamespace != m.cfg.ProfileNamespace || !validation.Valid {
		result.Rejected++
		result.Issues = append(result.Issues, fromProfileIssues(validation.Issues)...)
		if snapshot.Metadata.ProfileNamespace != m.cfg.ProfileNamespace {
			result.Issues = append(result.Issues, syncIssue("invalid_profile_namespace", profilemesh.ErrInvalidProfileNamespace.Error(), true))
		}
		return nil
	}
	duplicate, err := duplicateID(snapshot.Metadata.SnapshotID)
	if err != nil {
		result.Rejected++
		result.Issues = append(result.Issues, syncIssue("remote_snapshot_store_unavailable", ErrStoreUnavailable.Error(), true))
		return ErrStoreUnavailable
	}
	if duplicate {
		result.Rejected++
		result.ReviewRequired = true
		result.Issues = append(result.Issues, syncIssue("duplicate_snapshot_id", ErrDuplicateSnapshot.Error(), false))
		return nil
	}
	trustState, trustIssue := m.verifySnapshotSigner(ctx, snapshot)
	if trustIssue.Code != "" {
		result.Issues = append(result.Issues, trustIssue)
	}
	requiresReview := trustState != TrustTrusted || snapshotConflict(local, snapshot) || validation.Freshness.Stale
	if snapshot.Metadata.HostingMode == profilemesh.HostingMultiProfileDevices {
		requiresReview = true
		result.Issues = append(result.Issues, syncIssue("multi_host_unsupported", ErrMultiHostUnsupported.Error(), true))
	}
	if snapshotConflict(local, snapshot) {
		result.Issues = append(result.Issues, syncIssue("conflict_review_required", ErrConflictReview.Error(), false))
	}
	if err := save(RemoteSnapshotRecord{Snapshot: snapshot, ReceivedAt: m.now(), TrustState: trustState, RequiresReview: requiresReview, Freshness: validation.Freshness}); err != nil {
		result.Rejected++
		result.Issues = append(result.Issues, syncIssue("snapshot_store_unavailable", ErrStoreUnavailable.Error(), true))
		return ErrStoreUnavailable
	}
	result.ReceivedSnapshots++
	if requiresReview {
		result.ReviewRequired = true
	}
	return nil
}

func (m *SyncManager) pullProposal(ctx context.Context, envelope SyncEnvelope, local profilemesh.SignedProfileSnapshot, result *PullResult) error {
	var classify func(profilemesh.ProfileChangeProposal) (proposalReviewClassification, error)
	var save func(RemoteProposalRecord) error
	if m.proposals != nil {
		classify = func(proposal profilemesh.ProfileChangeProposal) (proposalReviewClassification, error) {
			return classifyRemoteProposal(ctx, m.proposals, proposal, local.Metadata.SnapshotID)
		}
		save = func(record RemoteProposalRecord) error { return m.proposals.SaveRemoteProposal(ctx, record) }
	}
	return m.pullProposalInto(ctx, envelope, local, result, classify, save)
}

func (m *SyncManager) pullProposalInto(ctx context.Context, envelope SyncEnvelope, local profilemesh.SignedProfileSnapshot, result *PullResult, classify func(profilemesh.ProfileChangeProposal) (proposalReviewClassification, error), save func(RemoteProposalRecord) error) error {
	if envelope.Proposal == nil {
		result.Rejected++
		result.Issues = append(result.Issues, syncIssue("missing_proposal", ErrProposalRejected.Error(), true))
		return nil
	}
	if save == nil {
		result.Rejected++
		result.Issues = append(result.Issues, syncIssue("proposal_store_missing", ErrStoreUnavailable.Error(), true))
		return ErrStoreUnavailable
	}
	proposal := *envelope.Proposal
	validation := profilemesh.ValidateProfileChangeProposal(proposal, m.now())
	if proposal.ProfileNamespace != m.cfg.ProfileNamespace || !validation.Valid {
		result.Rejected++
		result.Issues = append(result.Issues, fromProfileIssues(validation.Issues)...)
		if proposal.ProfileNamespace != m.cfg.ProfileNamespace {
			result.Issues = append(result.Issues, syncIssue("invalid_profile_namespace", profilemesh.ErrInvalidProfileNamespace.Error(), true))
		}
		return nil
	}
	review, err := classify(proposal)
	if err != nil {
		result.Rejected++
		result.Issues = append(result.Issues, syncIssue("remote_proposal_store_unavailable", ErrStoreUnavailable.Error(), true))
		return ErrStoreUnavailable
	}
	if review.duplicate {
		result.Rejected++
		result.ReviewRequired = true
		result.Issues = append(result.Issues, review.issues...)
		return nil
	}
	trustState, trustIssue := m.verifyProposalSigner(ctx, proposal)
	if trustIssue.Code != "" {
		result.Issues = append(result.Issues, trustIssue)
	}
	requiresReview := trustState != TrustTrusted || validation.RequiresUserReview || review.requiresReview
	if validation.RequiresUserReview {
		result.Issues = append(result.Issues, syncIssue("conflict_review_required", ErrConflictReview.Error(), false))
	}
	result.Issues = append(result.Issues, review.issues...)
	if err := save(RemoteProposalRecord{Proposal: proposal, ReceivedAt: m.now(), TrustState: trustState, RequiresReview: requiresReview}); err != nil {
		result.Rejected++
		result.Issues = append(result.Issues, syncIssue("proposal_store_unavailable", ErrStoreUnavailable.Error(), true))
		return ErrStoreUnavailable
	}
	result.ReceivedProposals++
	if requiresReview {
		result.ReviewRequired = true
	}
	return nil
}

func (m *SyncManager) verifySnapshotSigner(ctx context.Context, snapshot profilemesh.SignedProfileSnapshot) (TrustState, SyncIssue) {
	if m.trust == nil {
		return TrustPending, syncIssue("trust_verifier_missing", ErrTrustVerification.Error(), false)
	}
	decision := m.trust.VerifySigner(ctx, snapshot.Signature.SignerDeviceID, snapshot.Signature.SignerKeyFingerprint)
	return trustStateFromDecision(decision), trustIssueFromDecision(decision)
}

func (m *SyncManager) verifyProposalSigner(ctx context.Context, proposal profilemesh.ProfileChangeProposal) (TrustState, SyncIssue) {
	if m.trust == nil {
		return TrustPending, syncIssue("trust_verifier_missing", ErrTrustVerification.Error(), false)
	}
	decision := m.trust.VerifySigner(ctx, proposal.AuthorDeviceID, "")
	return trustStateFromDecision(decision), trustIssueFromDecision(decision)
}

func mergePushResults(a, b PushResult) PushResult {
	a.PushedSnapshots += b.PushedSnapshots
	a.PushedProposals += b.PushedProposals
	a.Receipts = append(a.Receipts, b.Receipts...)
	a.Issues = append(a.Issues, b.Issues...)
	return a
}

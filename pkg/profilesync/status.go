package profilesync

import (
	"context"
	"errors"
	"time"

	"github.com/AegisAgentAscalon/aegis-core/pkg/profilemesh"
)

// FormatStatusTimeRFC3339 converts a status timestamp to a browser-safe UTC
// RFC 3339 string. Zero timestamps remain absent.
func FormatStatusTimeRFC3339(value time.Time) string {
	if value.IsZero() {
		return ""
	}
	return value.UTC().Format(time.RFC3339Nano)
}

func (m *SyncManager) BuildStatus(ctx context.Context) SyncStatus {
	if m == nil || !m.cfg.Enabled {
		return SyncStatus{Enabled: false, Available: false, Summary: "profile sync is disabled"}
	}
	status := SyncStatus{Enabled: true, ProfileNamespace: m.cfg.ProfileNamespace, Available: true, Summary: "profile sync metadata orchestration is available", LastExchangeAt: m.lastExchangeAt()}
	if !validSyncName(m.cfg.ProfileNamespace) || !validSyncID(m.cfg.LocalDeviceID) {
		status.Available = false
		status.Issues = append(status.Issues, syncIssue("invalid_config", ErrInvalidConfig.Error(), true))
	}
	if m.snapshots == nil {
		status.Available = false
		status.Issues = append(status.Issues, syncIssue("snapshot_store_missing", ErrStoreUnavailable.Error(), true))
	} else {
		if local, err := m.snapshots.LoadLocalSnapshot(ctx); err != nil {
			status.Available = false
			status.Issues = append(status.Issues, syncIssue("snapshot_store_unavailable", ErrStoreUnavailable.Error(), true))
		} else {
			status.LocalSnapshotID = local.Metadata.SnapshotID
			issues, reviewRequired, blocking := classifyLocalSnapshot(local, m.now())
			status.Issues = append(status.Issues, issues...)
			if reviewRequired {
				status.ReviewRequired = true
			}
			if blocking {
				status.Available = false
			}
		}
		if remotes, err := m.snapshots.ListRemoteSnapshots(ctx); err != nil {
			status.Available = false
			status.Issues = append(status.Issues, syncIssue("remote_snapshot_store_unavailable", ErrStoreUnavailable.Error(), true))
		} else {
			status.RemoteSnapshotCount = len(remotes)
			for _, record := range remotes {
				if record.RequiresReview {
					status.ReviewRequired = true
				}
			}
		}
	}
	if m.proposals != nil {
		if proposals, err := m.proposals.ListRemoteProposals(ctx); err != nil {
			status.Available = false
			status.Issues = append(status.Issues, syncIssue("remote_proposal_store_unavailable", ErrStoreUnavailable.Error(), true))
		} else {
			status.RemoteProposalCount = len(proposals)
			for _, record := range proposals {
				if record.RequiresReview {
					status.ReviewRequired = true
				}
			}
		}
	}
	if m.transport == nil {
		status.Available = false
		status.Issues = append(status.Issues, syncIssue("transport_missing", ErrNoRelayProvider.Error(), false))
	} else {
		transportStatus := m.transport.GetStatus(ctx)
		if !transportStatus.Available {
			status.Available = false
			status.Issues = append(status.Issues, syncIssue("transport_unavailable", ErrTransportUnavailable.Error(), false))
		}
	}
	if status.ReviewRequired {
		status.Issues = append(status.Issues, syncIssue("conflict_review_required", ErrConflictReview.Error(), false))
	}
	if !status.Available {
		status.Summary = "profile sync metadata orchestration is degraded"
	} else if status.ReviewRequired {
		status.Summary = "profile sync metadata orchestration requires review"
	}
	return status
}

func (m *SyncManager) BuildSyncPlan(ctx context.Context) (SyncPlan, error) {
	if m == nil || !m.cfg.Enabled {
		return SyncPlan{Enabled: false, PlannedAt: time.Now().UTC(), Issues: []SyncIssue{syncIssue("sync_disabled", ErrDisabled.Error(), false)}}, nil
	}
	now := m.now()
	plan := SyncPlan{Enabled: true, ProfileNamespace: m.cfg.ProfileNamespace, PlannedAt: now}
	if err := m.ensureReadyForStoreOnly(); err != nil {
		plan.Issues = append(plan.Issues, syncIssue("invalid_config", err.Error(), true))
		return plan, err
	}
	local, err := m.snapshots.LoadLocalSnapshot(ctx)
	if err != nil {
		plan.Issues = append(plan.Issues, syncIssue("snapshot_store_unavailable", ErrStoreUnavailable.Error(), true))
		return plan, ErrStoreUnavailable
	}
	plan.LocalSnapshotID = local.Metadata.SnapshotID
	issues, reviewRequired, blocking := classifyLocalSnapshot(local, now)
	plan.Issues = append(plan.Issues, issues...)
	if reviewRequired {
		plan.ConflictReviewNeeded = true
	}
	if blocking {
		return plan, ErrSnapshotRejected
	}
	if m.proposals != nil {
		proposals, err := m.proposals.LoadLocalProposals(ctx)
		if err != nil {
			plan.Issues = append(plan.Issues, syncIssue("proposal_store_unavailable", ErrStoreUnavailable.Error(), true))
			return plan, ErrStoreUnavailable
		}
		plan.LocalProposalCount = len(proposals)
	}
	remotes, err := m.snapshots.ListRemoteSnapshots(ctx)
	if err != nil {
		plan.Issues = append(plan.Issues, syncIssue("remote_snapshot_store_unavailable", ErrStoreUnavailable.Error(), true))
		return plan, ErrStoreUnavailable
	}
	plan.RemoteSnapshotCount = len(remotes)
	for _, record := range remotes {
		if record.RequiresReview {
			plan.ConflictReviewNeeded = true
		}
	}
	if m.proposals != nil {
		remoteProposals, err := m.proposals.ListRemoteProposals(ctx)
		if err != nil {
			plan.Issues = append(plan.Issues, syncIssue("remote_proposal_store_unavailable", ErrStoreUnavailable.Error(), true))
			return plan, ErrStoreUnavailable
		}
		plan.RemoteProposalCount = len(remoteProposals)
		for _, record := range remoteProposals {
			if record.RequiresReview {
				plan.ConflictReviewNeeded = true
			}
		}
	}
	if m.transport == nil {
		plan.Issues = append(plan.Issues, syncIssue("offline_transport_missing", ErrNoRelayProvider.Error(), false))
	} else {
		transportStatus := m.transport.GetStatus(ctx)
		plan.TransportAvailable = transportStatus.Available
		if !transportStatus.Available {
			plan.Issues = append(plan.Issues, syncIssue("offline_transport_unavailable", ErrTransportUnavailable.Error(), false))
		}
	}
	if plan.ConflictReviewNeeded {
		plan.Issues = append(plan.Issues, syncIssue("conflict_review_required", ErrConflictReview.Error(), false))
	}
	return plan, nil
}

func (m *SyncManager) ensureReadyForStoreOnly() error {
	if m == nil || !m.cfg.Enabled {
		return ErrDisabled
	}
	if !validSyncName(m.cfg.ProfileNamespace) || !validSyncID(m.cfg.LocalDeviceID) {
		return ErrInvalidConfig
	}
	if m.snapshots == nil {
		return ErrStoreUnavailable
	}
	return nil
}

func (m *SyncManager) ensureReadyForExchange() error {
	if err := m.ensureReadyForStoreOnly(); err != nil {
		return err
	}
	if m.transport == nil {
		return ErrNoRelayProvider
	}
	return nil
}

func (m *SyncManager) ensureReadyForPush(ctx context.Context) error {
	if err := m.ensureReadyForExchange(); err != nil {
		return err
	}
	pushAvailable, pullAvailable := transportOperationAvailability(m.transport.GetStatus(ctx))
	if pushAvailable {
		return nil
	}
	if pullAvailable {
		return ErrReceiveOnlyTransport
	}
	return ErrTransportUnavailable
}

func (m *SyncManager) ensureReadyForPull(ctx context.Context) error {
	if err := m.ensureReadyForExchange(); err != nil {
		return err
	}
	_, pullAvailable := transportOperationAvailability(m.transport.GetStatus(ctx))
	if !pullAvailable {
		return ErrTransportUnavailable
	}
	return nil
}

func transportOperationAvailability(status SyncTransportStatus) (bool, bool) {
	if !status.Available {
		return false, false
	}
	if !status.PushAvailable && !status.PullAvailable {
		// Status values from transports predating directional capabilities are
		// interpreted as bidirectional for compatibility.
		return true, true
	}
	return status.PushAvailable, status.PullAvailable
}

func syncOperationReadinessIssue(err error) SyncIssue {
	switch {
	case errors.Is(err, ErrReceiveOnlyTransport):
		return syncIssue("push_unavailable", err.Error(), true)
	case errors.Is(err, ErrTransportUnavailable):
		return syncIssue("transport_unavailable", err.Error(), true)
	default:
		return syncIssue("sync_not_ready", err.Error(), true)
	}
}

func classifyLocalSnapshot(snapshot profilemesh.SignedProfileSnapshot, now time.Time) ([]SyncIssue, bool, bool) {
	validation := profilemesh.ValidateSignedProfileSnapshot(snapshot, now)
	issues := make([]SyncIssue, 0, len(validation.Issues))
	reviewRequired := false
	blocking := false
	for _, issue := range validation.Issues {
		code := safeID(issue.Code)
		if code == "stale_snapshot" {
			code = "local_snapshot_stale"
			reviewRequired = true
		}
		if code == "future_dated_snapshot" {
			code = "local_snapshot_future_dated"
		}
		if issue.Blocking {
			blocking = true
		}
		issues = append(issues, syncIssue(code, issue.Message, issue.Blocking))
	}
	if validation.Freshness.Stale && !containsSyncIssueCode(issues, "local_snapshot_stale") {
		issues = append(issues, syncIssue("local_snapshot_stale", profilemesh.ErrSnapshotMetadataStale.Error(), false))
		reviewRequired = true
	}
	if validation.Freshness.FutureDated {
		blocking = true
	}
	return issues, reviewRequired, blocking
}

func containsSyncIssueCode(issues []SyncIssue, code string) bool {
	for _, issue := range issues {
		if issue.Code == code {
			return true
		}
	}
	return false
}

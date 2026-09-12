package profilesync

import (
	"context"
	"encoding/json"
	"time"

	"github.com/AegisAgentAscalon/aegis-core/pkg/profilemesh"
	"github.com/AegisAgentAscalon/aegis-core/pkg/relay"
)

type ReliableSyncReceiverConfig struct {
	Provider       relay.ReliableRelayProvider
	Inbox          *ReliableInbox
	LocalSnapshots SnapshotStore
	Trust          TrustVerifier
	Clock          Clock
}

// ReliableSyncReceiver is explicit opt-in reliable delivery. Read received
// metadata from its Inbox projections; legacy SyncManager remains at-most-once.
type ReliableSyncReceiver struct{ cfg ReliableSyncReceiverConfig }

func NewReliableSyncReceiver(cfg ReliableSyncReceiverConfig) (*ReliableSyncReceiver, error) {
	if cfg.Provider == nil || cfg.Inbox == nil || cfg.LocalSnapshots == nil {
		return nil, ErrInvalidConfig
	}
	return &ReliableSyncReceiver{cfg: cfg}, nil
}

func (r *ReliableSyncReceiver) now() time.Time {
	if r.cfg.Clock != nil {
		return r.cfg.Clock.Now().UTC()
	}
	return time.Now().UTC()
}

// PullRemote performs bounded work. Any network failure leaves provider or local
// custody intact; callers retry with their own cancellation/backoff policy.
func (r *ReliableSyncReceiver) PullRemote(ctx context.Context) (PullResult, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	var result PullResult
	local, err := r.cfg.LocalSnapshots.LoadLocalSnapshot(ctx)
	if err != nil {
		return result, ErrStoreUnavailable
	}
	if err := r.processPending(ctx, local, &result); err != nil {
		return result, err
	}
	// Retry old ack intents before admitting a new page. Failure does not stop
	// processing already committed local ingress.
	ackErr := r.ackPending(ctx)
	ref := r.cfg.Inbox.cfg.Mailbox
	req := relay.ReceiveBatchRequest{ProtocolVersion: 2, Mailbox: ref}
	page, err := r.cfg.Provider.ReceiveBatch(ctx, req)
	if err != nil {
		return result, ErrTransportUnavailable
	}
	if relay.ValidateReliableBatch(req, page) != nil {
		return result, ErrInvalidSyncEnvelope
	}
	var ingestErr error
	for _, item := range page.Items {
		if err := r.cfg.Inbox.accept(ctx, item, r.now()); err != nil {
			ingestErr = err
			break
		}
	}
	if err := r.ackPending(ctx); err != nil {
		ackErr = err
	} else {
		ackErr = nil
	}
	if err := r.processPending(ctx, local, &result); err != nil {
		return result, err
	}
	if ingestErr != nil {
		return result, ingestErr
	}
	return result, ackErr
}

func (r *ReliableSyncReceiver) ackPending(ctx context.Context) error {
	state, err := r.cfg.Inbox.read(ctx)
	if err != nil {
		return err
	}
	req := relay.AcknowledgeBatchRequest{ProtocolVersion: 2, Mailbox: state.Mailbox}
	for _, entry := range state.Entries {
		if !entry.Acknowledged {
			req.ReceiptIDs = append(req.ReceiptIDs, entry.ReceiptID)
			if len(req.ReceiptIDs) == relay.ReliableBatchItems {
				break
			}
		}
	}
	if len(req.ReceiptIDs) == 0 {
		return nil
	}
	ack, err := r.cfg.Provider.AcknowledgeBatch(ctx, req)
	if err != nil {
		return ErrTransportUnavailable
	}
	if ack.ProtocolVersion != 2 || ack.Mailbox != req.Mailbox || len(ack.Results) != len(req.ReceiptIDs) {
		return ErrInvalidSyncEnvelope
	}
	var accepted []string
	unknown := false
	for j, out := range ack.Results {
		if out.ReceiptID != req.ReceiptIDs[j] {
			return ErrInvalidSyncEnvelope
		}
		switch out.Status {
		case "acknowledged", "already_acknowledged":
			accepted = append(accepted, out.ReceiptID)
		case "unknown":
			unknown = true
		default:
			return ErrInvalidSyncEnvelope
		}
	}
	if err := r.cfg.Inbox.markAcknowledged(ctx, accepted); err != nil {
		return err
	}
	if unknown {
		return ErrTransportUnavailable
	}
	return nil
}

func (r *ReliableSyncReceiver) processPending(ctx context.Context, local profilemesh.SignedProfileSnapshot, result *PullResult) error {
	state, err := r.cfg.Inbox.read(ctx)
	if err != nil {
		return err
	}
	view := newInboxView(state)
	processed := 0
	for _, entry := range state.Entries {
		if entry.State != "pending" {
			continue
		}
		if processed == relay.ReliableBatchItems {
			break
		}
		processed++
		if err := r.processOne(ctx, &view, entry.ReceiptID, local, result); err != nil {
			return err
		}
	}
	return nil
}

func (r *ReliableSyncReceiver) processOne(ctx context.Context, view *inboxView, id string, local profilemesh.SignedProfileSnapshot, result *PullResult) error {
	for attempt := 0; attempt < 3; attempt++ {
		if err := storeContextError(ctx); err != nil {
			return err
		}
		if attempt > 0 {
			state, err := r.cfg.Inbox.read(ctx)
			if err != nil {
				return err
			}
			*view = newInboxView(state)
		}
		index, found := view.positions[id]
		if !found || view.state.Entries[index].State != "pending" {
			return nil
		}
		out, delta, err := r.classify(ctx, view, view.state.Entries[index], local)
		if err != nil {
			return err
		}
		committed, err := r.cfg.Inbox.commit(ctx, view.state.Revision, out)
		if err != nil {
			return err
		}
		if committed {
			view.accepted(out)
			result.ReceivedSnapshots += delta.ReceivedSnapshots
			result.ReceivedProposals += delta.ReceivedProposals
			result.Rejected += delta.Rejected
			result.ReviewRequired = result.ReviewRequired || delta.ReviewRequired
			result.Issues = append(result.Issues, delta.Issues...)
			return nil
		}
	}
	return ErrStoreUnavailable
}

type inboxClock struct{ at time.Time }

func (c inboxClock) Now() time.Time { return c.at }

func (r *ReliableSyncReceiver) classify(ctx context.Context, view *inboxView, entry inboxEntry, local profilemesh.SignedProfileSnapshot) (inboxEntry, PullResult, error) {
	var result PullResult
	entry.ProcessedAt = r.now()
	if entry.ProcessedAt.IsZero() {
		return entry, result, ErrInvalidConfig
	}
	carrier := entry.Delivery.Envelope
	entry.Delivery = nil
	entry.State = "rejected"
	reject := func(reason string) (inboxEntry, PullResult, error) {
		entry.Reason = reason
		result.Rejected = 1
		result.ReviewRequired = reason == "domain_conflict" || reason == "duplicate"
		result.Issues = []SyncIssue{syncIssue(reason, ErrInvalidSyncEnvelope.Error(), true)}
		return entry, result, nil
	}
	if !carrier.ExpiresAt.After(entry.ReceivedAt) {
		return reject("expired")
	}
	var decoded SyncEnvelope
	if json.Unmarshal(carrier.Payload, &decoded) != nil || carrier.MessageKind != relay.MessageKindOpaque || validateEnvelopeHeaderAt(decoded, view.state.Mailbox.Namespace, entry.ReceivedAt) != nil || decoded.SourceDeviceID != carrier.SourceDeviceID || decoded.MessageID != carrier.MessageID || decoded.ProfileNamespace != carrier.Namespace {
		return reject("invalid_envelope")
	}
	if kind := carrier.Metadata["aegis_profile_sync_kind"]; kind != "" && kind != string(decoded.Kind) {
		return reject("invalid_envelope")
	}
	if decoded.Kind == EnvelopeKindSnapshot && decoded.Proposal != nil || decoded.Kind == EnvelopeKindProposal && decoded.Snapshot != nil {
		return reject("invalid_envelope")
	}
	var digest, key string
	if decoded.Snapshot != nil {
		digest = domainDigest(*decoded.Snapshot)
		key = decoded.Snapshot.Metadata.SnapshotID
	}
	if decoded.Proposal != nil {
		digest = domainDigest(*decoded.Proposal)
		key = decoded.Proposal.ProposalID
	}
	// Some timestamps decode successfully but cannot be encoded for storage.
	// Quarantine the domain instead of leaving acknowledged ingress pending.
	if digest == "" {
		return reject("invalid_envelope")
	}
	digests := view.snapshotDigests
	if decoded.Kind == EnvelopeKindProposal {
		digests = view.proposalDigests
	}
	if previous, found := digests[key]; found {
		if previous == digest {
			return reject("duplicate")
		}
		return reject("domain_conflict")
	}
	manager := SyncManager{cfg: SyncConfig{Enabled: true, ProfileNamespace: view.state.Mailbox.Namespace, LocalDeviceID: view.state.Mailbox.OwnerDeviceID}, trust: r.cfg.Trust, clock: inboxClock{at: entry.ProcessedAt}}
	var err error
	switch decoded.Kind {
	case EnvelopeKindSnapshot:
		err = manager.pullSnapshotInto(ctx, decoded, local, &result, func(id string) (bool, error) {
			_, found := view.snapshotDigests[id]
			return found, storeContextError(ctx)
		}, func(record RemoteSnapshotRecord) error {
			record.ReceivedAt = entry.ReceivedAt
			entry.Snapshot = &record
			return storeContextError(ctx)
		})
	case EnvelopeKindProposal:
		err = manager.pullProposalInto(ctx, decoded, local, &result, func(proposal profilemesh.ProfileChangeProposal) (proposalReviewClassification, error) {
			return classifyProposalRecords(view.proposals, proposal, local.Metadata.SnapshotID), storeContextError(ctx)
		}, func(record RemoteProposalRecord) error {
			record.ReceivedAt = entry.ReceivedAt
			entry.Proposal = &record
			return storeContextError(ctx)
		})
	}
	if err != nil {
		return entry, result, err
	}
	if entry.Snapshot == nil && entry.Proposal == nil {
		entry.Reason = "domain_rejected"
	} else {
		entry.State = "applied"
		entry.DomainDigest = digest
	}
	return entry, result, nil
}

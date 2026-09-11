package profilesync

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/AegisAgentAscalon/aegis-core/internal/filepersist"
	"github.com/AegisAgentAscalon/aegis-core/pkg/relay"
)

const reliableInboxBytes = 32 << 20
const reliableInboxRecords = 1024

type ReliableInboxConfig struct {
	Directory     string
	Mailbox       relay.ReliableMailboxRef
	MaxRecords    int
	MaxStateBytes int
}

// ReliableInbox owns reliable remote metadata and receipt state in one atomic
// file. Exactly one instance owns a path; several receivers may share it.
// Legacy LocalMetadataStore files are neither modified nor implicitly merged.
type ReliableInbox struct {
	mu    sync.Mutex
	cfg   ReliableInboxConfig
	path  string
	write func(context.Context, string, []byte) error
}

type ReliableInboxReceipt struct {
	ReceiptID    string    `json:"receipt_id"`
	Digest       string    `json:"digest"`
	ReceivedAt   time.Time `json:"received_at"`
	ProcessedAt  time.Time `json:"processed_at"`
	State        string    `json:"state"`
	Reason       string    `json:"reason,omitempty"`
	Acknowledged bool      `json:"acknowledged"`
}

type inboxEntry struct {
	ReliableInboxReceipt
	Delivery     *relay.ReliableDelivery `json:"delivery,omitempty"`
	Snapshot     *RemoteSnapshotRecord   `json:"snapshot,omitempty"`
	Proposal     *RemoteProposalRecord   `json:"proposal,omitempty"`
	DomainDigest string                  `json:"domain_digest,omitempty"`
}

type inboxState struct {
	Version  int                      `json:"version"`
	Mailbox  relay.ReliableMailboxRef `json:"mailbox"`
	Revision uint64                   `json:"revision"`
	Entries  []inboxEntry             `json:"entries"`
}

func NewReliableInbox(cfg ReliableInboxConfig) (*ReliableInbox, error) {
	if cfg.MaxRecords == 0 {
		cfg.MaxRecords = reliableInboxRecords
	}
	if cfg.MaxStateBytes == 0 {
		cfg.MaxStateBytes = reliableInboxBytes
	}
	if cfg.Directory == "" || relay.ValidateReliableMailbox(cfg.Mailbox) != nil || cfg.MaxRecords < 1 || cfg.MaxRecords > reliableInboxRecords || cfg.MaxStateBytes < 8192 || cfg.MaxStateBytes > reliableInboxBytes {
		return nil, ErrInvalidConfig
	}
	i := &ReliableInbox{cfg: cfg, path: filepath.Join(cfg.Directory, "reliable-inbox-v2.json"), write: writeInboxState}
	ctx := context.Background()
	if err := filepersist.EnsureDir(ctx, cfg.Directory); err != nil {
		return nil, ErrStoreUnavailable
	}
	var state inboxState
	err := filepersist.ReadJSON(ctx, i.path, reliableInboxBytes, &state)
	if errors.Is(err, os.ErrNotExist) {
		if err := i.save(ctx, inboxState{Version: 2, Mailbox: cfg.Mailbox, Revision: 1, Entries: []inboxEntry{}}, true); err != nil {
			return nil, err
		}
	} else if err != nil || i.validate(state) != nil {
		return nil, ErrLocalStoreCorrupt
	}
	return i, nil
}

func writeInboxState(ctx context.Context, path string, raw []byte) error {
	return filepersist.Write(ctx, path, 0600, reliableInboxBytes, func(w io.Writer) error { _, err := w.Write(raw); return err })
}

func domainDigest(value any) string {
	raw, err := json.Marshal(value)
	if err != nil {
		return ""
	}
	sum := sha256.Sum256(raw)
	return hex.EncodeToString(sum[:])
}

func inboxHash(value string) bool {
	raw, err := hex.DecodeString(value)
	return err == nil && len(raw) == 32 && hex.EncodeToString(raw) == value
}

func (i *ReliableInbox) validate(state inboxState) error {
	if state.Version != 2 || state.Mailbox != i.cfg.Mailbox || state.Revision == 0 || state.Revision == ^uint64(0) || len(state.Entries) > reliableInboxRecords {
		return ErrLocalStoreCorrupt
	}
	seen, domains := map[string]bool{}, map[string]bool{}
	for _, e := range state.Entries {
		if !inboxHash(e.ReceiptID) || !inboxHash(e.Digest) || e.ReceivedAt.IsZero() || seen[e.ReceiptID] {
			return ErrLocalStoreCorrupt
		}
		seen[e.ReceiptID] = true
		switch e.State {
		case "pending":
			if !e.ProcessedAt.IsZero() {
				return ErrLocalStoreCorrupt
			}
			if e.Delivery == nil || e.Snapshot != nil || e.Proposal != nil || e.Reason != "" || e.DomainDigest != "" || e.ReceiptID != e.Delivery.ReceiptID || e.Digest != e.Delivery.Digest {
				return ErrLocalStoreCorrupt
			}
			if relay.ValidateReliableBatch(relay.ReceiveBatchRequest{ProtocolVersion: 2, Mailbox: state.Mailbox}, relay.ReceiveBatchResult{ProtocolVersion: 2, Mailbox: state.Mailbox, Items: []relay.ReliableDelivery{*e.Delivery}}) != nil {
				return ErrLocalStoreCorrupt
			}
		case "applied":
			if e.ProcessedAt.IsZero() || e.Delivery != nil || e.Reason != "" || (e.Snapshot == nil) == (e.Proposal == nil) {
				return ErrLocalStoreCorrupt
			}
			var key, digest string
			if e.Snapshot != nil {
				checked, err := validateRemoteSnapshotRecord(state.Mailbox.Namespace, *e.Snapshot, e.ProcessedAt)
				if err != nil || !validTrustState(e.Snapshot.TrustState) || checked.RequiresReview && !e.Snapshot.RequiresReview || domainDigest(checked.Freshness) != domainDigest(e.Snapshot.Freshness) {
					return ErrLocalStoreCorrupt
				}
				key = "snapshot:" + e.Snapshot.Snapshot.Metadata.SnapshotID
				digest = domainDigest(e.Snapshot.Snapshot)
				if e.Snapshot.Snapshot.Metadata.ProfileNamespace != state.Mailbox.Namespace || e.Snapshot.ReceivedAt != e.ReceivedAt {
					return ErrLocalStoreCorrupt
				}
			}
			if e.Proposal != nil {
				checked, err := validateRemoteProposalRecord(state.Mailbox.Namespace, *e.Proposal, e.ProcessedAt)
				if err != nil || !validTrustState(e.Proposal.TrustState) || checked.RequiresReview && !e.Proposal.RequiresReview {
					return ErrLocalStoreCorrupt
				}
				key = "proposal:" + e.Proposal.Proposal.ProposalID
				digest = domainDigest(e.Proposal.Proposal)
				if e.Proposal.Proposal.ProfileNamespace != state.Mailbox.Namespace || e.Proposal.ReceivedAt != e.ReceivedAt {
					return ErrLocalStoreCorrupt
				}
			}
			if !inboxHash(e.DomainDigest) || e.DomainDigest != digest || domains[key] {
				return ErrLocalStoreCorrupt
			}
			domains[key] = true
		case "rejected":
			if e.ProcessedAt.IsZero() || e.Delivery != nil || e.Snapshot != nil || e.Proposal != nil || e.DomainDigest != "" {
				return ErrLocalStoreCorrupt
			}
			switch e.Reason {
			case "invalid_envelope", "domain_rejected", "duplicate", "domain_conflict", "expired":
			default:
				return ErrLocalStoreCorrupt
			}
		default:
			return ErrLocalStoreCorrupt
		}
	}
	return nil
}

func (i *ReliableInbox) load(ctx context.Context) (inboxState, error) {
	var state inboxState
	if err := filepersist.ReadJSON(ctx, i.path, reliableInboxBytes, &state); err != nil {
		return state, ErrStoreUnavailable
	}
	return state, i.validate(state)
}

func (i *ReliableInbox) read(ctx context.Context) (inboxState, error) {
	i.mu.Lock()
	defer i.mu.Unlock()
	return i.load(ctx)
}

func (i *ReliableInbox) save(ctx context.Context, state inboxState, admission bool) error {
	if err := i.validate(state); err != nil {
		return err
	}
	raw, err := json.Marshal(state)
	if err != nil {
		return ErrStoreUnavailable
	}
	charge := len(raw) + 4096 // permanent revision/ack bookkeeping margin
	for _, entry := range state.Entries {
		if entry.Delivery != nil {
			charge += 6*len(entry.Delivery.Envelope.Payload) + (16 << 10)
		}
	}
	if charge > reliableInboxBytes || len(state.Entries) > reliableInboxRecords || admission && (charge > i.cfg.MaxStateBytes || len(state.Entries) > i.cfg.MaxRecords) {
		return ErrStoreUnavailable
	}
	if err := i.write(ctx, i.path, raw); err != nil {
		return ErrStoreUnavailable
	}
	return nil
}

func (i *ReliableInbox) accept(ctx context.Context, item relay.ReliableDelivery, now time.Time) error {
	if now.IsZero() {
		return ErrInvalidConfig
	}
	i.mu.Lock()
	defer i.mu.Unlock()
	state, err := i.load(ctx)
	if err != nil {
		return err
	}
	for _, e := range state.Entries {
		if e.ReceiptID == item.ReceiptID {
			if e.Digest != item.Digest {
				return ErrInvalidSyncEnvelope
			}
			return nil
		}
	}
	state.Entries = append(state.Entries, inboxEntry{ReliableInboxReceipt: ReliableInboxReceipt{ReceiptID: item.ReceiptID, Digest: item.Digest, ReceivedAt: now, State: "pending"}, Delivery: &item})
	state.Revision++
	return i.save(ctx, state, true)
}

func (i *ReliableInbox) markAcknowledged(ctx context.Context, ids []string) error {
	i.mu.Lock()
	defer i.mu.Unlock()
	state, err := i.load(ctx)
	if err != nil {
		return err
	}
	set := map[string]bool{}
	for _, id := range ids {
		set[id] = true
	}
	changed := false
	for j := range state.Entries {
		if set[state.Entries[j].ReceiptID] && !state.Entries[j].Acknowledged {
			state.Entries[j].Acknowledged = true
			changed = true
		}
	}
	if !changed {
		return nil
	}
	state.Revision++
	return i.save(ctx, state, false)
}

// commit compares the entire classification revision. No trust callback or
// external store call is made while the inbox data mutex is held.
func (i *ReliableInbox) commit(ctx context.Context, revision uint64, entry inboxEntry) (bool, error) {
	i.mu.Lock()
	defer i.mu.Unlock()
	state, err := i.load(ctx)
	if err != nil {
		return false, err
	}
	if state.Revision != revision {
		return false, nil
	}
	for j, e := range state.Entries {
		if e.ReceiptID == entry.ReceiptID && e.Digest == entry.Digest && e.State == "pending" {
			state.Entries[j] = entry
			state.Revision++
			return true, i.save(ctx, state, false)
		}
	}
	return false, nil
}

func (i *ReliableInbox) ListReceipts(ctx context.Context) ([]ReliableInboxReceipt, error) {
	state, err := i.read(ctx)
	if err != nil {
		return nil, err
	}
	out := make([]ReliableInboxReceipt, 0, len(state.Entries))
	for _, entry := range state.Entries {
		out = append(out, entry.ReliableInboxReceipt)
	}
	return out, nil
}

// ListRemoteSnapshots projects metadata committed in the same transaction as
// its receipt, rather than copying it to a separately written legacy store.
// Freshness describes its recorded ObservedAt, not current availability.
func (i *ReliableInbox) ListRemoteSnapshots(ctx context.Context) ([]RemoteSnapshotRecord, error) {
	state, err := i.read(ctx)
	if err != nil {
		return nil, err
	}
	var out []RemoteSnapshotRecord
	for _, entry := range state.Entries {
		if entry.Snapshot != nil {
			out = append(out, *entry.Snapshot)
		}
	}
	return out, nil
}

func (i *ReliableInbox) ListRemoteProposals(ctx context.Context) ([]RemoteProposalRecord, error) {
	state, err := i.read(ctx)
	if err != nil {
		return nil, err
	}
	var out []RemoteProposalRecord
	for _, entry := range state.Entries {
		if entry.Proposal != nil {
			out = append(out, *entry.Proposal)
		}
	}
	return out, nil
}

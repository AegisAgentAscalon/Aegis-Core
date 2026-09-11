package relay

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/AegisAgentAscalon/aegis-core/internal/filepersist"
)

const reliableStateBytes = 32 << 20
const reliableStateRecords = 1024

type FileReliableMailboxConfig struct {
	Directory       string
	ProviderID      string
	Namespace       string
	MailboxID       string
	OwnerDeviceID   string
	MaxRecords      int
	MaxStateBytes   int
	MaxPayloadBytes int
	Clock           Clock
}

// FileReliableMailbox owns one bounded spool. Use exactly one owning instance
// per path; mutexes do not coordinate independently reopened objects/processes.
// Records survive process restart, not necessarily power loss. No expiry purge,
// mailbox rotation or replay-tombstone pruning is performed.
type FileReliableMailbox struct {
	mu    sync.Mutex
	cfg   FileReliableMailboxConfig
	ref   ReliableMailboxRef
	path  string
	write func(context.Context, string, []byte) error
}

type reliableStored struct {
	ReceiptID      string         `json:"receipt_id"`
	Digest         string         `json:"digest"`
	SourceDeviceID string         `json:"source_device_id"`
	MessageID      string         `json:"message_id"`
	Envelope       *RelayEnvelope `json:"envelope,omitempty"`
}

type reliableState struct {
	Version int                `json:"version"`
	Mailbox ReliableMailboxRef `json:"mailbox"`
	Items   []reliableStored   `json:"items"`
}

func NewFileReliableMailbox(cfg FileReliableMailboxConfig) (*FileReliableMailbox, error) {
	if cfg.MaxRecords == 0 {
		cfg.MaxRecords = reliableStateRecords
	}
	if cfg.MaxStateBytes == 0 {
		cfg.MaxStateBytes = reliableStateBytes
	}
	if cfg.MaxPayloadBytes == 0 {
		cfg.MaxPayloadBytes = DefaultMaxPayloadSize
	}
	if cfg.Directory == "" || cfg.MaxRecords < 1 || cfg.MaxRecords > reliableStateRecords || cfg.MaxStateBytes < 1024 || cfg.MaxStateBytes > reliableStateBytes || cfg.MaxPayloadBytes < 1 || cfg.MaxPayloadBytes > ReliableBatchBytes {
		return nil, ErrInvalidConfig
	}
	ref := ReliableMailboxRef{ProviderID: cfg.ProviderID, Namespace: cfg.Namespace, MailboxID: cfg.MailboxID, OwnerDeviceID: cfg.OwnerDeviceID, Epoch: reliableRandomID()}
	if ValidateReliableMailbox(ref) != nil {
		return nil, ErrInvalidConfig
	}
	p := &FileReliableMailbox{cfg: cfg, ref: ref, path: filepath.Join(cfg.Directory, "reliable-mailbox-v2.json"), write: writeReliableState}
	ctx := context.Background()
	if err := filepersist.EnsureDir(ctx, cfg.Directory); err != nil {
		return nil, ErrProviderUnavailable
	}
	var state reliableState
	err := filepersist.ReadJSON(ctx, p.path, reliableStateBytes, &state)
	if errors.Is(err, os.ErrNotExist) {
		if err := p.save(ctx, reliableState{Version: 2, Mailbox: ref, Items: []reliableStored{}}, true); err != nil {
			return nil, err
		}
	} else {
		if err != nil {
			return nil, ErrProviderUnavailable
		}
		ref.Epoch = state.Mailbox.Epoch
		p.ref = ref
		if err := p.validate(state); err != nil {
			return nil, err
		}
	}
	return p, nil
}

func reliableRandomID() string {
	var raw [32]byte
	if _, err := rand.Read(raw[:]); err != nil {
		return ""
	}
	return hex.EncodeToString(raw[:])
}

func writeReliableState(ctx context.Context, path string, raw []byte) error {
	return filepersist.Write(ctx, path, 0600, reliableStateBytes, func(w io.Writer) error { _, err := w.Write(raw); return err })
}

func (p *FileReliableMailbox) Mailbox() ReliableMailboxRef { return p.ref }

func (p *FileReliableMailbox) validate(state reliableState) error {
	if state.Version != 2 || state.Mailbox != p.ref || ValidateReliableMailbox(state.Mailbox) != nil || len(state.Items) > reliableStateRecords {
		return ErrProviderUnavailable
	}
	ids, logical := map[string]bool{}, map[[2]string]bool{}
	for _, item := range state.Items {
		key := [2]string{item.SourceDeviceID, item.MessageID}
		if !reliableID(item.ReceiptID) || !reliableID(item.Digest) || !validDeviceID(item.SourceDeviceID) || !validMessageID(item.MessageID) || ids[item.ReceiptID] || logical[key] {
			return ErrProviderUnavailable
		}
		ids[item.ReceiptID], logical[key] = true, true
		if item.Envelope != nil {
			digest, err := ReliableEnvelopeDigest(*item.Envelope)
			if err != nil || digest != item.Digest || item.SourceDeviceID != item.Envelope.SourceDeviceID || item.MessageID != item.Envelope.MessageID || !reliableTarget(*item.Envelope, p.ref) || validateEnvelopeAt(*item.Envelope, ReliableBatchBytes, item.Envelope.CreatedAt) != nil {
				return ErrProviderUnavailable
			}
		}
	}
	return nil
}

func (p *FileReliableMailbox) load(ctx context.Context) (reliableState, error) {
	var state reliableState
	if err := filepersist.ReadJSON(ctx, p.path, reliableStateBytes, &state); err != nil {
		return state, reliableStorageError(err)
	}
	return state, p.validate(state)
}

func reliableStorageError(err error) error {
	if err == nil {
		return nil
	}
	if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
		return ErrContextCanceled
	}
	return ErrProviderUnavailable
}

func (p *FileReliableMailbox) save(ctx context.Context, state reliableState, admission bool) error {
	raw, err := json.Marshal(state)
	if err != nil {
		return ErrProviderUnavailable
	}
	if len(raw) > reliableStateBytes || len(state.Items) > reliableStateRecords || admission && (len(raw) > p.cfg.MaxStateBytes || len(state.Items) > p.cfg.MaxRecords) {
		return ErrPayloadTooLarge
	}
	return reliableStorageError(p.write(ctx, p.path, raw))
}

func (p *FileReliableMailbox) SendReliableEnvelope(ctx context.Context, req ReliableSendRequest) (ReliableSendResult, error) {
	if err := reliableRequest(req.ProtocolVersion, req.Mailbox); err != nil {
		return ReliableSendResult{}, err
	}
	if req.Mailbox != p.ref || !reliableTarget(req.Envelope, p.ref) {
		return ReliableSendResult{}, ErrInvalidMailbox
	}
	if _, err := encodedReliable(req); err != nil {
		return ReliableSendResult{}, err
	}
	digest, err := ReliableEnvelopeDigest(req.Envelope)
	if err != nil {
		return ReliableSendResult{}, err
	}
	now := time.Now().UTC()
	if p.cfg.Clock != nil {
		now = p.cfg.Clock.Now().UTC()
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	state, err := p.load(ctx)
	if err != nil {
		return ReliableSendResult{}, err
	}
	result := ReliableSendResult{ProtocolVersion: 2, Mailbox: p.ref, Digest: digest}
	for _, item := range state.Items {
		if item.SourceDeviceID == req.Envelope.SourceDeviceID && item.MessageID == req.Envelope.MessageID {
			if item.Digest != digest {
				return ReliableSendResult{}, ErrDuplicateEnvelope
			}
			result.ReceiptID = item.ReceiptID
			return result, nil
		}
	}
	if err := validateEnvelopeAt(req.Envelope, p.cfg.MaxPayloadBytes, now); err != nil {
		return ReliableSendResult{}, err
	}
	result.ReceiptID = reliableRandomID()
	if result.ReceiptID == "" {
		return ReliableSendResult{}, ErrProviderUnavailable
	}
	page := ReceiveBatchResult{ProtocolVersion: 2, Mailbox: p.ref, Items: []ReliableDelivery{{ReceiptID: result.ReceiptID, Digest: digest, Envelope: req.Envelope}}}
	if _, err := encodedReliable(page); err != nil {
		return ReliableSendResult{}, err
	}
	stored := cloneRelayEnvelope(req.Envelope)
	state.Items = append(state.Items, reliableStored{ReceiptID: result.ReceiptID, Digest: digest, SourceDeviceID: stored.SourceDeviceID, MessageID: stored.MessageID, Envelope: &stored})
	if err := p.save(ctx, state, true); err != nil {
		return ReliableSendResult{}, err
	}
	return result, nil
}

func (p *FileReliableMailbox) ReceiveBatch(ctx context.Context, req ReceiveBatchRequest) (ReceiveBatchResult, error) {
	limit, err := receiveLimit(req)
	if err != nil {
		return ReceiveBatchResult{}, err
	}
	if req.Mailbox != p.ref {
		return ReceiveBatchResult{}, ErrInvalidMailbox
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	state, err := p.load(ctx)
	if err != nil {
		return ReceiveBatchResult{}, err
	}
	result := ReceiveBatchResult{ProtocolVersion: 2, Mailbox: p.ref, Items: []ReliableDelivery{}}
	for _, item := range state.Items {
		if item.Envelope == nil {
			continue
		}
		if len(result.Items) == limit {
			result.HasMore = true
			break
		}
		result.Items = append(result.Items, ReliableDelivery{ReceiptID: item.ReceiptID, Digest: item.Digest, Envelope: *item.Envelope})
		if _, err := encodedReliable(result); err != nil {
			result.Items = result.Items[:len(result.Items)-1]
			result.HasMore = true
			break
		}
	}
	return result, nil
}

func (p *FileReliableMailbox) AcknowledgeBatch(ctx context.Context, req AcknowledgeBatchRequest) (AcknowledgeBatchResult, error) {
	if err := ackRequest(req); err != nil {
		return AcknowledgeBatchResult{}, err
	}
	if req.Mailbox != p.ref {
		return AcknowledgeBatchResult{}, ErrInvalidMailbox
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	state, err := p.load(ctx)
	if err != nil {
		return AcknowledgeBatchResult{}, err
	}
	result := AcknowledgeBatchResult{ProtocolVersion: 2, Mailbox: p.ref}
	changed := false
	for _, id := range req.ReceiptIDs {
		status := "unknown"
		for i := range state.Items {
			if state.Items[i].ReceiptID == id {
				status = "already_acknowledged"
				if state.Items[i].Envelope != nil {
					state.Items[i].Envelope = nil
					changed = true
					status = "acknowledged"
				}
				break
			}
		}
		result.Results = append(result.Results, AcknowledgeResult{ReceiptID: id, Status: status})
	}
	if changed {
		if err := p.save(ctx, state, false); err != nil {
			return AcknowledgeBatchResult{}, err
		}
	}
	return result, nil
}

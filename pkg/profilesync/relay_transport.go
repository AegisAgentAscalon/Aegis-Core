package profilesync

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"time"

	"github.com/AegisAgentAscalon/aegis-core/pkg/relay"
)

type RelaySyncTransportConfig struct {
	Provider        relay.RelayProvider
	Namespace       string
	SourceDeviceID  string
	TargetDeviceID  string
	TargetMailboxID string
	Mailbox         relay.MailboxRef
	MessageTTL      time.Duration
	MaxPayloadBytes int
	Clock           Clock
}

type RelaySyncTransport struct {
	cfg RelaySyncTransportConfig
}

func NewRelaySyncTransport(config RelaySyncTransportConfig) (*RelaySyncTransport, error) {
	if config.Provider == nil {
		return nil, ErrNoRelayProvider
	}
	if !validExactSyncName(config.Namespace) || !validExactSyncID(config.SourceDeviceID) {
		return nil, ErrInvalidConfig
	}
	hasSendTarget := config.TargetDeviceID != "" || config.TargetMailboxID != ""
	hasReceiveMailbox := config.Mailbox.MailboxID != ""
	if !hasSendTarget && !hasReceiveMailbox {
		return nil, ErrInvalidConfig
	}
	if config.TargetDeviceID != "" && !validExactSyncID(config.TargetDeviceID) {
		return nil, ErrInvalidConfig
	}
	if config.TargetMailboxID != "" && relay.ValidateMailboxID(config.TargetMailboxID) != nil {
		return nil, ErrInvalidConfig
	}
	if hasReceiveMailbox {
		if err := relay.ValidateMailboxRef(config.Mailbox); err != nil {
			return nil, ErrInvalidConfig
		}
		if config.Mailbox.Namespace != config.Namespace || config.Mailbox.OwnerDeviceID != config.SourceDeviceID {
			return nil, ErrInvalidConfig
		}
	}
	return &RelaySyncTransport{cfg: config}, nil
}

// NewReceiveOnlyRelaySyncTransport constructs a mailbox-backed transport that
// can pull Profile Sync envelopes without requiring a placeholder send target.
func NewReceiveOnlyRelaySyncTransport(config RelaySyncTransportConfig) (*RelaySyncTransport, error) {
	if config.TargetDeviceID != "" || config.TargetMailboxID != "" || config.Mailbox.MailboxID == "" {
		return nil, ErrInvalidConfig
	}
	return NewRelaySyncTransport(config)
}

// DeterministicRelayMailboxID returns a stable, domain-separated mailbox ID.
// The digest isolates namespaces and owner devices without exposing either one.
func DeterministicRelayMailboxID(namespace, ownerDeviceID string) (string, error) {
	if !validExactSyncName(namespace) || !validExactSyncID(ownerDeviceID) {
		return "", ErrInvalidConfig
	}
	sum := sha256.Sum256([]byte(deterministicMailboxDomain + "\x00" + namespace + "\x00" + ownerDeviceID))
	mailboxID := "profilesync-" + hex.EncodeToString(sum[:])
	if err := relay.ValidateMailboxID(mailboxID); err != nil {
		return "", ErrInvalidConfig
	}
	return mailboxID, nil
}

func (t *RelaySyncTransport) GetStatus(ctx context.Context) SyncTransportStatus {
	if t == nil || t.cfg.Provider == nil {
		return SyncTransportStatus{Available: false, Summary: ErrNoRelayProvider.Error(), Issues: []SyncIssue{syncIssue("relay_missing", ErrNoRelayProvider.Error(), false)}}
	}
	status := t.cfg.Provider.GetStatus(ctx)
	out := SyncTransportStatus{ProviderAvailable: status.Available, ProviderID: safeID(status.ProviderID)}
	for _, issue := range status.Issues {
		out.Issues = append(out.Issues, syncIssue(safeID(issue.Code), safeSummary(issue.Message, ErrTransportUnavailable.Error()), false))
	}
	out.PushAvailable = out.ProviderAvailable && (t.cfg.TargetDeviceID != "" || t.cfg.TargetMailboxID != "")
	out.PullAvailable = out.ProviderAvailable && t.cfg.Mailbox.MailboxID != ""
	if out.PullAvailable && !t.cfg.Mailbox.ExpiresAt.IsZero() && !t.cfg.Mailbox.ExpiresAt.After(t.now()) {
		out.PullAvailable = false
		out.Issues = append(out.Issues, syncIssue("relay_mailbox_expired", relay.ErrMailboxExpired.Error(), false))
	}
	out.Available = out.PushAvailable || out.PullAvailable
	switch {
	case out.PushAvailable && out.PullAvailable:
		out.Summary = "profile sync relay push and pull are available"
	case out.PullAvailable:
		out.Summary = "profile sync relay pull is available"
	case out.PushAvailable:
		out.Summary = "profile sync relay push is available"
	case out.ProviderAvailable:
		out.Summary = "profile sync relay provider has no available configured operation"
	default:
		out.Summary = "profile sync relay transport is unavailable"
	}
	if !out.ProviderAvailable && len(out.Issues) == 0 {
		out.Issues = append(out.Issues, syncIssue("relay_unavailable", ErrTransportUnavailable.Error(), false))
	}
	return out
}

// BuildDiagnostics reports safe relay capabilities without exposing routing
// identifiers, caller signature evidence, payloads, or provider error details.
func (t *RelaySyncTransport) BuildDiagnostics(ctx context.Context) RelaySyncDiagnostics {
	status := t.GetStatus(ctx)
	diagnostics := RelaySyncDiagnostics{
		Available:           status.Available,
		ProviderAvailable:   status.ProviderAvailable,
		SendAvailable:       status.PushAvailable,
		ReceiveAvailable:    status.PullAvailable,
		ProviderID:          status.ProviderID,
		Summary:             status.Summary,
		Issues:              append([]SyncIssue(nil), status.Issues...),
		MaximumPayloadBytes: relay.DefaultMaxPayloadSize,
	}
	if t == nil {
		return diagnostics
	}
	diagnostics.SendConfigured = t.cfg.TargetDeviceID != "" || t.cfg.TargetMailboxID != ""
	diagnostics.ReceiveConfigured = t.cfg.Mailbox.MailboxID != ""
	diagnostics.ReceiveOnly = diagnostics.ReceiveConfigured && !diagnostics.SendConfigured
	if t.cfg.MaxPayloadBytes > 0 {
		diagnostics.MaximumPayloadBytes = t.cfg.MaxPayloadBytes
	}
	if diagnostics.SendConfigured {
		ttl := t.cfg.MessageTTL
		if ttl <= 0 {
			ttl = DefaultEnvelopeTTL
		}
		diagnostics.MessageTTLSeconds = int64(ttl / time.Second)
	}
	if diagnostics.ReceiveConfigured {
		diagnostics.MailboxExpiresAtRFC3339 = FormatStatusTimeRFC3339(t.cfg.Mailbox.ExpiresAt)
	}
	return diagnostics
}

func (t *RelaySyncTransport) PushEnvelope(ctx context.Context, envelope SyncEnvelope) (relay.DeliveryReceipt, error) {
	if t == nil || t.cfg.Provider == nil {
		return relay.DeliveryReceipt{}, ErrNoRelayProvider
	}
	if t.cfg.TargetDeviceID == "" && t.cfg.TargetMailboxID == "" {
		return relay.DeliveryReceipt{}, ErrReceiveOnlyTransport
	}
	if err := validateEnvelopeHeaderAt(envelope, t.cfg.Namespace, t.now()); err != nil {
		return relay.DeliveryReceipt{}, err
	}
	payload, err := json.Marshal(envelope)
	if err != nil {
		return relay.DeliveryReceipt{}, ErrInvalidSyncEnvelope
	}
	now := t.now()
	ttl := t.cfg.MessageTTL
	if ttl <= 0 {
		ttl = DefaultEnvelopeTTL
	}
	targetMailboxID := t.cfg.TargetMailboxID
	targetDeviceID := t.cfg.TargetDeviceID
	rEnvelope := relay.RelayEnvelope{
		RelayEnvelopeMetadata: relay.RelayEnvelopeMetadata{
			ProtocolVersion: relay.ProtocolVersion,
			Namespace:       t.cfg.Namespace,
			SourceDeviceID:  t.cfg.SourceDeviceID,
			TargetDeviceID:  targetDeviceID,
			TargetMailboxID: targetMailboxID,
			MessageKind:     relay.MessageKindOpaque,
			CreatedAt:       now,
			ExpiresAt:       now.Add(ttl),
			MessageID:       envelope.MessageID,
			PayloadHash:     relay.PayloadSHA256(payload),
			Metadata:        map[string]string{"aegis_profile_sync_kind": string(envelope.Kind)},
		},
		Payload: payload,
	}
	receipt, err := t.cfg.Provider.SendEnvelope(ctx, rEnvelope)
	if err != nil {
		if errors.Is(err, relay.ErrDuplicateEnvelope) {
			return relay.DeliveryReceipt{MessageID: envelope.MessageID, Accepted: true, Delivered: false, ReceivedAt: now, Summary: "profile sync envelope was already accepted"}, nil
		}
		return relay.DeliveryReceipt{}, ErrTransportUnavailable
	}
	return sanitizeReceipt(receipt), nil
}

func (t *RelaySyncTransport) PullEnvelopes(ctx context.Context) ([]SyncEnvelope, error) {
	if t == nil || t.cfg.Provider == nil {
		return nil, ErrNoRelayProvider
	}
	if t.cfg.Mailbox.MailboxID == "" {
		return nil, ErrInvalidConfig
	}
	envelopes, err := t.cfg.Provider.ReceiveEnvelopes(ctx, t.cfg.Mailbox)
	if err != nil {
		return nil, ErrTransportUnavailable
	}
	out := make([]SyncEnvelope, 0, len(envelopes))
	for _, envelope := range envelopes {
		if err := validateRelayCarrierEnvelope(envelope, t.cfg); err != nil {
			return nil, ErrInvalidSyncEnvelope
		}
		var decoded SyncEnvelope
		if err := json.Unmarshal(envelope.Payload, &decoded); err != nil {
			return nil, ErrInvalidSyncEnvelope
		}
		if kind := envelope.Metadata["aegis_profile_sync_kind"]; kind != "" && kind != string(decoded.Kind) {
			return nil, ErrInvalidSyncEnvelope
		}
		if err := validateEnvelopeHeaderAt(decoded, t.cfg.Namespace, t.now()); err != nil {
			return nil, err
		}
		out = append(out, decoded)
	}
	return out, nil
}

func (t *RelaySyncTransport) now() time.Time {
	if t != nil && t.cfg.Clock != nil {
		return t.cfg.Clock.Now().UTC()
	}
	return time.Now().UTC()
}

func validateRelayCarrierEnvelope(envelope relay.RelayEnvelope, cfg RelaySyncTransportConfig) error {
	limit := cfg.MaxPayloadBytes
	if limit <= 0 {
		limit = relay.DefaultMaxPayloadSize
	}
	if err := relay.ValidateEnvelopeWithLimit(envelope, limit); err != nil {
		return err
	}
	if envelope.Namespace != cfg.Namespace || envelope.MessageKind != relay.MessageKindOpaque {
		return ErrInvalidSyncEnvelope
	}
	if cfg.Mailbox.MailboxID != "" && envelope.TargetMailboxID != "" && envelope.TargetMailboxID != cfg.Mailbox.MailboxID {
		return ErrInvalidSyncEnvelope
	}
	return nil
}

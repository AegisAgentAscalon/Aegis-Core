package relay

import (
	"context"
	"fmt"
	"sync"
	"time"
)

// Clock allows local/dev relay tests and adapters to use deterministic time.
type Clock interface {
	Now() time.Time
}

// LocalDevProviderConfig configures the in-process local/dev relay provider.
// The provider is for development, tests, and single-process local workflows;
// it is not a production relay server or hosted relay service.
type LocalDevProviderConfig struct {
	ProviderID      string
	MaxPayloadBytes int
	Clock           Clock
	Disabled        bool
}

// EndpointHintRevokeRequest removes a previously published endpoint hint.
type EndpointHintRevokeRequest struct {
	Namespace  string
	DeviceID   string
	EndpointID string
}

// LocalDevProvider is an in-process local/dev implementation of RelayProvider
// and RendezvousProvider. It stores only endpoint hints, rendezvous metadata,
// mailbox refs, opaque envelopes, and delivery attempt metadata in memory.
type LocalDevProvider struct {
	mu            sync.Mutex
	providerID    string
	maxPayload    int
	clock         Clock
	disabled      bool
	unavailable   bool
	hints         map[string]EndpointHint
	announcements map[string]RendezvousAnnouncement
	mailboxes     map[string]MailboxRef
	envelopes     map[string][]RelayEnvelope
	seen          map[string]seenDelivery
	mailboxSeq    uint64
}

type seenDelivery struct {
	Receipt   DeliveryReceipt
	ExpiresAt time.Time
}

func NewLocalDevProvider(config LocalDevProviderConfig) (*LocalDevProvider, error) {
	providerID := config.ProviderID
	if providerID == "" {
		providerID = "local-dev-relay"
	}
	if !validID(providerID) {
		return nil, ErrInvalidConfig
	}
	maxPayload := config.MaxPayloadBytes
	if maxPayload <= 0 {
		maxPayload = DefaultMaxPayloadSize
	}
	return &LocalDevProvider{
		providerID:    providerID,
		maxPayload:    maxPayload,
		clock:         config.Clock,
		disabled:      config.Disabled,
		hints:         map[string]EndpointHint{},
		announcements: map[string]RendezvousAnnouncement{},
		mailboxes:     map[string]MailboxRef{},
		envelopes:     map[string][]RelayEnvelope{},
		seen:          map[string]seenDelivery{},
	}, nil
}

func (p *LocalDevProvider) SetUnavailable(unavailable bool) {
	if p == nil {
		return
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	p.unavailable = unavailable
}

func (p *LocalDevProvider) GetStatus(ctx context.Context) RelayStatus {
	if p == nil {
		return RelayStatus{Enabled: false, Available: false, Summary: "relay provider is not configured", Issues: []RelayIssue{{Code: "relay_provider_missing", Message: "relay provider is not configured", Blocking: false}}}
	}
	if p.disabled {
		return DisabledStatus()
	}
	if ctx != nil {
		if err := SanitizeProviderError(ctx.Err()); err != nil {
			return RelayStatus{Enabled: true, Available: false, ProviderID: p.providerID, Summary: "local/dev relay is unavailable", Issues: []RelayIssue{{Code: "relay_unavailable", Message: err.Error(), Blocking: false}}}
		}
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.unavailable {
		return RelayStatus{Enabled: true, Available: false, ProviderID: p.providerID, Summary: "local/dev relay is unavailable", Issues: []RelayIssue{{Code: "relay_unavailable", Message: ErrProviderUnavailable.Error(), Blocking: false}}}
	}
	return RelayStatus{Enabled: true, Available: true, ProviderID: p.providerID, Summary: "local/dev relay provider is available"}
}

func (p *LocalDevProvider) PublishEndpointHint(ctx context.Context, hint EndpointHint) error {
	if err := p.ready(ctx); err != nil {
		return err
	}
	if err := ValidateEndpointHint(hint); err != nil {
		return err
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	p.cleanupExpiredLocked(p.now())
	p.hints[endpointHintKey(hint.Namespace, hint.DeviceID, hint.EndpointID)] = cloneEndpointHint(hint)
	return nil
}

func (p *LocalDevProvider) ListEndpointHints(ctx context.Context, query EndpointHintQuery) ([]EndpointHint, error) {
	if err := p.ready(ctx); err != nil {
		return nil, err
	}
	if !validNamespace(query.Namespace) {
		return nil, ErrInvalidNamespace
	}
	if query.DeviceID != "" && !validDeviceID(query.DeviceID) {
		return nil, ErrInvalidDeviceID
	}
	now := query.Now
	if now.IsZero() {
		now = p.now()
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	p.cleanupExpiredLocked(now)
	out := []EndpointHint{}
	for _, hint := range p.hints {
		if hint.Namespace != query.Namespace || (query.DeviceID != "" && hint.DeviceID != query.DeviceID) {
			continue
		}
		out = append(out, cloneEndpointHint(hint))
	}
	return out, nil
}

func (p *LocalDevProvider) RevokeEndpointHint(ctx context.Context, request EndpointHintRevokeRequest) error {
	if err := p.ready(ctx); err != nil {
		return err
	}
	if !validNamespace(request.Namespace) {
		return ErrInvalidNamespace
	}
	if !validDeviceID(request.DeviceID) {
		return ErrInvalidDeviceID
	}
	if !validID(request.EndpointID) {
		return ErrInvalidEndpointHint
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	delete(p.hints, endpointHintKey(request.Namespace, request.DeviceID, request.EndpointID))
	return nil
}

func (p *LocalDevProvider) Announce(ctx context.Context, announcement RendezvousAnnouncement) error {
	if err := p.ready(ctx); err != nil {
		return err
	}
	if err := ValidateRendezvousAnnouncement(announcement); err != nil {
		return err
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	p.cleanupExpiredLocked(p.now())
	p.announcements[rendezvousKey(announcement.Namespace, announcement.DeviceID, announcement.AnnouncementID)] = cloneRendezvousAnnouncement(announcement)
	return nil
}

func (p *LocalDevProvider) Query(ctx context.Context, query RendezvousQuery) ([]RendezvousPeerHint, error) {
	if err := p.ready(ctx); err != nil {
		return nil, err
	}
	if !validNamespace(query.Namespace) {
		return nil, ErrInvalidNamespace
	}
	if query.ProfileID != "" && !validID(query.ProfileID) {
		return nil, ErrInvalidRendezvous
	}
	if query.DeviceID != "" && !validDeviceID(query.DeviceID) {
		return nil, ErrInvalidDeviceID
	}
	now := query.Now
	if now.IsZero() {
		now = p.now()
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	p.cleanupExpiredLocked(now)
	out := []RendezvousPeerHint{}
	for _, announcement := range p.announcements {
		if announcement.Namespace != query.Namespace ||
			(query.ProfileID != "" && announcement.ProfileID != query.ProfileID) ||
			(query.DeviceID != "" && announcement.DeviceID != query.DeviceID) {
			continue
		}
		out = append(out, RendezvousPeerHint{
			Namespace:     announcement.Namespace,
			ProfileID:     announcement.ProfileID,
			DeviceID:      announcement.DeviceID,
			EndpointHints: cloneEndpointHints(announcement.EndpointHints),
			LastSeen:      announcement.CreatedAt,
			ExpiresAt:     announcement.ExpiresAt,
			Metadata:      cloneStringMap(announcement.Metadata),
		})
	}
	return out, nil
}

func (p *LocalDevProvider) Revoke(ctx context.Context, request RendezvousRevokeRequest) error {
	if err := p.ready(ctx); err != nil {
		return err
	}
	if !validNamespace(request.Namespace) {
		return ErrInvalidNamespace
	}
	if !validDeviceID(request.DeviceID) || !validID(request.AnnouncementID) {
		return ErrInvalidRendezvous
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	delete(p.announcements, rendezvousKey(request.Namespace, request.DeviceID, request.AnnouncementID))
	return nil
}

func (p *LocalDevProvider) OpenMailbox(ctx context.Context, request MailboxOpenRequest) (MailboxRef, error) {
	if err := p.ready(ctx); err != nil {
		return MailboxRef{}, err
	}
	if err := ValidateMailboxOpenRequest(request); err != nil {
		return MailboxRef{}, err
	}
	now := p.now()
	p.mu.Lock()
	defer p.mu.Unlock()
	p.cleanupExpiredLocked(now)
	if request.MailboxID == "" {
		request.MailboxID = p.nextMailboxIDLocked(now)
	}
	ref := MailboxRef{
		Namespace:     request.Namespace,
		MailboxID:     request.MailboxID,
		OwnerDeviceID: request.OwnerDeviceID,
		ProviderID:    p.providerID,
		ExpiresAt:     request.ExpiresAt,
		Metadata:      cloneStringMap(request.Metadata),
	}
	p.mailboxes[mailboxKey(ref.Namespace, ref.MailboxID)] = ref
	return ref, nil
}

func (p *LocalDevProvider) SendEnvelope(ctx context.Context, envelope RelayEnvelope) (DeliveryReceipt, error) {
	if err := p.ready(ctx); err != nil {
		return DeliveryReceipt{}, err
	}
	if err := ValidateEnvelopeWithLimit(envelope, p.maxPayload); err != nil {
		return DeliveryReceipt{}, err
	}
	now := p.now()
	p.mu.Lock()
	defer p.mu.Unlock()
	p.cleanupExpiredLocked(now)
	seenKey := envelopeDeliveryKey(envelope)
	if _, ok := p.seen[seenKey]; ok {
		return DeliveryReceipt{}, ErrDuplicateEnvelope
	}
	targetKeys, err := p.targetMailboxKeysLocked(envelope, now)
	if err != nil {
		return DeliveryReceipt{}, err
	}
	stored := cloneRelayEnvelope(envelope)
	for _, key := range targetKeys {
		p.envelopes[key] = append(p.envelopes[key], stored)
	}
	receipt := DeliveryReceipt{MessageID: envelope.MessageID, Accepted: true, Delivered: len(targetKeys) > 0, ReceivedAt: now, Summary: "local/dev relay accepted envelope metadata"}
	p.seen[seenKey] = seenDelivery{Receipt: receipt, ExpiresAt: envelope.ExpiresAt}
	return receipt, nil
}

func (p *LocalDevProvider) ReceiveEnvelopes(ctx context.Context, mailbox MailboxRef) ([]RelayEnvelope, error) {
	if err := p.ready(ctx); err != nil {
		return nil, err
	}
	if err := ValidateMailboxRef(mailbox); err != nil {
		return nil, err
	}
	now := p.now()
	p.mu.Lock()
	defer p.mu.Unlock()
	ref, ok := p.mailboxes[mailboxKey(mailbox.Namespace, mailbox.MailboxID)]
	if !ok {
		return nil, ErrMailboxNotFound
	}
	if expiredAt(ref.ExpiresAt, now) {
		delete(p.mailboxes, mailboxKey(mailbox.Namespace, mailbox.MailboxID))
		return nil, ErrMailboxExpired
	}
	key := mailboxKey(mailbox.Namespace, mailbox.MailboxID)
	queued := p.envelopes[key]
	out := make([]RelayEnvelope, 0, len(queued))
	for _, envelope := range queued {
		if expiredAt(envelope.ExpiresAt, now) {
			continue
		}
		out = append(out, cloneRelayEnvelope(envelope))
	}
	delete(p.envelopes, key)
	return out, nil
}

func (p *LocalDevProvider) CleanupExpired(ctx context.Context) error {
	if err := p.ready(ctx); err != nil {
		return err
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	p.cleanupExpiredLocked(p.now())
	return nil
}

func (p *LocalDevProvider) ready(ctx context.Context) error {
	if p == nil {
		return ErrProviderUnavailable
	}
	if p.disabled {
		return ErrDisabled
	}
	if ctx != nil {
		if err := SanitizeProviderError(ctx.Err()); err != nil {
			return err
		}
	}
	p.mu.Lock()
	unavailable := p.unavailable
	p.mu.Unlock()
	if unavailable {
		return ErrProviderUnavailable
	}
	return nil
}

func (p *LocalDevProvider) now() time.Time {
	if p != nil && p.clock != nil {
		return p.clock.Now().UTC()
	}
	return time.Now().UTC()
}

func (p *LocalDevProvider) targetMailboxKeysLocked(envelope RelayEnvelope, now time.Time) ([]string, error) {
	if envelope.TargetMailboxID != "" {
		key := mailboxKey(envelope.Namespace, envelope.TargetMailboxID)
		ref, ok := p.mailboxes[key]
		if !ok {
			return nil, ErrMailboxNotFound
		}
		if expiredAt(ref.ExpiresAt, now) {
			delete(p.mailboxes, key)
			return nil, ErrMailboxExpired
		}
		return []string{key}, nil
	}
	keys := []string{}
	for key, ref := range p.mailboxes {
		if ref.Namespace == envelope.Namespace && ref.OwnerDeviceID == envelope.TargetDeviceID && !expiredAt(ref.ExpiresAt, now) {
			keys = append(keys, key)
		}
	}
	if len(keys) == 0 {
		return nil, ErrMailboxNotFound
	}
	return keys, nil
}

func (p *LocalDevProvider) cleanupExpiredLocked(now time.Time) {
	for key, hint := range p.hints {
		if expiredAt(hint.ExpiresAt, now) {
			delete(p.hints, key)
		}
	}
	for key, announcement := range p.announcements {
		if expiredAt(announcement.ExpiresAt, now) {
			delete(p.announcements, key)
		}
	}
	for key, mailbox := range p.mailboxes {
		if expiredAt(mailbox.ExpiresAt, now) {
			delete(p.mailboxes, key)
			delete(p.envelopes, key)
		}
	}
	for key, queued := range p.envelopes {
		filtered := queued[:0]
		for _, envelope := range queued {
			if !expiredAt(envelope.ExpiresAt, now) {
				filtered = append(filtered, envelope)
			}
		}
		if len(filtered) == 0 {
			delete(p.envelopes, key)
		} else {
			p.envelopes[key] = filtered
		}
	}
	for key, seen := range p.seen {
		if expiredAt(seen.ExpiresAt, now) {
			delete(p.seen, key)
		}
	}
}

func (p *LocalDevProvider) nextMailboxIDLocked(now time.Time) string {
	p.mailboxSeq++
	return fmt.Sprintf("mbox-%d-%d", now.UnixNano(), p.mailboxSeq)
}

func expiredAt(expiresAt, now time.Time) bool {
	return expiresAt.IsZero() || expiresAt.Before(now.Add(-defaultClockSkew))
}

func endpointHintKey(namespace, deviceID, endpointID string) string {
	return namespace + "|" + deviceID + "|" + endpointID
}

func rendezvousKey(namespace, deviceID, announcementID string) string {
	return namespace + "|" + deviceID + "|" + announcementID
}

func mailboxKey(namespace, mailboxID string) string {
	return namespace + "|" + mailboxID
}

func envelopeDeliveryKey(envelope RelayEnvelope) string {
	return envelope.Namespace + "|" + envelope.MessageID + "|" + envelope.TargetDeviceID + "|" + envelope.TargetMailboxID
}

func cloneEndpointHint(hint EndpointHint) EndpointHint {
	hint.Capabilities = append([]string{}, hint.Capabilities...)
	hint.Metadata = cloneStringMap(hint.Metadata)
	return hint
}

func cloneEndpointHints(in []EndpointHint) []EndpointHint {
	out := make([]EndpointHint, 0, len(in))
	for _, hint := range in {
		out = append(out, cloneEndpointHint(hint))
	}
	return out
}

func cloneRendezvousAnnouncement(announcement RendezvousAnnouncement) RendezvousAnnouncement {
	announcement.EndpointHints = cloneEndpointHints(announcement.EndpointHints)
	announcement.Metadata = cloneStringMap(announcement.Metadata)
	return announcement
}

func cloneRelayEnvelope(envelope RelayEnvelope) RelayEnvelope {
	envelope.Payload = append([]byte{}, envelope.Payload...)
	envelope.Metadata = cloneStringMap(envelope.Metadata)
	return envelope
}

func cloneStringMap(in map[string]string) map[string]string {
	if in == nil {
		return nil
	}
	out := map[string]string{}
	for key, value := range in {
		out[key] = value
	}
	return out
}

var _ RelayProvider = (*LocalDevProvider)(nil)
var _ RendezvousProvider = (*LocalDevProvider)(nil)

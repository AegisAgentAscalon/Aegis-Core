package relay

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestRelayConfigValidation(t *testing.T) {
	if err := ValidateConfig(RelayConfig{Enabled: false}); err != nil {
		t.Fatalf("disabled relay should be valid: %v", err)
	}
	if err := ValidateConfig(RelayConfig{Enabled: true, Namespace: "profile-a", ProviderID: "provider-1"}); err != nil {
		t.Fatalf("valid config failed: %v", err)
	}
	for _, namespace := range []string{"", "../x", `..\x`, "bad/name", `bad\name`, "CON"} {
		if err := ValidateConfig(RelayConfig{Enabled: true, Namespace: namespace}); !errors.Is(err, ErrInvalidNamespace) {
			t.Fatalf("namespace %q error = %v, want ErrInvalidNamespace", namespace, err)
		}
	}
}

func TestEndpointHintValidationAndExpiry(t *testing.T) {
	now := time.Now().UTC()
	hint := validEndpointHint(now)
	if err := ValidateEndpointHint(hint); err != nil {
		t.Fatalf("valid endpoint hint failed: %v", err)
	}
	hint.DeviceID = "../device"
	if err := ValidateEndpointHint(hint); !errors.Is(err, ErrInvalidDeviceID) {
		t.Fatalf("bad device id error = %v", err)
	}
	expired := validEndpointHint(now)
	expired.ExpiresAt = now.Add(-10 * time.Minute)
	if err := ValidateEndpointHint(expired); !errors.Is(err, ErrExpiredEndpointHint) {
		t.Fatalf("expired hint error = %v", err)
	}
	skew := validEndpointHint(now)
	skew.CreatedAt = now.Add(-5 * time.Minute)
	skew.ExpiresAt = now.Add(-time.Minute)
	if err := ValidateEndpointHint(skew); err != nil {
		t.Fatalf("clock-skew expiry should be accepted: %v", err)
	}
}

func TestRendezvousAnnouncementValidation(t *testing.T) {
	now := time.Now().UTC()
	announcement := RendezvousAnnouncement{
		ProtocolVersion: ProtocolVersion,
		Namespace:       "profile-a",
		ProfileID:       "profile-1",
		DeviceID:        "device-1",
		AnnouncementID:  "ann-1",
		CreatedAt:       now,
		ExpiresAt:       now.Add(time.Minute),
		EndpointHints:   []EndpointHint{validEndpointHint(now)},
	}
	if err := ValidateRendezvousAnnouncement(announcement); err != nil {
		t.Fatalf("valid announcement failed: %v", err)
	}
	announcement.EndpointHints[0].DeviceID = "device-2"
	if err := ValidateRendezvousAnnouncement(announcement); !errors.Is(err, ErrInvalidRendezvous) {
		t.Fatalf("mismatched hint error = %v", err)
	}
	announcement = RendezvousAnnouncement{ProtocolVersion: ProtocolVersion, Namespace: "profile-a", DeviceID: "device-1", AnnouncementID: "ann-1", CreatedAt: now.Add(-time.Hour), ExpiresAt: now.Add(-30 * time.Minute)}
	if err := ValidateRendezvousAnnouncement(announcement); !errors.Is(err, ErrStaleRendezvous) {
		t.Fatalf("stale announcement error = %v", err)
	}
}

func TestMailboxValidationAndExpiry(t *testing.T) {
	now := time.Now().UTC()
	req := MailboxOpenRequest{Namespace: "profile-a", OwnerDeviceID: "device-1", MailboxID: "mbox-1", CreatedAt: now, ExpiresAt: now.Add(time.Minute)}
	if err := ValidateMailboxOpenRequest(req); err != nil {
		t.Fatalf("valid mailbox request failed: %v", err)
	}
	req.OwnerDeviceID = "bad/device"
	if err := ValidateMailboxOpenRequest(req); !errors.Is(err, ErrInvalidDeviceID) {
		t.Fatalf("invalid owner error = %v", err)
	}
	ref := MailboxRef{Namespace: "profile-a", OwnerDeviceID: "device-1", MailboxID: "mbox-1", ProviderID: "provider-1", ExpiresAt: now.Add(time.Minute)}
	if err := ValidateMailboxRef(ref); err != nil {
		t.Fatalf("valid mailbox ref failed: %v", err)
	}
	ref.ExpiresAt = now.Add(-10 * time.Minute)
	if err := ValidateMailboxRef(ref); !errors.Is(err, ErrMailboxExpired) {
		t.Fatalf("expired mailbox ref error = %v", err)
	}
}

func TestEnvelopeValidationFailureModes(t *testing.T) {
	now := time.Now().UTC()
	envelope := validEnvelope(now, []byte("hello"))
	if err := ValidateEnvelope(envelope); err != nil {
		t.Fatalf("valid envelope failed: %v", err)
	}
	cases := []struct {
		name string
		edit func(*RelayEnvelope)
		want error
	}{
		{"expired", func(e *RelayEnvelope) { e.CreatedAt = now.Add(-time.Hour); e.ExpiresAt = now.Add(-30 * time.Minute) }, ErrEnvelopeExpired},
		{"unsupported protocol", func(e *RelayEnvelope) { e.ProtocolVersion = 999 }, ErrUnsupportedProtocolVersion},
		{"oversized", func(e *RelayEnvelope) {
			e.Payload = make([]byte, DefaultMaxPayloadSize+1)
			e.PayloadHash = PayloadSHA256(e.Payload)
		}, ErrPayloadTooLarge},
		{"missing hash", func(e *RelayEnvelope) { e.PayloadHash = "" }, ErrMissingPayloadHash},
		{"hash mismatch", func(e *RelayEnvelope) { e.PayloadHash = PayloadSHA256([]byte("different")) }, ErrPayloadHashMismatch},
		{"unsafe metadata", func(e *RelayEnvelope) { e.Metadata = map[string]string{"access_token": "x"} }, ErrInvalidMetadata},
		{"bad source", func(e *RelayEnvelope) { e.SourceDeviceID = `/tmp/x` }, ErrInvalidDeviceID},
		{"bad target", func(e *RelayEnvelope) { e.TargetDeviceID = `..\x` }, ErrInvalidDeviceID},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			copy := envelope
			copy.Payload = append([]byte{}, envelope.Payload...)
			copy.Metadata = map[string]string{"purpose": "test"}
			tc.edit(&copy)
			if err := ValidateEnvelope(copy); !errors.Is(err, tc.want) {
				t.Fatalf("error = %v, want %v", err, tc.want)
			}
		})
	}
}

func TestMetadataRejectsSecretsAndPaths(t *testing.T) {
	for _, metadata := range []map[string]string{
		{"safe": `C:\Users\person\token.txt`},
		{"client_secret": "value"},
		{"path": "/Users/name/private_key"},
	} {
		if err := ValidateMetadata(metadata); !errors.Is(err, ErrInvalidMetadata) {
			t.Fatalf("metadata %v error = %v, want ErrInvalidMetadata", metadata, err)
		}
	}
}

func TestMemoryProviderSendReceiveReplayAndMailboxExpiry(t *testing.T) {
	ctx := context.Background()
	now := time.Now().UTC()
	provider := newTestMemoryProvider("provider-1", now)
	mailbox, err := provider.OpenMailbox(ctx, MailboxOpenRequest{Namespace: "profile-a", OwnerDeviceID: "device-2", MailboxID: "mbox-1", CreatedAt: now, ExpiresAt: now.Add(time.Minute)})
	if err != nil {
		t.Fatalf("OpenMailbox returned error: %v", err)
	}
	envelope := validEnvelope(now, []byte("ping"))
	envelope.TargetDeviceID = ""
	envelope.TargetMailboxID = mailbox.MailboxID
	receipt, err := provider.SendEnvelope(ctx, envelope)
	if err != nil {
		t.Fatalf("SendEnvelope returned error: %v", err)
	}
	if !receipt.Accepted || receipt.MessageID != envelope.MessageID {
		t.Fatalf("unexpected receipt: %+v", receipt)
	}
	if _, err := provider.SendEnvelope(ctx, envelope); !errors.Is(err, ErrDuplicateEnvelope) {
		t.Fatalf("duplicate send error = %v", err)
	}
	received, err := provider.ReceiveEnvelopes(ctx, mailbox)
	if err != nil {
		t.Fatalf("ReceiveEnvelopes returned error: %v", err)
	}
	if len(received) != 1 || string(received[0].Payload) != "ping" {
		t.Fatalf("unexpected received envelopes: %+v", received)
	}
	provider.now = now.Add(2 * time.Hour)
	if _, err := provider.ReceiveEnvelopes(ctx, mailbox); !errors.Is(err, ErrMailboxExpired) {
		t.Fatalf("expired mailbox receive error = %v", err)
	}
}

func TestMemoryProviderEndpointAndRendezvousBehavior(t *testing.T) {
	ctx := context.Background()
	now := time.Now().UTC()
	provider := newTestMemoryProvider("provider-1", now)
	hint := validEndpointHint(now)
	if err := provider.PublishEndpointHint(ctx, hint); err != nil {
		t.Fatalf("PublishEndpointHint returned error: %v", err)
	}
	hints, err := provider.ListEndpointHints(ctx, EndpointHintQuery{Namespace: "profile-a", DeviceID: "device-1"})
	if err != nil {
		t.Fatalf("ListEndpointHints returned error: %v", err)
	}
	if len(hints) != 1 {
		t.Fatalf("expected one endpoint hint, got %d", len(hints))
	}
	announcement := RendezvousAnnouncement{ProtocolVersion: ProtocolVersion, Namespace: "profile-a", ProfileID: "profile-1", DeviceID: "device-1", AnnouncementID: "ann-1", CreatedAt: now, ExpiresAt: now.Add(time.Minute), EndpointHints: []EndpointHint{hint}}
	if err := provider.Announce(ctx, announcement); err != nil {
		t.Fatalf("Announce returned error: %v", err)
	}
	peers, err := provider.Query(ctx, RendezvousQuery{Namespace: "profile-a", ProfileID: "profile-1"})
	if err != nil {
		t.Fatalf("Query returned error: %v", err)
	}
	if len(peers) != 1 || peers[0].DeviceID != "device-1" {
		t.Fatalf("unexpected peer hints: %+v", peers)
	}
	if err := provider.Revoke(ctx, RendezvousRevokeRequest{Namespace: "profile-a", DeviceID: "device-1", AnnouncementID: "ann-1"}); err != nil {
		t.Fatalf("Revoke returned error: %v", err)
	}
	peers, err = provider.Query(ctx, RendezvousQuery{Namespace: "profile-a", ProfileID: "profile-1"})
	if err != nil {
		t.Fatalf("Query after revoke returned error: %v", err)
	}
	if len(peers) != 0 {
		t.Fatalf("revoked announcement still returned peers: %+v", peers)
	}
}

func TestProviderUnavailableTimeoutAndStatusAreSafe(t *testing.T) {
	if err := SanitizeProviderError(errors.New(`C:\Users\name\secret-token.txt`)); !errors.Is(err, ErrProviderUnavailable) || strings.Contains(err.Error(), `C:\`) || strings.Contains(strings.ToLower(err.Error()), "secret") {
		t.Fatalf("provider error was not sanitized: %v", err)
	}
	if err := SanitizeProviderError(context.DeadlineExceeded); !errors.Is(err, ErrProviderTimeout) {
		t.Fatalf("timeout error = %v", err)
	}
	status := DisabledStatus()
	if status.Enabled || status.Available || strings.Contains(strings.ToLower(status.Summary), "secret") {
		t.Fatalf("disabled status should be safe and non-fatal: %+v", status)
	}
}

func TestRelayPackageDoesNotImportInternalsOrExamples(t *testing.T) {
	files, err := filepath.Glob("*.go")
	if err != nil {
		t.Fatalf("glob relay files: %v", err)
	}
	for _, file := range files {
		if strings.HasSuffix(file, "_test.go") {
			continue
		}
		raw, err := os.ReadFile(file)
		if err != nil {
			t.Fatalf("read %s: %v", file, err)
		}
		text := string(raw)
		for _, forbidden := range []string{"/internal/", "internal/", "examples/", "named-consumer-app", "named-consumer-current", "named-consumer.local"} {
			if strings.Contains(text, forbidden) {
				t.Fatalf("pkg/relay imports or references forbidden text %q in %s", forbidden, file)
			}
		}
	}
}

func validEndpointHint(now time.Time) EndpointHint {
	return EndpointHint{
		ProtocolVersion: ProtocolVersion,
		Namespace:       "profile-a",
		DeviceID:        "device-1",
		EndpointID:      "endpoint-1",
		EndpointType:    "mailbox",
		ProviderID:      "provider-1",
		CreatedAt:       now,
		ExpiresAt:       now.Add(time.Minute),
		Capabilities:    []string{"relay"},
		Metadata:        map[string]string{"purpose": "test"},
	}
}

func validEnvelope(now time.Time, payload []byte) RelayEnvelope {
	return RelayEnvelope{
		RelayEnvelopeMetadata: RelayEnvelopeMetadata{
			ProtocolVersion: ProtocolVersion,
			Namespace:       "profile-a",
			SourceDeviceID:  "device-1",
			TargetDeviceID:  "device-2",
			MessageKind:     MessageKindOpaque,
			CreatedAt:       now,
			ExpiresAt:       now.Add(time.Minute),
			MessageID:       "msg-1",
			PayloadHash:     PayloadSHA256(payload),
			Metadata:        map[string]string{"purpose": "test"},
		},
		Payload: payload,
	}
}

type testMemoryProvider struct {
	providerID    string
	now           time.Time
	mu            sync.Mutex
	hints         map[string]EndpointHint
	announcements map[string]RendezvousAnnouncement
	mailboxes     map[string]MailboxRef
	envelopes     map[string][]RelayEnvelope
	seen          map[string]bool
}

func newTestMemoryProvider(providerID string, now time.Time) *testMemoryProvider {
	return &testMemoryProvider{
		providerID:    providerID,
		now:           now,
		hints:         map[string]EndpointHint{},
		announcements: map[string]RendezvousAnnouncement{},
		mailboxes:     map[string]MailboxRef{},
		envelopes:     map[string][]RelayEnvelope{},
		seen:          map[string]bool{},
	}
}

func (p *testMemoryProvider) GetStatus(ctx context.Context) RelayStatus {
	if err := ctx.Err(); err != nil {
		return RelayStatus{Enabled: true, Available: false, ProviderID: p.providerID, Issues: []RelayIssue{{Code: "relay_unavailable", Message: SanitizeProviderError(err).Error(), Blocking: false}}}
	}
	return RelayStatus{Enabled: true, Available: true, ProviderID: p.providerID, Summary: "relay provider is available"}
}

func (p *testMemoryProvider) PublishEndpointHint(ctx context.Context, hint EndpointHint) error {
	if err := SanitizeProviderError(ctx.Err()); err != nil {
		return err
	}
	if err := ValidateEndpointHint(hint); err != nil {
		return err
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	p.hints[hint.Namespace+"|"+hint.DeviceID+"|"+hint.EndpointID] = hint
	return nil
}

func (p *testMemoryProvider) ListEndpointHints(ctx context.Context, query EndpointHintQuery) ([]EndpointHint, error) {
	if err := SanitizeProviderError(ctx.Err()); err != nil {
		return nil, err
	}
	if !validNamespace(query.Namespace) {
		return nil, ErrInvalidNamespace
	}
	if query.DeviceID != "" && !validDeviceID(query.DeviceID) {
		return nil, ErrInvalidDeviceID
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	var out []EndpointHint
	for _, hint := range p.hints {
		if hint.Namespace != query.Namespace || (query.DeviceID != "" && hint.DeviceID != query.DeviceID) {
			continue
		}
		if hint.ExpiresAt.Before(p.now.Add(-defaultClockSkew)) {
			continue
		}
		out = append(out, hint)
	}
	return out, nil
}

func (p *testMemoryProvider) OpenMailbox(ctx context.Context, request MailboxOpenRequest) (MailboxRef, error) {
	if err := SanitizeProviderError(ctx.Err()); err != nil {
		return MailboxRef{}, err
	}
	if err := ValidateMailboxOpenRequest(request); err != nil {
		return MailboxRef{}, err
	}
	ref := MailboxRef{Namespace: request.Namespace, MailboxID: request.MailboxID, OwnerDeviceID: request.OwnerDeviceID, ProviderID: p.providerID, ExpiresAt: request.ExpiresAt, Metadata: request.Metadata}
	p.mu.Lock()
	defer p.mu.Unlock()
	p.mailboxes[ref.Namespace+"|"+ref.MailboxID] = ref
	return ref, nil
}

func (p *testMemoryProvider) SendEnvelope(ctx context.Context, envelope RelayEnvelope) (DeliveryReceipt, error) {
	if err := SanitizeProviderError(ctx.Err()); err != nil {
		return DeliveryReceipt{}, err
	}
	if err := ValidateEnvelope(envelope); err != nil {
		return DeliveryReceipt{}, err
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.seen[envelope.Namespace+"|"+envelope.MessageID] {
		return DeliveryReceipt{}, ErrDuplicateEnvelope
	}
	if envelope.TargetMailboxID != "" {
		ref, ok := p.mailboxes[envelope.Namespace+"|"+envelope.TargetMailboxID]
		if !ok {
			return DeliveryReceipt{}, ErrMailboxNotFound
		}
		if ref.ExpiresAt.Before(p.now.Add(-defaultClockSkew)) {
			return DeliveryReceipt{}, ErrMailboxExpired
		}
	}
	p.seen[envelope.Namespace+"|"+envelope.MessageID] = true
	p.envelopes[envelope.Namespace+"|"+envelope.TargetMailboxID] = append(p.envelopes[envelope.Namespace+"|"+envelope.TargetMailboxID], envelope)
	return DeliveryReceipt{MessageID: envelope.MessageID, Accepted: true, Delivered: true, ReceivedAt: p.now, Summary: "relay accepted envelope metadata"}, nil
}

func (p *testMemoryProvider) ReceiveEnvelopes(ctx context.Context, mailbox MailboxRef) ([]RelayEnvelope, error) {
	if err := SanitizeProviderError(ctx.Err()); err != nil {
		return nil, err
	}
	if err := ValidateMailboxRef(mailbox); err != nil {
		return nil, err
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	ref, ok := p.mailboxes[mailbox.Namespace+"|"+mailbox.MailboxID]
	if !ok {
		return nil, ErrMailboxNotFound
	}
	if ref.ExpiresAt.Before(p.now.Add(-defaultClockSkew)) {
		return nil, ErrMailboxExpired
	}
	envelopes := append([]RelayEnvelope{}, p.envelopes[mailbox.Namespace+"|"+mailbox.MailboxID]...)
	return envelopes, nil
}

func (p *testMemoryProvider) Announce(ctx context.Context, announcement RendezvousAnnouncement) error {
	if err := SanitizeProviderError(ctx.Err()); err != nil {
		return err
	}
	if err := ValidateRendezvousAnnouncement(announcement); err != nil {
		return err
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	p.announcements[announcement.Namespace+"|"+announcement.DeviceID+"|"+announcement.AnnouncementID] = announcement
	return nil
}

func (p *testMemoryProvider) Query(ctx context.Context, query RendezvousQuery) ([]RendezvousPeerHint, error) {
	if err := SanitizeProviderError(ctx.Err()); err != nil {
		return nil, err
	}
	if !validNamespace(query.Namespace) {
		return nil, ErrInvalidNamespace
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	var out []RendezvousPeerHint
	for _, ann := range p.announcements {
		if ann.Namespace != query.Namespace || (query.ProfileID != "" && ann.ProfileID != query.ProfileID) || (query.DeviceID != "" && ann.DeviceID != query.DeviceID) {
			continue
		}
		if ann.ExpiresAt.Before(p.now.Add(-defaultClockSkew)) {
			continue
		}
		out = append(out, RendezvousPeerHint{Namespace: ann.Namespace, ProfileID: ann.ProfileID, DeviceID: ann.DeviceID, EndpointHints: ann.EndpointHints, LastSeen: ann.CreatedAt, ExpiresAt: ann.ExpiresAt, Metadata: ann.Metadata})
	}
	return out, nil
}

func (p *testMemoryProvider) Revoke(ctx context.Context, request RendezvousRevokeRequest) error {
	if err := SanitizeProviderError(ctx.Err()); err != nil {
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
	delete(p.announcements, request.Namespace+"|"+request.DeviceID+"|"+request.AnnouncementID)
	return nil
}

var _ RelayProvider = (*testMemoryProvider)(nil)
var _ RendezvousProvider = (*testMemoryProvider)(nil)

package profilesync

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/AegisAgentAscalon/aegis-core/pkg/relay"
)

func TestReceiveOnlyRelaySyncTransportPullsWithoutFakeTarget(t *testing.T) {
	ctx := context.Background()
	now := time.Now().UTC()
	clock := &syncClock{now: now}
	provider, err := relay.NewLocalDevProvider(relay.LocalDevProviderConfig{ProviderID: "local-dev-relay", Clock: clock})
	if err != nil {
		t.Fatalf("NewLocalDevProvider returned error: %v", err)
	}
	mailboxID, err := DeterministicRelayMailboxID("profile-a", "device-local")
	if err != nil {
		t.Fatalf("DeterministicRelayMailboxID returned error: %v", err)
	}
	mailbox, err := provider.OpenMailbox(ctx, relay.MailboxOpenRequest{Namespace: "profile-a", OwnerDeviceID: "device-local", MailboxID: mailboxID, CreatedAt: now, ExpiresAt: now.Add(time.Hour)})
	if err != nil {
		t.Fatalf("OpenMailbox returned error: %v", err)
	}
	transport, err := NewReceiveOnlyRelaySyncTransport(RelaySyncTransportConfig{Provider: provider, Namespace: "profile-a", SourceDeviceID: "device-local", Mailbox: mailbox, Clock: clock})
	if err != nil {
		t.Fatalf("NewReceiveOnlyRelaySyncTransport returned error: %v", err)
	}

	envelope := snapshotEnvelope("profile-a", "device-remote", validSyncSnapshot("snapshot-receive-only", "", now), now)
	sendSyncEnvelope(t, provider, mailbox.MailboxID, envelope, now, "msg-receive-only")
	received, err := transport.PullEnvelopes(ctx)
	if err != nil || len(received) != 1 || received[0].MessageID != "msg-receive-only" {
		t.Fatalf("PullEnvelopes = %+v, %v", received, err)
	}
	if _, err := transport.PushEnvelope(ctx, envelope); !errors.Is(err, ErrReceiveOnlyTransport) {
		t.Fatalf("receive-only PushEnvelope error = %v", err)
	}
	diagnostics := transport.BuildDiagnostics(ctx)
	if !diagnostics.Available || !diagnostics.ReceiveOnly || !diagnostics.ReceiveAvailable || diagnostics.SendConfigured || diagnostics.SendAvailable {
		t.Fatalf("receive-only diagnostics = %+v", diagnostics)
	}
	if diagnostics.MailboxExpiresAtRFC3339 != FormatStatusTimeRFC3339(mailbox.ExpiresAt) {
		t.Fatalf("mailbox expiry = %q", diagnostics.MailboxExpiresAtRFC3339)
	}
	if _, err := NewReceiveOnlyRelaySyncTransport(RelaySyncTransportConfig{Provider: provider, Namespace: "profile-a", SourceDeviceID: "device-local", TargetDeviceID: "fake-target", Mailbox: mailbox, Clock: clock}); !errors.Is(err, ErrInvalidConfig) {
		t.Fatalf("receive-only constructor with target error = %v", err)
	}
}

func TestDeterministicRelayMailboxIDIsStableAndIsolated(t *testing.T) {
	first, err := DeterministicRelayMailboxID("profile-a", "device-a")
	if err != nil {
		t.Fatalf("first mailbox ID error: %v", err)
	}
	second, err := DeterministicRelayMailboxID("profile-a", "device-a")
	if err != nil {
		t.Fatalf("second mailbox ID error: %v", err)
	}
	otherNamespace, err := DeterministicRelayMailboxID("profile-b", "device-a")
	if err != nil {
		t.Fatalf("other namespace mailbox ID error: %v", err)
	}
	otherDevice, err := DeterministicRelayMailboxID("profile-a", "device-b")
	if err != nil {
		t.Fatalf("other device mailbox ID error: %v", err)
	}
	if first != second || first == otherNamespace || first == otherDevice || otherNamespace == otherDevice {
		t.Fatalf("mailbox isolation failed: %q %q %q %q", first, second, otherNamespace, otherDevice)
	}
	if err := relay.ValidateMailboxID(first); err != nil {
		t.Fatalf("deterministic mailbox ID is invalid: %v", err)
	}
	if strings.Contains(first, "profile-a") || strings.Contains(first, "device-a") {
		t.Fatalf("deterministic mailbox ID exposes inputs: %q", first)
	}
	for _, test := range []struct {
		name      string
		namespace string
		deviceID  string
	}{
		{name: "empty namespace", namespace: "", deviceID: "device-a"},
		{name: "trimmed namespace", namespace: " profile-a", deviceID: "device-a"},
		{name: "traversal namespace", namespace: "../profile-a", deviceID: "device-a"},
		{name: "empty device", namespace: "profile-a", deviceID: ""},
		{name: "unsafe device", namespace: "profile-a", deviceID: "client_secret"},
	} {
		t.Run(test.name, func(t *testing.T) {
			if _, err := DeterministicRelayMailboxID(test.namespace, test.deviceID); !errors.Is(err, ErrInvalidConfig) {
				t.Fatalf("DeterministicRelayMailboxID error = %v", err)
			}
		})
	}
}

func TestRelaySyncDiagnosticsRedactProviderAndRoutingDetails(t *testing.T) {
	now := time.Now().UTC()
	mailbox := relay.MailboxRef{Namespace: "profile-a", MailboxID: "mailbox-private", OwnerDeviceID: "device-private", ProviderID: "provider-safe", ExpiresAt: now.Add(time.Hour)}
	provider := unsafeDiagnosticsRelayProvider{mailbox: mailbox}
	transport, err := NewReceiveOnlyRelaySyncTransport(RelaySyncTransportConfig{Provider: provider, Namespace: "profile-a", SourceDeviceID: "device-private", Mailbox: mailbox, Clock: &syncClock{now: now}})
	if err != nil {
		t.Fatalf("NewReceiveOnlyRelaySyncTransport returned error: %v", err)
	}
	diagnostics := transport.BuildDiagnostics(context.Background())
	if !diagnostics.Available || diagnostics.ProviderID != "" || diagnostics.Summary != "profile sync relay receive is available" {
		t.Fatalf("diagnostics = %+v", diagnostics)
	}
	raw, err := json.Marshal(diagnostics)
	if err != nil {
		t.Fatalf("marshal diagnostics: %v", err)
	}
	text := strings.ToLower(string(raw))
	for _, forbidden := range []string{"mailbox-private", "device-private", "profile-a", "client_secret", "secret=raw", `c:\\users\\`} {
		if strings.Contains(text, forbidden) {
			t.Fatalf("diagnostics exposed %q in %s", forbidden, text)
		}
	}
	assertSyncSafeJSON(t, diagnostics)
}

func TestPersistExchangeResultValidatesAndSanitizes(t *testing.T) {
	ctx := context.Background()
	now := time.Now().UTC()
	store, err := NewLocalMetadataStore(LocalMetadataStoreConfig{RootDir: t.TempDir(), ProfileNamespace: "profile-a", Clock: &syncClock{now: now}})
	if err != nil {
		t.Fatalf("NewLocalMetadataStore returned error: %v", err)
	}
	result := ExchangeResult{
		Session: SyncSession{SessionID: "sync-20260716120000", ProfileNamespace: "profile-a", LocalDeviceID: "device-local", StartedAt: now.Add(-time.Second), CompletedAt: now},
		Push:    PushResult{PushedSnapshots: 1, PushedProposals: 2, Issues: []SyncIssue{{Code: "client_secret", Message: `C:\Users\person\AppData\secret=raw`, Blocking: true}}},
		Pull:    PullResult{ReceivedSnapshots: 3, ReceivedProposals: 4, Rejected: 1},
		Status:  SyncStatus{Summary: `C:\Users\person\AppData\secret=raw`},
	}
	if err := PersistExchangeResult(ctx, store, result); err != nil {
		t.Fatalf("PersistExchangeResult returned error: %v", err)
	}
	record, err := store.LoadLastExchange(ctx)
	if err != nil {
		t.Fatalf("LoadLastExchange returned error: %v", err)
	}
	if record.PushedSnapshots != 1 || record.PushedProposals != 2 || record.ReceivedSnapshots != 3 || record.ReceivedProposals != 4 || record.Rejected != 1 {
		t.Fatalf("persisted exchange = %+v", record)
	}
	assertSyncSafeJSON(t, record)

	mismatched := result
	mismatched.Session.ProfileNamespace = "profile-b"
	if err := PersistExchangeResult(ctx, store, mismatched); !errors.Is(err, ErrInvalidConfig) {
		t.Fatalf("mismatched exchange error = %v", err)
	}
	if err := PersistExchangeResult(ctx, nil, result); !errors.Is(err, ErrStoreUnavailable) {
		t.Fatalf("nil store error = %v", err)
	}
}

func TestEnvelopeSignatureEvidenceIsPreservedAndBounded(t *testing.T) {
	ctx := context.Background()
	now := time.Now().UTC()
	clock := &syncClock{now: now}
	provider, err := relay.NewLocalDevProvider(relay.LocalDevProviderConfig{ProviderID: "local-dev-relay", Clock: clock})
	if err != nil {
		t.Fatalf("NewLocalDevProvider returned error: %v", err)
	}
	mailbox, err := provider.OpenMailbox(ctx, relay.MailboxOpenRequest{Namespace: "profile-a", OwnerDeviceID: "device-b", MailboxID: "mailbox-b", CreatedAt: now, ExpiresAt: now.Add(time.Hour)})
	if err != nil {
		t.Fatalf("OpenMailbox returned error: %v", err)
	}
	sender, err := NewRelaySyncTransport(RelaySyncTransportConfig{Provider: provider, Namespace: "profile-a", SourceDeviceID: "device-a", TargetMailboxID: mailbox.MailboxID, Clock: clock})
	if err != nil {
		t.Fatalf("sender transport error: %v", err)
	}
	receiver, err := NewReceiveOnlyRelaySyncTransport(RelaySyncTransportConfig{Provider: provider, Namespace: "profile-a", SourceDeviceID: "device-b", Mailbox: mailbox, Clock: clock})
	if err != nil {
		t.Fatalf("receiver transport error: %v", err)
	}
	signature := []byte{0x00, 0x01, 0x7f, 0x80, 0xff}
	envelope := snapshotEnvelope("profile-a", "device-a", validSyncSnapshot("snapshot-signed-envelope", "", now), now)
	envelope.SignatureEvidence = &EnvelopeSignatureEvidence{Algorithm: "ed25519", KeyID: "caller-key-1", Signature: signature}
	if _, err := sender.PushEnvelope(ctx, envelope); err != nil {
		t.Fatalf("PushEnvelope returned error: %v", err)
	}
	received, err := receiver.PullEnvelopes(ctx)
	if err != nil || len(received) != 1 || received[0].SignatureEvidence == nil || !bytes.Equal(received[0].SignatureEvidence.Signature, signature) {
		t.Fatalf("signature evidence was not preserved: %+v, %v", received, err)
	}

	malformed := envelope
	malformed.MessageID = "signature-missing-algorithm"
	malformed.SignatureEvidence = &EnvelopeSignatureEvidence{Signature: []byte{1}}
	if _, err := sender.PushEnvelope(ctx, malformed); !errors.Is(err, ErrInvalidSyncEnvelope) {
		t.Fatalf("malformed signature evidence error = %v", err)
	}
	oversized := envelope
	oversized.MessageID = "signature-oversized"
	oversized.SignatureEvidence = &EnvelopeSignatureEvidence{Algorithm: "ed25519", Signature: bytes.Repeat([]byte{1}, MaxEnvelopeSignatureEvidenceBytes+1)}
	if _, err := sender.PushEnvelope(ctx, oversized); !errors.Is(err, ErrInvalidSyncEnvelope) {
		t.Fatalf("oversized signature evidence error = %v", err)
	}

	malformedPayload := []byte(`{"signature_evidence":{"algorithm":"ed25519","signature":"%%%"}}`)
	malformedProvider := tamperedRelayProvider{mailbox: mailbox, envelope: relay.RelayEnvelope{
		RelayEnvelopeMetadata: relay.RelayEnvelopeMetadata{
			ProtocolVersion: relay.ProtocolVersion,
			Namespace:       "profile-a",
			SourceDeviceID:  "device-a",
			TargetMailboxID: mailbox.MailboxID,
			MessageKind:     relay.MessageKindOpaque,
			CreatedAt:       now,
			ExpiresAt:       now.Add(time.Minute),
			MessageID:       "signature-malformed-base64",
			PayloadHash:     relay.PayloadSHA256(malformedPayload),
		},
		Payload: malformedPayload,
	}}
	malformedReceiver, err := NewReceiveOnlyRelaySyncTransport(RelaySyncTransportConfig{Provider: malformedProvider, Namespace: "profile-a", SourceDeviceID: "device-b", Mailbox: mailbox, Clock: clock})
	if err != nil {
		t.Fatalf("malformed receiver transport error: %v", err)
	}
	if _, err := malformedReceiver.PullEnvelopes(ctx); !errors.Is(err, ErrInvalidSyncEnvelope) {
		t.Fatalf("malformed base64 signature evidence error = %v", err)
	}
}

type unsafeDiagnosticsRelayProvider struct {
	mailbox relay.MailboxRef
}

func (p unsafeDiagnosticsRelayProvider) GetStatus(context.Context) relay.RelayStatus {
	return relay.RelayStatus{Enabled: true, Available: true, ProviderID: "client_secret=raw", Summary: `C:\Users\person\AppData\secret=raw`, Issues: []relay.RelayIssue{{Code: "access_token", Message: "bearer raw"}}}
}

func (p unsafeDiagnosticsRelayProvider) PublishEndpointHint(context.Context, relay.EndpointHint) error {
	return nil
}

func (p unsafeDiagnosticsRelayProvider) ListEndpointHints(context.Context, relay.EndpointHintQuery) ([]relay.EndpointHint, error) {
	return nil, nil
}

func (p unsafeDiagnosticsRelayProvider) OpenMailbox(context.Context, relay.MailboxOpenRequest) (relay.MailboxRef, error) {
	return p.mailbox, nil
}

func (p unsafeDiagnosticsRelayProvider) SendEnvelope(context.Context, relay.RelayEnvelope) (relay.DeliveryReceipt, error) {
	return relay.DeliveryReceipt{}, nil
}

func (p unsafeDiagnosticsRelayProvider) ReceiveEnvelopes(context.Context, relay.MailboxRef) ([]relay.RelayEnvelope, error) {
	return nil, nil
}

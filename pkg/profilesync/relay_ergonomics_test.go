package profilesync

import (
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
	status := transport.GetStatus(ctx)
	if !status.Available || !status.ProviderAvailable || status.PushAvailable || !status.PullAvailable {
		t.Fatalf("receive-only status = %+v", status)
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
	store := NewMemoryMetadataStore()
	local := validSyncSnapshot("snapshot-local", "", now)
	store.SetLocalSnapshot(local)
	manager, err := NewSyncManager(
		SyncConfig{Enabled: true, ProfileNamespace: "profile-a", LocalDeviceID: "device-local"},
		WithSnapshotStore(store),
		WithProposalStore(store),
		WithTransport(transport),
		WithTrustVerifier(staticTrust{trusted: true}),
		WithClock(clock),
	)
	if err != nil {
		t.Fatalf("NewSyncManager returned error: %v", err)
	}
	push, err := manager.PushLocalSnapshot(ctx)
	if !errors.Is(err, ErrReceiveOnlyTransport) || !hasSyncIssue(push.Issues, "push_unavailable") {
		t.Fatalf("receive-only manager push = %+v, %v", push, err)
	}
	managerEnvelope := snapshotEnvelope("profile-a", "device-remote", validSyncSnapshot("snapshot-manager-pull", local.Metadata.SnapshotID, now), now)
	sendSyncEnvelope(t, provider, mailbox.MailboxID, managerEnvelope, now, "msg-manager-pull")
	exchange, err := manager.Exchange(ctx)
	if err != nil || exchange.Push.PushedSnapshots != 0 || exchange.Push.PushedProposals != 0 || exchange.Pull.ReceivedSnapshots != 1 {
		t.Fatalf("receive-only Exchange = %+v, %v", exchange, err)
	}
	diagnostics := transport.BuildDiagnostics(ctx)
	if !diagnostics.Available || !diagnostics.ReceiveOnly || !diagnostics.ReceiveAvailable || diagnostics.SendConfigured || diagnostics.SendAvailable {
		t.Fatalf("receive-only diagnostics = %+v", diagnostics)
	}
	if diagnostics.MailboxExpiresAtRFC3339 != FormatStatusTimeRFC3339(mailbox.ExpiresAt) {
		t.Fatalf("mailbox expiry = %q", diagnostics.MailboxExpiresAtRFC3339)
	}
	clock.now = now.Add(2 * time.Hour)
	expired := transport.GetStatus(ctx)
	if expired.Available || !expired.ProviderAvailable || expired.PushAvailable || expired.PullAvailable || !hasSyncIssue(expired.Issues, "relay_mailbox_expired") {
		t.Fatalf("expired receive-only status = %+v", expired)
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
	const golden = "profilesync-74038c3b861b04bbcacf5fd2aabae477040c12095a1b9cde65ba0d2eb2a65785"
	if first != golden {
		t.Fatalf("deterministic mailbox ID = %q, want golden %q", first, golden)
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
	if !diagnostics.Available || diagnostics.ProviderID != "" || diagnostics.Summary != "profile sync relay pull is available" {
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
	if record.SchemaVersion != LocalExchangeRecordSchemaVersion || record.StatusSummary != "profile sync exchange status" {
		t.Fatalf("persisted exchange schema/redaction = %+v", record)
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

func TestSyncSummaryPathRedactionVectors(t *testing.T) {
	for name, value := range map[string]string{
		"windows drive":    `C:\work\profiles\exchange.json`,
		"windows slash":    `C:/work/profiles/exchange.json`,
		"unc":              `\\server\share\exchange.json`,
		"posix":            `/var/lib/aegis/exchange.json`,
		"relative posix":   `state/exchange.json`,
		"relative windows": `state\exchange.json`,
		"dot relative":     `./state/exchange.json`,
		"parent relative":  `../state/exchange.json`,
		"dot windows":      `.\state\exchange.json`,
		"parent windows":   `..\state\exchange.json`,
	} {
		t.Run(name, func(t *testing.T) {
			if got := safeSummary(value, "redacted summary"); got != "redacted summary" {
				t.Fatalf("safeSummary(%q) = %q", value, got)
			}
		})
	}
}

func TestProfileSyncWireJSONVectors(t *testing.T) {
	now := time.Date(2026, 7, 16, 16, 0, 0, 0, time.UTC)
	vectors := []struct {
		name  string
		value any
		want  string
	}{
		{
			name:  "receive-only transport status",
			value: SyncTransportStatus{Available: true, ProviderAvailable: true, PullAvailable: true, ProviderID: "relay-1", Summary: "profile sync relay pull is available"},
			want:  `{"available":true,"provider_available":true,"push_available":false,"pull_available":true,"provider_id":"relay-1","summary":"profile sync relay pull is available"}`,
		},
		{
			name:  "schema 1 envelope header",
			value: SyncEnvelope{SchemaVersion: EnvelopeSchemaVersion, Kind: EnvelopeKindSnapshot, ProfileNamespace: "profile-a", SourceDeviceID: "device-a", MessageID: "snapshot-1", CreatedAt: now},
			want:  `{"schema_version":1,"kind":"profile_snapshot_metadata","profile_namespace":"profile-a","source_device_id":"device-a","message_id":"snapshot-1","created_at":"2026-07-16T16:00:00Z"}`,
		},
		{
			name:  "schema 2 exchange record",
			value: LocalExchangeRecord{SchemaVersion: LocalExchangeRecordSchemaVersion, ProfileNamespace: "profile-a", Session: SyncSession{SessionID: "sync-1", ProfileNamespace: "profile-a", LocalDeviceID: "device-a", StartedAt: now, CompletedAt: now}, RecordedAt: now},
			want:  `{"schema_version":2,"profile_namespace":"profile-a","session":{"session_id":"sync-1","profile_namespace":"profile-a","local_device_id":"device-a","started_at":"2026-07-16T16:00:00Z","completed_at":"2026-07-16T16:00:00Z","review_required":false},"pushed_snapshots":0,"pushed_proposals":0,"received_snapshots":0,"received_proposals":0,"rejected":0,"review_required":false,"recorded_at":"2026-07-16T16:00:00Z"}`,
		},
	}
	for _, vector := range vectors {
		t.Run(vector.name, func(t *testing.T) {
			raw, err := json.Marshal(vector.value)
			if err != nil {
				t.Fatalf("json.Marshal: %v", err)
			}
			if string(raw) != vector.want {
				t.Fatalf("wire JSON = %s\nwant      = %s", raw, vector.want)
			}
			if vector.name == "schema 1 envelope header" && strings.Contains(string(raw), "signature_evidence") {
				t.Fatalf("schema 1 envelope changed wire shape: %s", raw)
			}
		})
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

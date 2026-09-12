package profilesync

import (
	"context"
	"encoding/json"
	"fmt"
	"testing"
	"time"

	"github.com/AegisAgentAscalon/aegis-core/pkg/relay"
)

// Identical harness can run on frozen W14 via a Go overlay. Setup/reset writes
// are outside timing; actual pending classification and each CAS commit are in.
func BenchmarkReliablePendingBatch(b *testing.B) {
	for _, count := range []int{1, 8, 32} {
		b.Run(fmt.Sprint(count), func(b *testing.B) {
			ctx := context.Background()
			now := time.Date(2026, 9, 12, 12, 0, 0, 0, time.UTC)
			provider, err := relay.NewFileReliableMailbox(relay.FileReliableMailboxConfig{Directory: b.TempDir(), ProviderID: "provider", Namespace: "profile-a", MailboxID: "inbox", OwnerDeviceID: "device-local", Clock: inboxClock{at: now}})
			if err != nil {
				b.Fatal(err)
			}
			inbox, err := NewReliableInbox(ReliableInboxConfig{Directory: b.TempDir(), Mailbox: provider.Mailbox()})
			if err != nil {
				b.Fatal(err)
			}
			for j := 0; j < count; j++ {
				id := fmt.Sprintf("record-%d", j)
				envelope := snapshotEnvelope("profile-a", "device-remote", validSyncSnapshot(id, "local", now), now)
				payload, err := json.Marshal(envelope)
				if err != nil {
					b.Fatal(err)
				}
				carrier := relay.RelayEnvelope{RelayEnvelopeMetadata: relay.RelayEnvelopeMetadata{ProtocolVersion: 1, Namespace: "profile-a", SourceDeviceID: "device-remote", TargetDeviceID: "device-local", TargetMailboxID: "inbox", MessageKind: relay.MessageKindOpaque, MessageID: envelope.MessageID, CreatedAt: now, ExpiresAt: now.Add(time.Hour), PayloadHash: relay.PayloadSHA256(payload)}, Payload: payload}
				if _, err := provider.SendReliableEnvelope(ctx, relay.ReliableSendRequest{ProtocolVersion: 2, Mailbox: provider.Mailbox(), Envelope: carrier}); err != nil {
					b.Fatal(err)
				}
			}
			page, err := provider.ReceiveBatch(ctx, relay.ReceiveBatchRequest{ProtocolVersion: 2, Mailbox: provider.Mailbox()})
			if err != nil || len(page.Items) != count {
				b.Fatal("unexpected page", len(page.Items), err)
			}
			for _, item := range page.Items {
				if err := inbox.accept(ctx, item, now); err != nil {
					b.Fatal(err)
				}
			}
			pending, err := inbox.read(ctx)
			if err != nil {
				b.Fatal(err)
			}
			r := &ReliableSyncReceiver{cfg: ReliableSyncReceiverConfig{Inbox: inbox, Clock: inboxClock{at: now}}}
			local := validSyncSnapshot("local", "", now)
			b.ReportAllocs()
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				b.StopTimer()
				if err := inbox.save(ctx, pending, true); err != nil {
					b.Fatal(err)
				}
				b.StartTimer()
				var result PullResult
				if err := r.processPending(ctx, local, &result); err != nil || result.ReceivedSnapshots != count {
					b.Fatal(result, err)
				}
			}
		})
	}
}

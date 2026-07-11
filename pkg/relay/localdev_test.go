package relay

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestLocalDevProviderEndpointRendezvousMailboxLifecycle(t *testing.T) {
	ctx := context.Background()
	now := time.Now().UTC()
	clock := &mutableRelayClock{now: now}
	provider, err := NewLocalDevProvider(LocalDevProviderConfig{ProviderID: "local-dev-1", Clock: clock})
	if err != nil {
		t.Fatalf("NewLocalDevProvider returned error: %v", err)
	}
	if status := provider.GetStatus(ctx); !status.Enabled || !status.Available || status.ProviderID != "local-dev-1" {
		t.Fatalf("unexpected status: %+v", status)
	}

	hint := validEndpointHint(now)
	if err := provider.PublishEndpointHint(ctx, hint); err != nil {
		t.Fatalf("PublishEndpointHint returned error: %v", err)
	}
	hints, err := provider.ListEndpointHints(ctx, EndpointHintQuery{Namespace: "profile-a", DeviceID: "device-1"})
	if err != nil || len(hints) != 1 {
		t.Fatalf("ListEndpointHints = %+v, %v", hints, err)
	}
	if err := provider.RevokeEndpointHint(ctx, EndpointHintRevokeRequest{Namespace: "profile-a", DeviceID: "device-1", EndpointID: "endpoint-1"}); err != nil {
		t.Fatalf("RevokeEndpointHint returned error: %v", err)
	}
	hints, err = provider.ListEndpointHints(ctx, EndpointHintQuery{Namespace: "profile-a", DeviceID: "device-1"})
	if err != nil || len(hints) != 0 {
		t.Fatalf("revoked endpoint hints = %+v, %v", hints, err)
	}

	announcement := RendezvousAnnouncement{ProtocolVersion: ProtocolVersion, Namespace: "profile-a", ProfileID: "profile-1", DeviceID: "device-1", AnnouncementID: "ann-1", CreatedAt: now, ExpiresAt: now.Add(time.Minute), EndpointHints: []EndpointHint{hint}}
	if err := provider.Announce(ctx, announcement); err != nil {
		t.Fatalf("Announce returned error: %v", err)
	}
	peers, err := provider.Query(ctx, RendezvousQuery{Namespace: "profile-a", ProfileID: "profile-1"})
	if err != nil || len(peers) != 1 {
		t.Fatalf("Query = %+v, %v", peers, err)
	}
	if err := provider.Revoke(ctx, RendezvousRevokeRequest{Namespace: "profile-a", DeviceID: "device-1", AnnouncementID: "ann-1"}); err != nil {
		t.Fatalf("Revoke returned error: %v", err)
	}
	peers, err = provider.Query(ctx, RendezvousQuery{Namespace: "profile-a", ProfileID: "profile-1"})
	if err != nil || len(peers) != 0 {
		t.Fatalf("revoked peers = %+v, %v", peers, err)
	}

	mailbox, err := provider.OpenMailbox(ctx, MailboxOpenRequest{Namespace: "profile-a", OwnerDeviceID: "device-2", MailboxID: "mbox-1", CreatedAt: now, ExpiresAt: now.Add(time.Minute)})
	if err != nil {
		t.Fatalf("OpenMailbox returned error: %v", err)
	}
	envelope := validEnvelope(now, []byte("local-dev-ping"))
	envelope.TargetDeviceID = ""
	envelope.TargetMailboxID = mailbox.MailboxID
	receipt, err := provider.SendEnvelope(ctx, envelope)
	if err != nil {
		t.Fatalf("SendEnvelope returned error: %v", err)
	}
	if !receipt.Accepted || !receipt.Delivered || strings.Contains(receipt.Summary, "local-dev-ping") {
		t.Fatalf("unsafe or unexpected receipt: %+v", receipt)
	}
	if _, err := provider.SendEnvelope(ctx, envelope); !errors.Is(err, ErrDuplicateEnvelope) {
		t.Fatalf("duplicate send error = %v", err)
	}
	received, err := provider.ReceiveEnvelopes(ctx, mailbox)
	if err != nil || len(received) != 1 || string(received[0].Payload) != "local-dev-ping" {
		t.Fatalf("ReceiveEnvelopes = %+v, %v", received, err)
	}
	received, err = provider.ReceiveEnvelopes(ctx, mailbox)
	if err != nil || len(received) != 0 {
		t.Fatalf("mailbox should drain after receive: %+v, %v", received, err)
	}
	assertRelaySafeJSON(t, provider.GetStatus(ctx))
}

func TestLocalDevProviderExpiryAndSafeFailures(t *testing.T) {
	ctx := context.Background()
	now := time.Now().UTC()
	clock := &mutableRelayClock{now: now}
	provider, err := NewLocalDevProvider(LocalDevProviderConfig{ProviderID: "local-dev-1", Clock: clock})
	if err != nil {
		t.Fatalf("NewLocalDevProvider returned error: %v", err)
	}
	if err := provider.PublishEndpointHint(ctx, validEndpointHint(now)); err != nil {
		t.Fatalf("PublishEndpointHint returned error: %v", err)
	}
	announcement := RendezvousAnnouncement{ProtocolVersion: ProtocolVersion, Namespace: "profile-a", ProfileID: "profile-1", DeviceID: "device-1", AnnouncementID: "ann-1", CreatedAt: now, ExpiresAt: now.Add(time.Minute), EndpointHints: []EndpointHint{validEndpointHint(now)}}
	if err := provider.Announce(ctx, announcement); err != nil {
		t.Fatalf("Announce returned error: %v", err)
	}
	mailbox, err := provider.OpenMailbox(ctx, MailboxOpenRequest{Namespace: "profile-a", OwnerDeviceID: "device-2", MailboxID: "mbox-1", CreatedAt: now, ExpiresAt: now.Add(time.Hour)})
	if err != nil {
		t.Fatalf("OpenMailbox returned error: %v", err)
	}
	envelope := validEnvelope(now, []byte("expires-before-mailbox"))
	envelope.TargetMailboxID = mailbox.MailboxID
	envelope.TargetDeviceID = ""
	if _, err := provider.SendEnvelope(ctx, envelope); err != nil {
		t.Fatalf("SendEnvelope returned error: %v", err)
	}
	clock.now = now.Add(10 * time.Minute)
	hints, err := provider.ListEndpointHints(ctx, EndpointHintQuery{Namespace: "profile-a", DeviceID: "device-1"})
	if err != nil || len(hints) != 0 {
		t.Fatalf("expired endpoint hints = %+v, %v", hints, err)
	}
	peers, err := provider.Query(ctx, RendezvousQuery{Namespace: "profile-a", ProfileID: "profile-1"})
	if err != nil || len(peers) != 0 {
		t.Fatalf("expired rendezvous peers = %+v, %v", peers, err)
	}
	received, err := provider.ReceiveEnvelopes(ctx, mailbox)
	if err != nil || len(received) != 0 {
		t.Fatalf("expired envelope should not be delivered: %+v, %v", received, err)
	}

	clock.now = now.Add(2 * time.Hour)
	if _, err := provider.ReceiveEnvelopes(ctx, mailbox); !errors.Is(err, ErrMailboxExpired) {
		t.Fatalf("expired mailbox error = %v", err)
	}

	provider.SetUnavailable(true)
	if err := provider.PublishEndpointHint(ctx, validEndpointHint(now)); !errors.Is(err, ErrProviderUnavailable) {
		t.Fatalf("unavailable provider error = %v", err)
	}
	assertRelaySafeJSON(t, provider.GetStatus(ctx))

	canceled, cancel := context.WithCancel(ctx)
	cancel()
	provider.SetUnavailable(false)
	if _, err := provider.ListEndpointHints(canceled, EndpointHintQuery{Namespace: "profile-a"}); !errors.Is(err, ErrContextCanceled) {
		t.Fatalf("canceled provider error = %v", err)
	}
	timedOut, cancelTimeout := context.WithDeadline(ctx, now.Add(-time.Second))
	defer cancelTimeout()
	if _, err := provider.ListEndpointHints(timedOut, EndpointHintQuery{Namespace: "profile-a"}); !errors.Is(err, ErrProviderTimeout) {
		t.Fatalf("timed-out provider error = %v", err)
	}
}

func TestLocalDevProviderConcurrentAutoMailboxAndSendReceive(t *testing.T) {
	ctx := context.Background()
	now := time.Now().UTC()
	clock := &mutableRelayClock{now: now}
	provider, err := NewLocalDevProvider(LocalDevProviderConfig{ProviderID: "local-dev-1", Clock: clock})
	if err != nil {
		t.Fatalf("NewLocalDevProvider returned error: %v", err)
	}

	const count = 24
	var openWG sync.WaitGroup
	ids := make(chan string, count)
	errs := make(chan error, count)
	for i := 0; i < count; i++ {
		openWG.Add(1)
		go func(i int) {
			defer openWG.Done()
			mailbox, err := provider.OpenMailbox(ctx, MailboxOpenRequest{Namespace: "profile-a", OwnerDeviceID: fmt.Sprintf("device-open-%02d", i), CreatedAt: now, ExpiresAt: now.Add(time.Hour)})
			if err != nil {
				errs <- err
				return
			}
			ids <- mailbox.MailboxID
		}(i)
	}
	openWG.Wait()
	close(ids)
	close(errs)
	for err := range errs {
		if err != nil {
			t.Fatalf("OpenMailbox returned error: %v", err)
		}
	}
	seen := map[string]bool{}
	for id := range ids {
		if seen[id] {
			t.Fatalf("auto mailbox ID was reused: %s", id)
		}
		seen[id] = true
	}
	if len(seen) != count {
		t.Fatalf("opened mailbox count = %d, want %d", len(seen), count)
	}

	target, err := provider.OpenMailbox(ctx, MailboxOpenRequest{Namespace: "profile-a", OwnerDeviceID: "device-target", MailboxID: "mbox-target", CreatedAt: now, ExpiresAt: now.Add(time.Hour)})
	if err != nil {
		t.Fatalf("OpenMailbox target returned error: %v", err)
	}
	var sendWG sync.WaitGroup
	sendErrs := make(chan error, count)
	for i := 0; i < count; i++ {
		sendWG.Add(1)
		go func(i int) {
			defer sendWG.Done()
			payload := []byte(fmt.Sprintf("payload-%02d", i))
			envelope := validEnvelope(now, payload)
			envelope.MessageID = fmt.Sprintf("msg-concurrent-%02d", i)
			envelope.SourceDeviceID = fmt.Sprintf("device-source-%02d", i)
			envelope.TargetDeviceID = "device-target"
			envelope.TargetMailboxID = ""
			envelope.PayloadHash = PayloadSHA256(payload)
			if _, err := provider.SendEnvelope(ctx, envelope); err != nil {
				sendErrs <- err
			}
			_ = provider.GetStatus(ctx)
		}(i)
	}
	sendWG.Wait()
	close(sendErrs)
	for err := range sendErrs {
		if err != nil {
			t.Fatalf("SendEnvelope returned error: %v", err)
		}
	}
	received, err := provider.ReceiveEnvelopes(ctx, target)
	if err != nil {
		t.Fatalf("ReceiveEnvelopes returned error: %v", err)
	}
	if len(received) != count {
		t.Fatalf("received envelope count = %d, want %d", len(received), count)
	}
	assertRelaySafeJSON(t, provider.GetStatus(ctx))
}

func TestLocalDevProviderDuplicateMessageIDIsTargetScoped(t *testing.T) {
	ctx := context.Background()
	now := time.Now().UTC()
	provider, err := NewLocalDevProvider(LocalDevProviderConfig{ProviderID: "local-dev-1", Clock: &mutableRelayClock{now: now}})
	if err != nil {
		t.Fatalf("NewLocalDevProvider returned error: %v", err)
	}
	mailboxA, err := provider.OpenMailbox(ctx, MailboxOpenRequest{Namespace: "profile-a", OwnerDeviceID: "device-a", MailboxID: "mbox-a", CreatedAt: now, ExpiresAt: now.Add(time.Hour)})
	if err != nil {
		t.Fatalf("OpenMailbox A returned error: %v", err)
	}
	mailboxB, err := provider.OpenMailbox(ctx, MailboxOpenRequest{Namespace: "profile-a", OwnerDeviceID: "device-b", MailboxID: "mbox-b", CreatedAt: now, ExpiresAt: now.Add(time.Hour)})
	if err != nil {
		t.Fatalf("OpenMailbox B returned error: %v", err)
	}

	envelopeA := validEnvelope(now, []byte("same-metadata-for-a"))
	envelopeA.MessageID = "snapshot-shared"
	envelopeA.TargetDeviceID = ""
	envelopeA.TargetMailboxID = mailboxA.MailboxID
	envelopeA.PayloadHash = PayloadSHA256(envelopeA.Payload)
	if _, err := provider.SendEnvelope(ctx, envelopeA); err != nil {
		t.Fatalf("SendEnvelope A returned error: %v", err)
	}
	if _, err := provider.SendEnvelope(ctx, envelopeA); !errors.Is(err, ErrDuplicateEnvelope) {
		t.Fatalf("duplicate send to same target error = %v", err)
	}

	envelopeB := validEnvelope(now, []byte("same-metadata-for-b"))
	envelopeB.MessageID = envelopeA.MessageID
	envelopeB.TargetDeviceID = ""
	envelopeB.TargetMailboxID = mailboxB.MailboxID
	envelopeB.PayloadHash = PayloadSHA256(envelopeB.Payload)
	if _, err := provider.SendEnvelope(ctx, envelopeB); err != nil {
		t.Fatalf("same message ID to different target should be accepted, got: %v", err)
	}

	receivedA, err := provider.ReceiveEnvelopes(ctx, mailboxA)
	if err != nil || len(receivedA) != 1 || string(receivedA[0].Payload) != "same-metadata-for-a" {
		t.Fatalf("Receive A = %+v, %v", receivedA, err)
	}
	receivedB, err := provider.ReceiveEnvelopes(ctx, mailboxB)
	if err != nil || len(receivedB) != 1 || string(receivedB[0].Payload) != "same-metadata-for-b" {
		t.Fatalf("Receive B = %+v, %v", receivedB, err)
	}
}

func TestLocalDevProviderExpiresDuplicateTracking(t *testing.T) {
	ctx := context.Background()
	now := time.Now().UTC()
	clock := &mutableRelayClock{now: now}
	provider, err := NewLocalDevProvider(LocalDevProviderConfig{ProviderID: "local-dev-1", Clock: clock})
	if err != nil {
		t.Fatal(err)
	}
	mailbox, err := provider.OpenMailbox(ctx, MailboxOpenRequest{
		Namespace:     "profile-a",
		OwnerDeviceID: "device-2",
		MailboxID:     "mbox-2",
		CreatedAt:     now,
		ExpiresAt:     now.Add(time.Hour),
	})
	if err != nil {
		t.Fatal(err)
	}
	envelope := validEnvelope(now, []byte("bounded-duplicate-state"))
	envelope.TargetDeviceID = ""
	envelope.TargetMailboxID = mailbox.MailboxID
	envelope.ExpiresAt = now.Add(time.Minute)
	envelope.PayloadHash = PayloadSHA256(envelope.Payload)
	if _, err := provider.SendEnvelope(ctx, envelope); err != nil {
		t.Fatal(err)
	}
	if len(provider.seen) != 1 {
		t.Fatalf("seen delivery count = %d, want 1", len(provider.seen))
	}
	clock.now = now.Add(2 * time.Hour)
	if err := provider.CleanupExpired(ctx); err != nil {
		t.Fatal(err)
	}
	if len(provider.seen) != 0 {
		t.Fatalf("expired duplicate tracking retained %d entries", len(provider.seen))
	}
}

func TestLocalDevProviderNilContextDoesNotPanic(t *testing.T) {
	provider, err := NewLocalDevProvider(LocalDevProviderConfig{ProviderID: "local-dev-1"})
	if err != nil {
		t.Fatal(err)
	}
	status := provider.GetStatus(nil)
	if !status.Available {
		t.Fatalf("nil-context status unexpectedly unavailable: %+v", status)
	}
}

type mutableRelayClock struct {
	now time.Time
}

func (c *mutableRelayClock) Now() time.Time {
	return c.now
}

func assertRelaySafeJSON(t *testing.T, v any) {
	t.Helper()
	raw, err := json.Marshal(v)
	if err != nil {
		t.Fatalf("json marshal failed: %v", err)
	}
	text := strings.ToLower(string(raw))
	for _, forbidden := range []string{"client_secret", "refresh_token", "access_token", "id_token", "auth_code", "verifier", "private_key", "begin private key", "github_pat", "ghp_", "token=", "password=", "secret=", `c:\\users\\`, "appdata", "downloads"} {
		if strings.Contains(text, forbidden) {
			t.Fatalf("unsafe relay JSON detail %q in %s", forbidden, string(raw))
		}
	}
}

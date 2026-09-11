package relay

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http/httptest"
	"testing"
	"time"
)

func TestHTTPReceivePagesPreserveAllQueuedMessages(t *testing.T) {
	for _, tc := range []struct {
		name        string
		count, size int
	}{{"two near limit", 2, DefaultMaxPayloadSize}, {"encoded byte pages", 30, DefaultMaxPayloadSize}, {"count pages", 200, 8}} {
		t.Run(tc.name, func(t *testing.T) {
			ctx := context.Background()
			now := time.Now().UTC()
			p, _ := NewLocalDevProvider(LocalDevProviderConfig{})
			handler, err := NewHTTPRelayHandler(HTTPRelayHandlerConfig{Provider: p, AllowUnauthenticated: true})
			if err != nil {
				t.Fatal(err)
			}
			server := httptest.NewServer(handler)
			defer server.Close()
			client, err := NewHTTPRelayClient(HTTPRelayClientConfig{BaseURL: server.URL})
			if err != nil {
				t.Fatal(err)
			}
			box, err := client.OpenMailbox(ctx, MailboxOpenRequest{Namespace: "profile-a", MailboxID: "page", OwnerDeviceID: "device-2", CreatedAt: now, ExpiresAt: now.Add(time.Hour)})
			if err != nil {
				t.Fatal(err)
			}
			for i := 0; i < tc.count; i++ {
				e := validEnvelope(now, bytes.Repeat([]byte("x"), tc.size))
				e.TargetDeviceID = ""
				e.TargetMailboxID = box.MailboxID
				e.MessageID = fmt.Sprintf("m%d", i)
				if _, err := client.SendEnvelope(ctx, e); err != nil {
					t.Fatal(err)
				}
			}
			seen := map[string]bool{}
			for page := 0; page <= tc.count; page++ {
				got, err := client.ReceiveEnvelopes(ctx, box)
				if err != nil {
					t.Fatal(err)
				}
				raw, err := json.Marshal(got)
				if err != nil {
					t.Fatal(err)
				}
				if len(got) > maxReceivePageCount || len(raw)+1 > maxReceivePageBytes {
					t.Fatal("unbounded page")
				}
				if len(got) == 0 {
					break
				}
				for _, e := range got {
					if seen[e.MessageID] || len(e.Payload) != tc.size {
						t.Fatal("duplicate or altered message")
					}
					seen[e.MessageID] = true
				}
			}
			if len(seen) != tc.count {
				t.Fatalf("lost accepted messages: %d/%d", len(seen), tc.count)
			}
		})
	}
}
func TestLocalSendRejectsEnvelopeThatCannotFitPage(t *testing.T) {
	p, _ := NewLocalDevProvider(LocalDevProviderConfig{MaxPayloadBytes: 2 * maxReceivePageBytes})
	now := time.Now().UTC()
	ctx := context.Background()
	box, err := p.OpenMailbox(ctx, MailboxOpenRequest{Namespace: "profile-a", MailboxID: "box", OwnerDeviceID: "device-2", CreatedAt: now, ExpiresAt: now.Add(time.Hour)})
	if err != nil {
		t.Fatal(err)
	}
	e := validEnvelope(now, bytes.Repeat([]byte("x"), maxReceivePageBytes))
	e.TargetDeviceID = ""
	e.TargetMailboxID = box.MailboxID
	if _, err := p.SendEnvelope(ctx, e); !errors.Is(err, ErrPayloadTooLarge) {
		t.Fatalf("accepted unpageable envelope: %v", err)
	}
	if got, err := p.ReceiveEnvelopes(ctx, box); err != nil || len(got) != 0 {
		t.Fatalf("rejection queued data: %v %v", got, err)
	}
}
func TestQueryAsOfNeverAdvancesProviderCleanup(t *testing.T) {
	for _, queryKind := range []string{"hints", "rendezvous"} {
		t.Run(queryKind, func(t *testing.T) {
			ctx := context.Background()
			now := time.Now().UTC()
			clock := &mutableRelayClock{now: now}
			p, _ := NewLocalDevProvider(LocalDevProviderConfig{Clock: clock})
			hint := validEndpointHint(now)
			if err := p.PublishEndpointHint(ctx, hint); err != nil {
				t.Fatal(err)
			}
			ann := RendezvousAnnouncement{ProtocolVersion: ProtocolVersion, Namespace: "profile-a", DeviceID: "device-1", AnnouncementID: "ann", CreatedAt: now, ExpiresAt: now.Add(time.Hour)}
			if err := p.Announce(ctx, ann); err != nil {
				t.Fatal(err)
			}
			box, err := p.OpenMailbox(ctx, MailboxOpenRequest{Namespace: "profile-a", MailboxID: "box", OwnerDeviceID: "device-2", CreatedAt: now, ExpiresAt: now.Add(time.Hour)})
			if err != nil {
				t.Fatal(err)
			}
			e := validEnvelope(now, []byte("retained"))
			e.TargetDeviceID = ""
			e.TargetMailboxID = box.MailboxID
			if _, err := p.SendEnvelope(ctx, e); err != nil {
				t.Fatal(err)
			}
			for _, ns := range []string{"unrelated", "profile-a"} {
				if queryKind == "hints" {
					got, err := p.ListEndpointHints(ctx, EndpointHintQuery{Namespace: ns, Now: now.Add(24 * time.Hour)})
					if err != nil || len(got) != 0 {
						t.Fatalf("as-of filter: %v %v", got, err)
					}
				} else {
					got, err := p.Query(ctx, RendezvousQuery{Namespace: ns, Now: now.Add(24 * time.Hour)})
					if err != nil || len(got) != 0 {
						t.Fatalf("as-of filter: %v %v", got, err)
					}
				}
			}
			if _, err := p.SendEnvelope(ctx, e); !errors.Is(err, ErrDuplicateEnvelope) {
				t.Fatalf("query erased replay state: %v", err)
			}
			if got, err := p.ReceiveEnvelopes(ctx, box); err != nil || len(got) != 1 {
				t.Fatalf("query erased mailbox: %v %v", got, err)
			}
			if got, err := p.ListEndpointHints(ctx, EndpointHintQuery{Namespace: "profile-a"}); err != nil || len(got) != 1 {
				t.Fatalf("query erased hint: %v %v", got, err)
			}
			if got, err := p.Query(ctx, RendezvousQuery{Namespace: "profile-a"}); err != nil || len(got) != 1 {
				t.Fatalf("query erased announcement: %v %v", got, err)
			}
			clock.now = now.Add(48 * time.Hour)
			if got, err := p.ListEndpointHints(ctx, EndpointHintQuery{Namespace: "profile-a", Now: now}); err != nil || len(got) != 0 {
				t.Fatalf("past query revived expired state: %v %v", got, err)
			}
		})
	}
}

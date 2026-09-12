package relay

import (
	"context"
	"fmt"
	"testing"
	"time"
)

func TestLocalDevClockCanReadStatus(t *testing.T) {
	for _, operation := range []string{"publish_hint", "list_hints", "announce", "query", "cleanup"} {
		t.Run(operation, func(t *testing.T) {
			ctx := context.Background()
			now := time.Now().UTC()
			p, err := NewLocalDevProvider(LocalDevProviderConfig{})
			if err != nil {
				t.Fatal(err)
			}
			calls := 0
			var callbackErr error
			p.clock = reliableClockFunc(func() time.Time {
				calls++
				if status := p.GetStatus(ctx); !status.Available {
					callbackErr = fmt.Errorf("callback status unavailable: %+v", status)
				}
				return now
			})
			done := make(chan error, 1)
			go func() {
				var err error
				switch operation {
				case "publish_hint":
					err = p.PublishEndpointHint(ctx, validEndpointHint(now))
				case "list_hints":
					_, err = p.ListEndpointHints(ctx, EndpointHintQuery{Namespace: "profile-a"})
				case "announce":
					err = p.Announce(ctx, RendezvousAnnouncement{ProtocolVersion: 1, Namespace: "profile-a", DeviceID: "device", AnnouncementID: "announcement", CreatedAt: now, ExpiresAt: now.Add(time.Hour)})
				case "query":
					_, err = p.Query(ctx, RendezvousQuery{Namespace: "profile-a"})
				case "cleanup":
					err = p.CleanupExpired(ctx)
				}
				done <- err
			}()
			select {
			case err := <-done:
				if err != nil || callbackErr != nil || calls == 0 {
					t.Fatal("clock reentry failed", err, callbackErr, calls)
				}
			case <-time.After(5 * time.Second):
				t.Fatal("clock callback deadlocked reading provider status")
			}
		})
	}
}

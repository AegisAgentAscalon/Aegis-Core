package devicelink

import (
	"context"
	"errors"
	"fmt"
	"testing"
	"time"
)

type callbackClock struct {
	Clock
	visit func()
}

func (c *callbackClock) Now() time.Time {
	if c.visit != nil {
		c.visit()
	}
	return c.Clock.Now()
}

func TestDeviceLinkClockCanReenterDomainMethodsAndCopiedService(t *testing.T) {
	for _, copied := range []bool{false, true} {
		t.Run(fmt.Sprintf("copied=%t", copied), func(t *testing.T) {
			ctx := context.Background()
			base := &testClock{now: time.Date(2026, 9, 12, 0, 0, 0, 0, time.UTC)}
			clock := &callbackClock{Clock: base}
			discovery, transport := NewMemoryDiscoveryProvider(), NewMemoryTransport()
			original := newTestService(t, "clock", WithClock(clock), WithDiscoveryProvider(discovery), WithTransport(transport))
			target := original
			if copied {
				copy := *original
				target = &copy
			}
			clock.visit = func() {
				_, err := original.GetCurrentDevice(ctx)
				if err != nil && !errors.Is(err, ErrCurrentDeviceNotFound) {
					t.Errorf("clock reentry: %v", err)
				}
			}
			peer := newTestService(t, "clock", WithClock(base), WithDiscoveryProvider(discovery))
			peerID, err := peer.BootstrapCurrentDevice(ctx, BootstrapDeviceRequest{})
			if err != nil {
				t.Fatal(err)
			}
			transport.RegisterHandler(peerID.DeviceID, func(context.Context, Message) (Message, error) {
				return Message{Kind: "pong", FromDeviceID: peerID.DeviceID}, nil
			})
			// Exercise every domain that samples the clock, including reentry
			// through the original owner when the receiver has been copied.
			mustFinishDeviceLinkCall(t, func() error {
				id, err := target.BootstrapCurrentDevice(ctx, BootstrapDeviceRequest{})
				if err != nil {
					return err
				}
				request := TrustDeviceRequest{DeviceID: peerID.DeviceID, PublicKey: peerID.PublicKey, PublicKeyFingerprint: peerID.PublicKeyFingerprint}
				if _, err := target.TrustDevice(ctx, request); err != nil {
					return err
				}
				if _, err := peer.TrustDevice(ctx, TrustDeviceRequest{DeviceID: id.DeviceID, PublicKey: id.PublicKey, PublicKeyFingerprint: id.PublicKeyFingerprint}); err != nil {
					return err
				}
				if err := target.AdvertiseResources(ctx, ResourceAdvertisementRequest{Resources: []ResourceDescriptor{{ResourceID: "resource", Type: ResourceData}}}); err != nil {
					return err
				}
				if _, err := target.PublishPresence(ctx); err != nil {
					return err
				}
				if _, err := peer.PublishPresence(ctx); err != nil {
					return err
				}
				if _, err := target.DiscoverPeers(ctx); err != nil {
					return err
				}
				if _, err := target.ListKnownRemoteResources(ctx); err != nil {
					return err
				}
				start, err := target.StartHandshake(ctx, DiscoveredPeer{Presence: PresenceRecord{DeviceID: peerID.DeviceID, PublicKeyFingerprint: peerID.PublicKeyFingerprint}})
				if err != nil {
					return err
				}
				signed, err := peer.SignHandshakeChallenge(ctx, HandshakeChallengeRequest{ChallengerDeviceID: id.DeviceID, Challenge: start.Challenge})
				if err != nil {
					return err
				}
				if _, err := target.CompleteHandshake(ctx, HandshakeCompleteRequest{SessionID: start.SessionID, PeerDeviceID: peerID.DeviceID, Signature: signed.Signature}); err != nil {
					return err
				}
				if _, err := target.TestLink(ctx, peerID.DeviceID); err != nil {
					return err
				}
				if _, err := target.EvaluateProof(ctx, peerID.DeviceID); err != nil {
					return err
				}
				if _, err := target.GetConnectionStatus(ctx, peerID.DeviceID); err != nil {
					return err
				}
				snapshot, err := target.ExportRegistrySnapshot(ctx)
				if err != nil {
					return err
				}
				if err := target.ImportRegistrySnapshot(ctx, snapshot); err != nil {
					return err
				}
				if err := target.RevokeDevice(ctx, peerID.DeviceID); err != nil {
					return err
				}
				_, err = target.TrustDevice(ctx, request)
				return err
			})
		})
	}
}

func TestDeviceLinkTransportRechecksTimeTrustAndCancellation(t *testing.T) {
	for _, change := range []string{"time", "revoked", "fingerprint", "canceled"} {
		t.Run(change, func(t *testing.T) {
			start := time.Date(2026, 9, 12, 0, 0, 0, 0, time.UTC)
			clock := &testClock{now: start}
			discovery, transport := NewMemoryDiscoveryProvider(), NewMemoryTransport()
			svc := newTestService(t, "transport-check", WithClock(clock), WithDiscoveryProvider(discovery), WithTransport(transport))
			if _, err := svc.BootstrapCurrentDevice(context.Background(), BootstrapDeviceRequest{}); err != nil {
				t.Fatal(err)
			}
			peer := makeTrustRequest(t, "peer")
			if _, err := svc.TrustDevice(context.Background(), peer); err != nil {
				t.Fatal(err)
			}
			if err := discovery.Publish(context.Background(), PresenceRecord{SchemaVersion: schemaVersion, DeviceID: peer.DeviceID, PublicKeyFingerprint: peer.PublicKeyFingerprint, LastSeen: start}); err != nil {
				t.Fatal(err)
			}
			if _, err := svc.DiscoverPeers(context.Background()); err != nil {
				t.Fatal(err)
			}
			replacement, err := svc.ExportRegistrySnapshot(context.Background())
			if err != nil {
				t.Fatal(err)
			}
			newKey := makeTrustRequest(t, peer.DeviceID)
			replacement.Devices[0].PublicKey = newKey.PublicKey
			replacement.Devices[0].PublicKeyFingerprint = newKey.PublicKeyFingerprint
			replacement.SnapshotFingerprint = snapshotFingerprint(replacement)
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			transport.RegisterHandler(peer.DeviceID, func(context.Context, Message) (Message, error) {
				clock.Add(2 * time.Second)
				var err error
				switch change {
				case "revoked":
					err = svc.RevokeDevice(context.Background(), peer.DeviceID)
				case "fingerprint":
					err = svc.ImportRegistrySnapshot(context.Background(), replacement)
				case "canceled":
					cancel()
				}
				return Message{Kind: "pong", FromDeviceID: peer.DeviceID}, err
			})
			result, err := svc.TestLink(ctx, peer.DeviceID)
			want := map[string]error{"revoked": ErrDeviceRevoked, "fingerprint": ErrFingerprintMismatch, "canceled": ErrContextCanceled}[change]
			if !errors.Is(err, want) {
				t.Fatalf("transport result = %+v, %v; want %v", result, err, want)
			}
			links, err := svc.store.readLinks()
			if err != nil {
				t.Fatal(err)
			}
			if change == "time" {
				if !result.OK || result.LatencyMillis != 2000 || len(links.Links) != 1 || !links.Links[0].LastSeen.Equal(start.Add(2*time.Second)) {
					t.Fatalf("transport did not use completion time: %+v, %+v", result, links)
				}
				proof, err := svc.EvaluateProof(context.Background(), peer.DeviceID)
				if err != nil || proof.Satisfied || proof.State != ProofStateUnverified {
					t.Fatalf("reachability became proof: %+v, %v", proof, err)
				}
			} else if len(links.Links) != 0 {
				t.Fatalf("invalidated transport persisted reachability: %+v", links)
			}
		})
	}
}

func TestDeviceLinkClockCancellationPreventsBootstrapWrites(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	clock := &callbackClock{Clock: realClock{}, visit: cancel}
	svc := newTestService(t, "clock-cancel", WithClock(clock))
	if _, err := svc.BootstrapCurrentDevice(ctx, BootstrapDeviceRequest{}); !errors.Is(err, ErrContextCanceled) {
		t.Fatalf("clock cancellation = %v", err)
	}
	status, err := InspectBootstrap(svc.cfg)
	if err != nil || status.IdentityPresent || status.PrivateKeyPresent || status.Ready {
		t.Fatalf("canceled clock allowed bootstrap writes: %+v, %v", status, err)
	}
}

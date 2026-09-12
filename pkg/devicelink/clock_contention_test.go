package devicelink

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"testing"
	"time"
)

type contentionClock struct {
	*testClock
	observed chan struct{}
	once     sync.Once
}

func (clock *contentionClock) Now() time.Time {
	now := clock.testClock.Now()
	if clock.observed != nil {
		clock.once.Do(func() { close(clock.observed) })
	}
	return now
}

func TestDeviceLinkExpiryAndCancellationWhileWaitingForOwner(t *testing.T) {
	for _, operation := range []string{"complete", "evaluate", "status", "canceled-complete"} {
		t.Run(operation, func(t *testing.T) {
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			clock := &contentionClock{testClock: &testClock{now: time.Date(2026, 9, 12, 0, 0, 0, 0, time.UTC)}}
			svc := newTestService(t, "contention", WithClock(clock))
			peer := newTestService(t, "contention", WithClock(clock.testClock))
			localID, err := svc.BootstrapCurrentDevice(ctx, BootstrapDeviceRequest{})
			if err != nil {
				t.Fatal(err)
			}
			peerID, err := peer.BootstrapCurrentDevice(ctx, BootstrapDeviceRequest{})
			if err != nil {
				t.Fatal(err)
			}
			trustBoth(t, svc, localID, peer, peerID)
			start, err := svc.StartHandshake(ctx, DiscoveredPeer{Presence: PresenceRecord{DeviceID: peerID.DeviceID, PublicKeyFingerprint: peerID.PublicKeyFingerprint}})
			if err != nil {
				t.Fatal(err)
			}
			response, err := peer.SignHandshakeChallenge(ctx, HandshakeChallengeRequest{ChallengerDeviceID: localID.DeviceID, Challenge: start.Challenge})
			if err != nil {
				t.Fatal(err)
			}
			request := HandshakeCompleteRequest{SessionID: start.SessionID, PeerDeviceID: peerID.DeviceID, Signature: response.Signature}
			if operation == "evaluate" || operation == "status" {
				if _, err := svc.CompleteHandshake(ctx, request); err != nil {
					t.Fatal(err)
				}
			}

			svc.mu.Lock()
			var unlock sync.Once
			release := func() { unlock.Do(svc.mu.Unlock) }
			defer release()
			clock.observed = make(chan struct{})
			finished := make(chan error, 1)
			go func() {
				switch operation {
				case "complete", "canceled-complete":
					_, err := svc.CompleteHandshake(ctx, request)
					want := ErrChallengeExpired
					if operation == "canceled-complete" {
						want = ErrContextCanceled
					}
					if !errors.Is(err, want) {
						finished <- fmt.Errorf("completion after contention: %v; want %v", err, want)
						return
					}
				case "evaluate":
					proof, err := svc.EvaluateProof(ctx, peerID.DeviceID)
					if err != nil || proof.State != ProofStateExpired || proof.Satisfied {
						finished <- fmt.Errorf("proof after contention: %+v, %v", proof, err)
						return
					}
				case "status":
					status, err := svc.GetConnectionStatus(ctx, peerID.DeviceID)
					if err != nil || status.ProofState != ProofStateExpired {
						finished <- fmt.Errorf("status after contention: %+v, %v", status, err)
						return
					}
				}
				finished <- nil
			}()
			select {
			case <-clock.observed:
			case <-time.After(3 * time.Second):
				t.Fatal("operation did not sample its clock outside the busy owner")
			}
			// Expire only after the operation has sampled time and while the
			// owner remains busy. It must resample after obtaining ownership.
			clock.Add(defaultLinkTTL + time.Second)
			if operation == "canceled-complete" {
				cancel()
			}
			release()
			select {
			case err := <-finished:
				if err != nil {
					t.Fatal(err)
				}
			case <-time.After(3 * time.Second):
				t.Fatal("operation did not finish after owner release")
			}
			if operation == "complete" || operation == "canceled-complete" {
				session, err := svc.store.readHandshake(start.SessionID)
				if err != nil || session.Consumed {
					t.Fatalf("rejected completion consumed the handshake: %+v, %v", session, err)
				}
			}
		})
	}
}

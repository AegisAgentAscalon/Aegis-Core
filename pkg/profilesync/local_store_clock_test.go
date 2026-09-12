package profilesync

import (
	"context"
	"fmt"
	"os"
	"testing"
	"time"
)

func TestLocalMetadataClockCanReadStore(t *testing.T) {
	for _, operation := range []string{"initialize", "save_local_snapshot", "load_local_snapshot", "save_remote_snapshot", "load_remote_snapshot", "list_remote_snapshots", "save_local_proposal", "load_local_proposals", "save_remote_proposal", "load_remote_proposal", "list_remote_proposals", "save_exchange", "load_exchange"} {
		t.Run(operation, func(t *testing.T) {
			ctx := context.Background()
			now := time.Now().UTC()
			s, err := NewLocalMetadataStore(LocalMetadataStoreConfig{RootDir: t.TempDir(), ProfileNamespace: "profile-a", Clock: inboxClock{at: now}})
			if err != nil {
				t.Fatal(err)
			}
			snapshot := validSyncSnapshot("snapshot", "", now)
			proposal := validSyncProposal("proposal", "snapshot", now)
			remoteSnapshot := RemoteSnapshotRecord{Snapshot: snapshot, ReceivedAt: now, TrustState: TrustTrusted}
			remoteProposal := RemoteProposalRecord{Proposal: proposal, ReceivedAt: now, TrustState: TrustTrusted}
			exchange := ExchangeResult{Session: SyncSession{SessionID: "exchange", ProfileNamespace: "profile-a", LocalDeviceID: "device-local", StartedAt: now, CompletedAt: now}}
			for _, err := range []error{s.SaveLocalSnapshot(ctx, snapshot), s.SaveRemoteSnapshot(ctx, remoteSnapshot), s.SaveLocalProposal(ctx, proposal), s.SaveRemoteProposal(ctx, remoteProposal), s.SaveLastExchange(ctx, exchange)} {
				if err != nil {
					t.Fatal(err)
				}
			}
			if operation == "initialize" {
				if err := os.Remove(s.metadataPath()); err != nil {
					t.Fatal(err)
				}
			}
			active, calls := false, 0
			var callbackErr error
			s.clock = w15Clock(func() time.Time {
				if !active {
					active = true
					calls++
					if record, err := s.LoadLastExchange(ctx); err != nil || record.Session.SessionID != "exchange" {
						callbackErr = fmt.Errorf("callback read failed: %v", err)
					}
					active = false
				}
				return now
			})
			done := make(chan error, 1)
			go func() {
				var err error
				switch operation {
				case "initialize":
					err = s.ensureInitialized(ctx)
				case "save_local_snapshot":
					err = s.SaveLocalSnapshot(ctx, snapshot)
				case "load_local_snapshot":
					_, err = s.LoadLocalSnapshot(ctx)
				case "save_remote_snapshot":
					err = s.SaveRemoteSnapshot(ctx, remoteSnapshot)
				case "load_remote_snapshot":
					_, err = s.LoadRemoteSnapshot(ctx, "snapshot")
				case "list_remote_snapshots":
					_, err = s.ListRemoteSnapshots(ctx)
				case "save_local_proposal":
					err = s.SaveLocalProposal(ctx, proposal)
				case "load_local_proposals":
					_, err = s.LoadLocalProposals(ctx)
				case "save_remote_proposal":
					err = s.SaveRemoteProposal(ctx, remoteProposal)
				case "load_remote_proposal":
					_, err = s.LoadRemoteProposal(ctx, "proposal")
				case "list_remote_proposals":
					_, err = s.ListRemoteProposals(ctx)
				case "save_exchange":
					err = s.SaveLastExchange(ctx, exchange)
				case "load_exchange":
					_, err = s.LoadLastExchange(ctx)
				}
				done <- err
			}()
			select {
			case err := <-done:
				if err != nil || callbackErr != nil || calls == 0 {
					t.Fatal("clock reentry failed", err, callbackErr, calls)
				}
			case <-time.After(5 * time.Second):
				t.Fatal("clock callback deadlocked reading store")
			}
		})
	}
}

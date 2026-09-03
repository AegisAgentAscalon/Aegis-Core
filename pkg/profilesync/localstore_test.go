package profilesync

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/AegisAgentAscalon/aegis-core/pkg/relay"
)

func TestLocalMetadataStorePersistsMetadataAcrossInstances(t *testing.T) {
	ctx := context.Background()
	now := time.Now().UTC()
	clock := &syncClock{now: now}
	root := t.TempDir()
	store, err := NewLocalMetadataStore(LocalMetadataStoreConfig{RootDir: root, ProfileNamespace: "profile-a", Clock: clock})
	if err != nil {
		t.Fatalf("NewLocalMetadataStore returned error: %v", err)
	}

	localSnapshot := validSyncSnapshot("snapshot-local", "", now)
	if err := store.SaveLocalSnapshot(ctx, localSnapshot); err != nil {
		t.Fatalf("SaveLocalSnapshot returned error: %v", err)
	}
	localProposal := validSyncProposal("proposal-local", localSnapshot.Metadata.SnapshotID, now)
	if err := store.SaveLocalProposal(ctx, localProposal); err != nil {
		t.Fatalf("SaveLocalProposal returned error: %v", err)
	}
	remoteSnapshot := validSyncSnapshot("snapshot-remote", localSnapshot.Metadata.SnapshotID, now)
	if err := store.SaveRemoteSnapshot(ctx, RemoteSnapshotRecord{Snapshot: remoteSnapshot, ReceivedAt: now, TrustState: TrustTrusted}); err != nil {
		t.Fatalf("SaveRemoteSnapshot returned error: %v", err)
	}
	remoteProposal := validSyncProposal("proposal-remote", localSnapshot.Metadata.SnapshotID, now)
	if err := store.SaveRemoteProposal(ctx, RemoteProposalRecord{Proposal: remoteProposal, ReceivedAt: now, TrustState: TrustTrusted}); err != nil {
		t.Fatalf("SaveRemoteProposal returned error: %v", err)
	}
	if err := store.SaveLastExchange(ctx, ExchangeResult{
		Session:        SyncSession{SessionID: "sync-20260507120000", ProfileNamespace: "profile-a", LocalDeviceID: "device-local", StartedAt: now, CompletedAt: now.Add(time.Second), ReviewRequired: true},
		Push:           PushResult{PushedSnapshots: 1, PushedProposals: 1},
		Pull:           PullResult{ReceivedSnapshots: 1, ReceivedProposals: 1, ReviewRequired: true},
		Status:         SyncStatus{Summary: "profile sync metadata orchestration is available"},
		ReviewRequired: true,
	}); err != nil {
		t.Fatalf("SaveLastExchange returned error: %v", err)
	}

	reopened, err := NewLocalMetadataStore(LocalMetadataStoreConfig{RootDir: root, ProfileNamespace: "profile-a", Clock: clock})
	if err != nil {
		t.Fatalf("reopen NewLocalMetadataStore returned error: %v", err)
	}
	loadedLocal, err := reopened.LoadLocalSnapshot(ctx)
	if err != nil || loadedLocal.Metadata.SnapshotID != localSnapshot.Metadata.SnapshotID {
		t.Fatalf("LoadLocalSnapshot = %+v, %v", loadedLocal, err)
	}
	localProposals, err := reopened.LoadLocalProposals(ctx)
	if err != nil || len(localProposals) != 1 || localProposals[0].ProposalID != localProposal.ProposalID {
		t.Fatalf("LoadLocalProposals = %+v, %v", localProposals, err)
	}
	loadedRemote, err := reopened.LoadRemoteSnapshot(ctx, remoteSnapshot.Metadata.SnapshotID)
	if err != nil || loadedRemote.Snapshot.Metadata.SnapshotID != remoteSnapshot.Metadata.SnapshotID {
		t.Fatalf("LoadRemoteSnapshot = %+v, %v", loadedRemote, err)
	}
	remoteSnapshots, err := reopened.ListRemoteSnapshots(ctx)
	if err != nil || len(remoteSnapshots) != 1 {
		t.Fatalf("ListRemoteSnapshots = %+v, %v", remoteSnapshots, err)
	}
	loadedProposal, err := reopened.LoadRemoteProposal(ctx, remoteProposal.ProposalID)
	if err != nil || loadedProposal.Proposal.ProposalID != remoteProposal.ProposalID {
		t.Fatalf("LoadRemoteProposal = %+v, %v", loadedProposal, err)
	}
	remoteProposals, err := reopened.ListRemoteProposals(ctx)
	if err != nil || len(remoteProposals) != 1 {
		t.Fatalf("ListRemoteProposals = %+v, %v", remoteProposals, err)
	}
	exchange, err := reopened.LoadLastExchange(ctx)
	if err != nil || exchange.SchemaVersion != LocalExchangeRecordSchemaVersion || exchange.Session.SessionID != "sync-20260507120000" || !exchange.ReviewRequired {
		t.Fatalf("LoadLastExchange = %+v, %v", exchange, err)
	}
	status := reopened.BuildStatus(ctx)
	if !status.Available || !status.LocalSnapshotConfigured || status.LocalProposalCount != 1 || status.RemoteSnapshotCount != 1 || status.RemoteProposalCount != 1 {
		t.Fatalf("BuildStatus = %+v", status)
	}
	assertSyncSafeJSON(t, status)
	assertNoUnsafeStoreFiles(t, root)
}

func TestLocalMetadataStoreReadsLegacySchemaOneExchangeRecord(t *testing.T) {
	ctx := context.Background()
	now := time.Date(2026, 7, 16, 16, 0, 0, 0, time.UTC)
	store, err := NewLocalMetadataStore(LocalMetadataStoreConfig{RootDir: t.TempDir(), ProfileNamespace: "profile-a", Clock: &syncClock{now: now}})
	if err != nil {
		t.Fatalf("NewLocalMetadataStore returned error: %v", err)
	}
	legacy := LocalExchangeRecord{
		SchemaVersion:    legacyExchangeRecordSchemaVersion,
		ProfileNamespace: "profile-a",
		Session:          SyncSession{SessionID: "sync-legacy-1"},
		StatusSummary:    "legacy exchange completed",
		RecordedAt:       now,
	}
	if err := writeJSONAtomic(store.lastExchangePath(), legacy); err != nil {
		t.Fatalf("write legacy exchange: %v", err)
	}
	loaded, err := store.LoadLastExchange(ctx)
	if err != nil {
		t.Fatalf("LoadLastExchange rejected schema 1: %v", err)
	}
	if loaded.SchemaVersion != legacyExchangeRecordSchemaVersion || loaded.Session.SessionID != legacy.Session.SessionID || loaded.StatusSummary != legacy.StatusSummary {
		t.Fatalf("legacy exchange changed on read: %+v", loaded)
	}
}

func TestLocalMetadataStoreRejectsInvalidIDsAndRoots(t *testing.T) {
	ctx := context.Background()
	now := time.Now().UTC()
	if _, err := NewLocalMetadataStore(LocalMetadataStoreConfig{RootDir: "", ProfileNamespace: "profile-a"}); !errors.Is(err, ErrInvalidConfig) {
		t.Fatalf("empty root error = %v", err)
	}
	if _, err := NewLocalMetadataStore(LocalMetadataStoreConfig{RootDir: t.TempDir(), ProfileNamespace: "../profile"}); !errors.Is(err, ErrInvalidConfig) {
		t.Fatalf("invalid namespace error = %v", err)
	}
	rootFile := filepath.Join(t.TempDir(), "store-root-file")
	if err := os.WriteFile(rootFile, []byte("not a directory"), 0o600); err != nil {
		t.Fatalf("write root file: %v", err)
	}
	if _, err := NewLocalMetadataStore(LocalMetadataStoreConfig{RootDir: rootFile, ProfileNamespace: "profile-a"}); !errors.Is(err, ErrStoreUnavailable) {
		t.Fatalf("file root error = %v", err)
	}

	store, err := NewLocalMetadataStore(LocalMetadataStoreConfig{RootDir: t.TempDir(), ProfileNamespace: "profile-a", Clock: &syncClock{now: now}})
	if err != nil {
		t.Fatalf("NewLocalMetadataStore returned error: %v", err)
	}
	badSnapshot := validSyncSnapshot("snapshot/escape", "", now)
	if err := store.SaveRemoteSnapshot(ctx, RemoteSnapshotRecord{Snapshot: badSnapshot, ReceivedAt: now, TrustState: TrustTrusted}); !errors.Is(err, ErrSnapshotRejected) {
		t.Fatalf("bad snapshot ID error = %v", err)
	}
	if _, err := store.LoadRemoteSnapshot(ctx, "../escape"); !errors.Is(err, ErrSnapshotRejected) {
		t.Fatalf("bad remote snapshot load error = %v", err)
	}
	badProposal := validSyncProposal("proposal/escape", "snapshot-local", now)
	if err := store.SaveRemoteProposal(ctx, RemoteProposalRecord{Proposal: badProposal, ReceivedAt: now, TrustState: TrustTrusted}); !errors.Is(err, ErrProposalRejected) {
		t.Fatalf("bad proposal ID error = %v", err)
	}
	if _, err := store.LoadRemoteProposal(ctx, "../escape"); !errors.Is(err, ErrProposalRejected) {
		t.Fatalf("bad remote proposal load error = %v", err)
	}
}

func TestLocalMetadataStoreCorruptFilesAndTempFilesAreSafe(t *testing.T) {
	ctx := context.Background()
	now := time.Now().UTC()
	root := t.TempDir()
	store, err := NewLocalMetadataStore(LocalMetadataStoreConfig{RootDir: root, ProfileNamespace: "profile-a", Clock: &syncClock{now: now}})
	if err != nil {
		t.Fatalf("NewLocalMetadataStore returned error: %v", err)
	}
	remoteSnapshot := validSyncSnapshot("snapshot-remote", "", now)
	if err := store.SaveRemoteSnapshot(ctx, RemoteSnapshotRecord{Snapshot: remoteSnapshot, ReceivedAt: now, TrustState: TrustTrusted}); err != nil {
		t.Fatalf("SaveRemoteSnapshot returned error: %v", err)
	}
	tempPath := filepath.Join(root, "profile-a", "snapshots", "remote", ".tmp-leftover.json")
	if err := os.WriteFile(tempPath, []byte("{"), 0o600); err != nil {
		t.Fatalf("write temp leftover: %v", err)
	}
	snapshots, err := store.ListRemoteSnapshots(ctx)
	if err != nil || len(snapshots) != 1 {
		t.Fatalf("temp file should be ignored, got %+v, %v", snapshots, err)
	}
	files, err := os.ReadDir(filepath.Join(root, "profile-a", "snapshots", "remote"))
	if err != nil {
		t.Fatalf("read remote snapshot dir: %v", err)
	}
	for _, file := range files {
		if strings.HasPrefix(file.Name(), ".tmp-") {
			continue
		}
		if err := os.WriteFile(filepath.Join(root, "profile-a", "snapshots", "remote", file.Name()), []byte("{"), 0o600); err != nil {
			t.Fatalf("corrupt snapshot file: %v", err)
		}
		break
	}
	if _, err := store.ListRemoteSnapshots(ctx); !errors.Is(err, ErrLocalStoreCorrupt) {
		t.Fatalf("corrupt snapshot list error = %v", err)
	}
	status := store.BuildStatus(ctx)
	if status.Available || len(status.Issues) == 0 {
		t.Fatalf("corrupt snapshot status = %+v", status)
	}
	assertSyncSafeJSON(t, status)

	metaRoot := t.TempDir()
	if err := os.MkdirAll(filepath.Join(metaRoot, "profile-a"), 0o700); err != nil {
		t.Fatalf("mkdir meta root: %v", err)
	}
	if err := os.WriteFile(filepath.Join(metaRoot, "profile-a", "store_meta.json"), []byte("{"), 0o600); err != nil {
		t.Fatalf("write corrupt meta: %v", err)
	}
	if _, err := NewLocalMetadataStore(LocalMetadataStoreConfig{RootDir: metaRoot, ProfileNamespace: "profile-a"}); !errors.Is(err, ErrLocalStoreCorrupt) {
		t.Fatalf("corrupt metadata reopen error = %v", err)
	}

	oversizedRoot := t.TempDir()
	oversizedStore, err := NewLocalMetadataStore(LocalMetadataStoreConfig{RootDir: oversizedRoot, ProfileNamespace: "profile-a"})
	if err != nil {
		t.Fatalf("NewLocalMetadataStore oversized fixture returned error: %v", err)
	}
	if err := os.WriteFile(oversizedStore.localSnapshotPath(), bytes.Repeat([]byte("x"), maxLocalJSONFileBytes+1), 0o600); err != nil {
		t.Fatalf("write oversized local snapshot: %v", err)
	}
	if _, err := oversizedStore.LoadLocalSnapshot(ctx); !errors.Is(err, ErrLocalStoreCorrupt) {
		t.Fatalf("oversized local snapshot error = %v", err)
	}
}

func TestSyncManagerWithLocalMetadataStorePersistsPulledMetadata(t *testing.T) {
	ctx := context.Background()
	now := time.Now().UTC()
	clock := &syncClock{now: now}
	provider, err := relay.NewLocalDevProvider(relay.LocalDevProviderConfig{ProviderID: "local-dev-relay", Clock: clock})
	if err != nil {
		t.Fatalf("NewLocalDevProvider returned error: %v", err)
	}
	mailbox, err := provider.OpenMailbox(ctx, relay.MailboxOpenRequest{Namespace: "profile-a", OwnerDeviceID: "device-local", MailboxID: "mailbox-local", CreatedAt: now, ExpiresAt: now.Add(time.Hour)})
	if err != nil {
		t.Fatalf("OpenMailbox returned error: %v", err)
	}
	transport, err := NewRelaySyncTransport(RelaySyncTransportConfig{Provider: provider, Namespace: "profile-a", SourceDeviceID: "device-local", TargetDeviceID: "device-remote", Mailbox: mailbox, Clock: clock})
	if err != nil {
		t.Fatalf("NewRelaySyncTransport returned error: %v", err)
	}
	root := t.TempDir()
	store, err := NewLocalMetadataStore(LocalMetadataStoreConfig{RootDir: root, ProfileNamespace: "profile-a", Clock: clock})
	if err != nil {
		t.Fatalf("NewLocalMetadataStore returned error: %v", err)
	}
	localSnapshot := validSyncSnapshot("snapshot-local", "", now)
	if err := store.SaveLocalSnapshot(ctx, localSnapshot); err != nil {
		t.Fatalf("SaveLocalSnapshot returned error: %v", err)
	}
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
	remote := validSyncSnapshot("snapshot-persisted", localSnapshot.Metadata.SnapshotID, now)
	sendSyncEnvelope(t, provider, mailbox.MailboxID, snapshotEnvelope("profile-a", "device-remote", remote, now), now, "msg-persisted")
	pull, err := manager.PullRemote(ctx)
	if err != nil || pull.ReceivedSnapshots != 1 {
		t.Fatalf("PullRemote = %+v, %v", pull, err)
	}
	reopened, err := NewLocalMetadataStore(LocalMetadataStoreConfig{RootDir: root, ProfileNamespace: "profile-a", Clock: clock})
	if err != nil {
		t.Fatalf("reopen NewLocalMetadataStore returned error: %v", err)
	}
	loaded, err := reopened.LoadRemoteSnapshot(ctx, remote.Metadata.SnapshotID)
	if err != nil || loaded.Snapshot.Metadata.SnapshotID != remote.Metadata.SnapshotID {
		t.Fatalf("persisted remote snapshot = %+v, %v", loaded, err)
	}

	sendSyncEnvelope(t, provider, mailbox.MailboxID, snapshotEnvelope("profile-a", "device-remote", remote, now), now, "msg-persisted-duplicate")
	pull, err = manager.PullRemote(ctx)
	if err != nil || pull.Rejected != 1 || !pull.ReviewRequired {
		t.Fatalf("duplicate persisted pull = %+v, %v", pull, err)
	}
	assertSyncSafeJSON(t, pull)

	blockedRoot := t.TempDir()
	blockedStore, err := NewLocalMetadataStore(LocalMetadataStoreConfig{RootDir: blockedRoot, ProfileNamespace: "profile-a", Clock: clock})
	if err != nil {
		t.Fatalf("blocked NewLocalMetadataStore returned error: %v", err)
	}
	if err := blockedStore.SaveLocalSnapshot(ctx, localSnapshot); err != nil {
		t.Fatalf("blocked SaveLocalSnapshot returned error: %v", err)
	}
	remoteDir := filepath.Join(blockedRoot, "profile-a", "snapshots", "remote")
	if err := os.RemoveAll(remoteDir); err != nil {
		t.Fatalf("remove remote dir: %v", err)
	}
	if err := os.WriteFile(remoteDir, []byte("not a directory"), 0o600); err != nil {
		t.Fatalf("write blocking file: %v", err)
	}
	blockedManager, err := NewSyncManager(
		SyncConfig{Enabled: true, ProfileNamespace: "profile-a", LocalDeviceID: "device-local"},
		WithSnapshotStore(blockedStore),
		WithProposalStore(blockedStore),
		WithTransport(transport),
		WithTrustVerifier(staticTrust{trusted: true}),
		WithClock(clock),
	)
	if err != nil {
		t.Fatalf("blocked NewSyncManager returned error: %v", err)
	}
	sendSyncEnvelope(t, provider, mailbox.MailboxID, snapshotEnvelope("profile-a", "device-remote", validSyncSnapshot("snapshot-write-failure", localSnapshot.Metadata.SnapshotID, now), now), now, "msg-write-failure")
	pull, err = blockedManager.PullRemote(ctx)
	if !errors.Is(err, ErrStoreUnavailable) || len(pull.Issues) == 0 {
		t.Fatalf("blocked pull should return safe store failure: %+v, %v", pull, err)
	}
	assertSyncSafeJSON(t, pull)
}

func assertNoUnsafeStoreFiles(t *testing.T, root string) {
	t.Helper()
	err := filepath.WalkDir(root, func(path string, entry os.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".json") {
			return nil
		}
		raw, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		lower := strings.ToLower(string(raw))
		for _, forbidden := range []string{"raw-relay-payload", "client_secret", "refresh_token", "access_token", "id_token", "auth_code", "verifier", "private_key", "begin private key", "github_pat", "ghp_", "token=", "password=", "secret=", `c:\\users\\`, "appdata", "downloads"} {
			if strings.Contains(lower, forbidden) {
				t.Fatalf("unsafe local store detail %q in %s", forbidden, string(raw))
			}
		}
		return nil
	})
	if err != nil {
		t.Fatalf("walk local store files: %v", err)
	}
}

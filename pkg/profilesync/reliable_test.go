package profilesync

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/AegisAgentAscalon/aegis-core/pkg/relay"
)

type reliableHarness struct {
	p     *relay.FileReliableMailbox
	inbox *ReliableInbox
	local *MemoryMetadataStore
	r     *ReliableSyncReceiver
	now   time.Time
}

func newReliableHarness(t *testing.T) *reliableHarness {
	t.Helper()
	now := time.Now().UTC()
	p, err := relay.NewFileReliableMailbox(relay.FileReliableMailboxConfig{Directory: t.TempDir(), ProviderID: "provider", Namespace: "profile-a", MailboxID: "inbox", OwnerDeviceID: "device-local"})
	if err != nil {
		t.Fatal(err)
	}
	i, err := NewReliableInbox(ReliableInboxConfig{Directory: t.TempDir(), Mailbox: p.Mailbox()})
	if err != nil {
		t.Fatal(err)
	}
	local := NewMemoryMetadataStore()
	local.SetLocalSnapshot(validSyncSnapshot("local", "", now))
	r, err := NewReliableSyncReceiver(ReliableSyncReceiverConfig{Provider: p, Inbox: i, LocalSnapshots: local, Clock: inboxClock{at: now}})
	if err != nil {
		t.Fatal(err)
	}
	return &reliableHarness{p: p, inbox: i, local: local, r: r, now: now}
}

func (h *reliableHarness) send(t *testing.T, id string, body []byte) {
	t.Helper()
	ref := h.p.Mailbox()
	envelope := relay.RelayEnvelope{RelayEnvelopeMetadata: relay.RelayEnvelopeMetadata{ProtocolVersion: 1, Namespace: ref.Namespace, SourceDeviceID: "device-remote", TargetDeviceID: ref.OwnerDeviceID, TargetMailboxID: ref.MailboxID, MessageKind: relay.MessageKindOpaque, MessageID: id, CreatedAt: h.now, ExpiresAt: h.now.Add(time.Hour), PayloadHash: relay.PayloadSHA256(body)}, Payload: body}
	if _, err := h.p.SendReliableEnvelope(context.Background(), relay.ReliableSendRequest{ProtocolVersion: 2, Mailbox: ref, Envelope: envelope}); err != nil {
		t.Fatal(err)
	}
}

func (h *reliableHarness) snapshot(t *testing.T, messageID, snapshotID string) {
	e := snapshotEnvelope("profile-a", "device-remote", validSyncSnapshot(snapshotID, "", h.now), h.now)
	e.MessageID = messageID
	raw, err := json.Marshal(e)
	if err != nil {
		t.Fatal(err)
	}
	h.send(t, messageID, raw)
}

func (h *reliableHarness) pending(t *testing.T) int {
	t.Helper()
	page, err := h.p.ReceiveBatch(context.Background(), relay.ReceiveBatchRequest{ProtocolVersion: 2, Mailbox: h.p.Mailbox()})
	if err != nil {
		t.Fatal(err)
	}
	return len(page.Items)
}

func (h *reliableHarness) restart(t *testing.T) {
	t.Helper()
	i, err := NewReliableInbox(h.inbox.cfg)
	if err != nil {
		t.Fatal(err)
	}
	h.inbox = i
	h.r.cfg.Inbox = i
}

func TestReliableInboxMixedPeersAndDomainDeduplication(t *testing.T) {
	h := newReliableHarness(t)
	ctx := context.Background()
	h.send(t, "bad", []byte("{malformed"))
	h.snapshot(t, "first", "remote")
	h.snapshot(t, "duplicate", "remote")
	conflict := snapshotEnvelope("profile-a", "device-remote", validSyncSnapshot("remote", "different-parent", h.now), h.now)
	conflict.MessageID = "conflict"
	raw, _ := json.Marshal(conflict)
	h.send(t, "conflict", raw)
	wrong := snapshotEnvelope("profile-a", "device-remote", validSyncSnapshot("wrong", "", h.now), h.now)
	wrong.MessageID = "inner-id"
	raw, _ = json.Marshal(wrong)
	h.send(t, "outer-id", raw)
	proposal := proposalEnvelope("profile-a", "device-remote", validSyncProposal("proposal", "local", h.now), h.now)
	proposal.MessageID = "proposal-msg"
	raw, _ = json.Marshal(proposal)
	h.send(t, "proposal-msg", raw)
	result, err := h.r.PullRemote(ctx)
	if err != nil || result.ReceivedSnapshots != 1 || result.ReceivedProposals != 1 || result.Rejected != 4 {
		t.Fatalf("mixed batch: %+v %v", result, err)
	}
	if h.pending(t) != 0 {
		t.Fatal("accepted peers not acknowledged")
	}
	h.restart(t)
	if result, err := h.r.PullRemote(ctx); err != nil || result.ReceivedSnapshots != 0 || result.ReceivedProposals != 0 {
		t.Fatal("retry reapplied", result, err)
	}
	snapshots, err := h.inbox.ListRemoteSnapshots(ctx)
	if err != nil || len(snapshots) != 1 || snapshots[0].Snapshot.Metadata.SnapshotID != "remote" {
		t.Fatal(snapshots, err)
	}
	receipts, err := h.inbox.ListReceipts(ctx)
	if err != nil || len(receipts) != 6 {
		t.Fatal(receipts, err)
	}
	for _, r := range receipts {
		if !r.Acknowledged || r.State == "pending" {
			t.Fatal("unfinished receipt", r)
		}
	}
}

func TestReliableInboxWriteFailureBoundaries(t *testing.T) {
	for _, fault := range []string{"ingress", "ack_state", "domain", "domain_committed_response_lost"} {
		t.Run(fault, func(t *testing.T) {
			h := newReliableHarness(t)
			ctx := context.Background()
			h.snapshot(t, "one", "remote")
			write := h.inbox.write
			h.inbox.write = func(ctx context.Context, path string, raw []byte) error {
				var state inboxState
				if err := json.Unmarshal(raw, &state); err != nil {
					return err
				}
				for _, e := range state.Entries {
					fail := fault == "ingress" || fault == "ack_state" && e.Acknowledged || fault == "domain" && e.State != "pending" || fault == "domain_committed_response_lost" && e.State != "pending"
					if fail {
						if fault == "domain_committed_response_lost" {
							if err := write(ctx, path, raw); err != nil {
								return err
							}
						}
						return errors.New("injected storage failure")
					}
				}
				return write(ctx, path, raw)
			}
			if _, err := h.r.PullRemote(ctx); err == nil {
				t.Fatal("fault did not fire")
			}
			if fault == "ingress" && h.pending(t) != 1 {
				t.Fatal("ack preceded ingress")
			}
			if fault != "ingress" && h.pending(t) != 0 {
				t.Fatal("expected local custody after ack")
			}
			h.restart(t)
			if _, err := h.r.PullRemote(ctx); err != nil {
				t.Fatal("restart did not recover", err)
			}
			for j := 0; j < 2; j++ {
				if _, err := h.r.PullRemote(ctx); err != nil {
					t.Fatal(err)
				}
			}
			records, err := h.inbox.ListRemoteSnapshots(ctx)
			if err != nil || len(records) != 1 {
				t.Fatal("wrong effect count", len(records), err)
			}
		})
	}
}

func TestReliableRestartAtCustodyCuts(t *testing.T) {
	for _, cut := range []string{"send", "receive", "ingress", "ack", "domain"} {
		t.Run(cut, func(t *testing.T) {
			h := newReliableHarness(t)
			ctx := context.Background()
			h.snapshot(t, "one", "remote")
			if cut != "send" {
				page, err := h.p.ReceiveBatch(ctx, relay.ReceiveBatchRequest{ProtocolVersion: 2, Mailbox: h.p.Mailbox()})
				if err != nil {
					t.Fatal(err)
				}
				if cut != "receive" {
					if err := h.inbox.accept(ctx, page.Items[0], h.now); err != nil {
						t.Fatal(err)
					}
				}
				if cut == "ack" || cut == "domain" {
					if _, err := h.p.AcknowledgeBatch(ctx, relay.AcknowledgeBatchRequest{ProtocolVersion: 2, Mailbox: h.p.Mailbox(), ReceiptIDs: []string{page.Items[0].ReceiptID}}); err != nil {
						t.Fatal(err)
					}
				}
				if cut == "domain" {
					local, _ := h.local.LoadLocalSnapshot(ctx)
					var result PullResult
					if err := h.r.processPending(ctx, local, &result); err != nil {
						t.Fatal(err)
					}
				}
			}
			h.restart(t)
			if _, err := h.r.PullRemote(ctx); err != nil {
				t.Fatal(err)
			}
			snapshots, err := h.inbox.ListRemoteSnapshots(ctx)
			if err != nil || len(snapshots) != 1 || h.pending(t) != 0 {
				t.Fatal("custody cut lost metadata", err)
			}
		})
	}
}

type reliableFaultProvider struct {
	relay.ReliableRelayProvider
	failReceive, badPage, loseAck bool
}

func (p *reliableFaultProvider) ReceiveBatch(ctx context.Context, req relay.ReceiveBatchRequest) (relay.ReceiveBatchResult, error) {
	if p.failReceive {
		return relay.ReceiveBatchResult{}, relay.ErrProviderUnavailable
	}
	page, err := p.ReliableRelayProvider.ReceiveBatch(ctx, req)
	if p.badPage && len(page.Items) > 0 {
		page.Items[0].Digest = "wrong"
	}
	return page, err
}
func (p *reliableFaultProvider) AcknowledgeBatch(ctx context.Context, req relay.AcknowledgeBatchRequest) (relay.AcknowledgeBatchResult, error) {
	result, err := p.ReliableRelayProvider.AcknowledgeBatch(ctx, req)
	if p.loseAck {
		p.loseAck = false
		return relay.AcknowledgeBatchResult{}, relay.ErrProviderUnavailable
	}
	return result, err
}

func TestReliableOfflineRecoveryProtocolFailureAndLostAck(t *testing.T) {
	h := newReliableHarness(t)
	ctx := context.Background()
	h.snapshot(t, "one", "remote")
	fault := &reliableFaultProvider{ReliableRelayProvider: h.p, badPage: true}
	h.r.cfg.Provider = fault
	if _, err := h.r.PullRemote(ctx); err == nil || h.pending(t) != 1 {
		t.Fatal("bad page consumed", err)
	}
	receipts, _ := h.inbox.ListReceipts(ctx)
	if len(receipts) != 0 {
		t.Fatal("partial page accepted")
	}
	fault.badPage = false
	fault.loseAck = true
	if _, err := h.r.PullRemote(ctx); err == nil {
		t.Fatal("lost ack response not reported")
	}
	h.restart(t)
	if _, err := h.r.PullRemote(ctx); err != nil {
		t.Fatal(err)
	}
	h.snapshot(t, "two", "remote-two")
	page, _ := h.p.ReceiveBatch(ctx, relay.ReceiveBatchRequest{ProtocolVersion: 2, Mailbox: h.p.Mailbox()})
	if err := h.inbox.accept(ctx, page.Items[0], h.now); err != nil {
		t.Fatal(err)
	}
	fault.failReceive = true
	result, err := h.r.PullRemote(ctx)
	if err == nil || result.ReceivedSnapshots != 1 {
		t.Fatal("offline local replay failed", result, err)
	}
	stored, _ := h.inbox.ListRemoteSnapshots(ctx)
	if len(stored) != 2 {
		t.Fatal("local custody lost")
	}
}

func TestReliablePreflightQuotasAndReceiptConflict(t *testing.T) {
	h := newReliableHarness(t)
	ctx := context.Background()
	h.snapshot(t, "one", "remote")
	h.snapshot(t, "two", "remote-two")
	h.local.SetError(errors.New("local read failed"))
	if _, err := h.r.PullRemote(ctx); err == nil || h.pending(t) != 2 {
		t.Fatal("preflight consumed")
	}
	h.local.SetError(nil)
	h.inbox.cfg.MaxRecords = 1
	if _, err := h.r.PullRemote(ctx); err == nil || h.pending(t) != 1 {
		t.Fatal("inbox quota lost accepted item", err)
	}
	h.inbox.cfg.MaxRecords = 2
	h.restart(t)
	if _, err := h.r.PullRemote(ctx); err != nil {
		t.Fatal(err)
	}
	pageReq := relay.ReceiveBatchRequest{ProtocolVersion: 2, Mailbox: h.p.Mailbox()}
	h.snapshot(t, "three", "remote-three")
	page, _ := h.p.ReceiveBatch(ctx, pageReq)
	h.inbox.cfg.MaxRecords = 3
	if err := h.inbox.accept(ctx, page.Items[0], h.now); err != nil {
		t.Fatal(err)
	}
	conflict := page.Items[0]
	conflict.Digest = "changed"
	if err := h.inbox.accept(ctx, conflict, h.now); !errors.Is(err, ErrInvalidSyncEnvelope) {
		t.Fatal("receipt overwritten")
	}
	// Lower admission limits never block work whose capacity was already reserved.
	h.inbox.cfg.MaxRecords = 1
	h.inbox.cfg.MaxStateBytes = 8192
	h.restart(t)
	if _, err := h.r.PullRemote(ctx); err != nil {
		t.Fatal("reduced quotas blocked drain", err)
	}
	if err := os.WriteFile(h.inbox.path, []byte(`{"version":2}`), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := NewReliableInbox(h.inbox.cfg); err == nil {
		t.Fatal("corrupt inbox recreated")
	}
}

func TestReliableConcurrentPullsCommitEachDomainOnce(t *testing.T) {
	h := newReliableHarness(t)
	ctx := context.Background()
	for j := 0; j < 8; j++ {
		h.snapshot(t, fmt.Sprintf("message-%d", j), fmt.Sprintf("snapshot-%d", j))
	}
	var wg sync.WaitGroup
	for j := 0; j < 3; j++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for k := 0; k < 3; k++ {
				_, _ = h.r.PullRemote(ctx)
			}
		}()
	}
	wg.Wait()
	if _, err := h.r.PullRemote(ctx); err != nil {
		t.Fatal(err)
	}
	snapshots, err := h.inbox.ListRemoteSnapshots(ctx)
	if err != nil || len(snapshots) != 8 {
		t.Fatal(len(snapshots), err)
	}
}

type reliableTrustFunc func(context.Context, string, string) TrustDecision

func (f reliableTrustFunc) VerifySigner(ctx context.Context, device, key string) TrustDecision {
	return f(ctx, device, key)
}

func TestReliableClockFreshnessAndStoredTrustValidation(t *testing.T) {
	t.Run("zero clock preserves inbox", func(t *testing.T) {
		h := newReliableHarness(t)
		h.snapshot(t, "one", "remote")
		before, err := os.ReadFile(h.inbox.path)
		if err != nil {
			t.Fatal(err)
		}
		h.r.cfg.Clock = inboxClock{}
		if _, err := h.r.PullRemote(context.Background()); err == nil {
			t.Fatal("zero clock accepted")
		}
		after, _ := os.ReadFile(h.inbox.path)
		if !bytes.Equal(before, after) || h.pending(t) != 1 {
			t.Fatal("zero clock corrupted custody")
		}
		h.restart(t)
	})
	t.Run("delayed processing uses current freshness", func(t *testing.T) {
		h := newReliableHarness(t)
		ctx := context.Background()
		h.snapshot(t, "one", "remote")
		page, _ := h.p.ReceiveBatch(ctx, relay.ReceiveBatchRequest{ProtocolVersion: 2, Mailbox: h.p.Mailbox()})
		if err := h.inbox.accept(ctx, page.Items[0], h.now); err != nil {
			t.Fatal(err)
		}
		h.r.cfg.Clock = inboxClock{at: h.now.Add(24 * time.Hour)}
		h.r.cfg.Trust = reliableTrustFunc(func(context.Context, string, string) TrustDecision { return TrustDecision{Trusted: true} })
		if _, err := h.r.PullRemote(ctx); err != nil {
			t.Fatal(err)
		}
		records, err := h.inbox.ListRemoteSnapshots(ctx)
		if err != nil {
			t.Fatal(err)
		}
		for _, record := range records {
			if record.Freshness.Fresh || !record.RequiresReview || !record.ReceivedAt.Equal(h.now) {
				t.Fatal("stale recovery misclassified", record)
			}
		}
		receipts, _ := h.inbox.ListReceipts(ctx)
		if len(receipts) != 1 || receipts[0].State == "pending" || !receipts[0].ProcessedAt.Equal(h.now.Add(24*time.Hour)) {
			t.Fatal("recovery was not classified", receipts)
		}
	})
	t.Run("trust corruption is rejected", func(t *testing.T) {
		h := newReliableHarness(t)
		ctx := context.Background()
		h.snapshot(t, "one", "remote")
		if _, err := h.r.PullRemote(ctx); err != nil {
			t.Fatal(err)
		}
		state, err := h.inbox.read(ctx)
		if err != nil {
			t.Fatal(err)
		}
		state.Entries[0].Snapshot.TrustState = "corrupted"
		raw, _ := json.Marshal(state)
		if err := os.WriteFile(h.inbox.path, raw, 0600); err != nil {
			t.Fatal(err)
		}
		if _, err := NewReliableInbox(h.inbox.cfg); err == nil {
			t.Fatal("invalid stored trust accepted")
		}
	})
	t.Run("conflict requires review and callbacks can read inbox", func(t *testing.T) {
		h := newReliableHarness(t)
		ctx := context.Background()
		h.r.cfg.Trust = reliableTrustFunc(func(ctx context.Context, _, _ string) TrustDecision {
			if _, err := h.inbox.ListReceipts(ctx); err != nil {
				t.Error(err)
			}
			return TrustDecision{Trusted: true}
		})
		h.snapshot(t, "one", "remote")
		if _, err := h.r.PullRemote(ctx); err != nil {
			t.Fatal(err)
		}
		e := snapshotEnvelope("profile-a", "device-remote", validSyncSnapshot("remote", "conflict", h.now), h.now)
		e.MessageID = "two"
		raw, _ := json.Marshal(e)
		h.send(t, "two", raw)
		result, err := h.r.PullRemote(ctx)
		if err != nil || !result.ReviewRequired || result.Rejected != 1 {
			t.Fatal("conflict not raised", result, err)
		}
	})
}

func TestReliableInboxReservesSpaceBeforeAck(t *testing.T) {
	h := newReliableHarness(t)
	ctx := context.Background()
	h.snapshot(t, "one", "remote")
	h.inbox.cfg.MaxStateBytes = 8192
	if _, err := h.r.PullRemote(ctx); err == nil || h.pending(t) != 1 {
		t.Fatal("insufficient effect headroom was acknowledged", err)
	}
	receipts, _ := h.inbox.ListReceipts(ctx)
	if len(receipts) != 0 {
		t.Fatal("accepted without reservation")
	}
}

// A child process exits after durable ingress and provider ack, before applying
// metadata. The parent must recover from files with no shared Go memory.
func TestReliableInboxProcessBoundary(t *testing.T) {
	dir := os.Getenv("AEGIS_W04_INBOX_CHILD")
	child := dir != ""
	if !child {
		dir = t.TempDir()
	}
	p, err := relay.NewFileReliableMailbox(relay.FileReliableMailboxConfig{Directory: filepath.Join(dir, "provider"), ProviderID: "provider", Namespace: "profile-a", MailboxID: "inbox", OwnerDeviceID: "device-local"})
	if err != nil {
		t.Fatal(err)
	}
	if !child {
		cmd := exec.Command(os.Args[0], "-test.run=^TestReliableInboxProcessBoundary$")
		cmd.Env = append(os.Environ(), "AEGIS_W04_INBOX_CHILD="+dir)
		if output, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("child failed: %v %s", err, output)
		}
	}
	inbox, err := NewReliableInbox(ReliableInboxConfig{Directory: filepath.Join(dir, "inbox"), Mailbox: p.Mailbox()})
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	local := NewMemoryMetadataStore()
	local.SetLocalSnapshot(validSyncSnapshot("local", "", now))
	r, err := NewReliableSyncReceiver(ReliableSyncReceiverConfig{Provider: p, Inbox: inbox, LocalSnapshots: local})
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	if child {
		h := reliableHarness{p: p, inbox: inbox, local: local, r: r, now: now}
		h.snapshot(t, "one", "remote")
		page, err := p.ReceiveBatch(ctx, relay.ReceiveBatchRequest{ProtocolVersion: 2, Mailbox: p.Mailbox()})
		if err != nil {
			t.Fatal(err)
		}
		if err := inbox.accept(ctx, page.Items[0], now); err != nil {
			t.Fatal(err)
		}
		if _, err := p.AcknowledgeBatch(ctx, relay.AcknowledgeBatchRequest{ProtocolVersion: 2, Mailbox: p.Mailbox(), ReceiptIDs: []string{page.Items[0].ReceiptID}}); err != nil {
			t.Fatal(err)
		}
		os.Exit(0)
	}
	if result, err := r.PullRemote(ctx); err != nil || result.ReceivedSnapshots != 1 {
		t.Fatal("process restart recovery failed", result, err)
	}
	if result, err := r.PullRemote(ctx); err != nil || result.ReceivedSnapshots != 0 {
		t.Fatal("process recovery reapplied", result, err)
	}
}

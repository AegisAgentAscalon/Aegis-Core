package profilesync

import (
	"context"
	"reflect"
	"testing"

	"github.com/AegisAgentAscalon/aegis-core/pkg/relay"
)

func TestW15ReliableRevisionRetryRebuildsInventory(t *testing.T) {
	h := newReliableHarness(t)
	ctx := context.Background()
	h.snapshot(t, "first", "same-domain")
	h.snapshot(t, "second", "same-domain")
	page, err := h.p.ReceiveBatch(ctx, relay.ReceiveBatchRequest{ProtocolVersion: 2, Mailbox: h.p.Mailbox()})
	if err != nil || len(page.Items) != 2 {
		t.Fatal(page, err)
	}
	for _, item := range page.Items {
		if err := h.inbox.accept(ctx, item, h.now); err != nil {
			t.Fatal(err)
		}
	}
	local, err := h.local.LoadLocalSnapshot(ctx)
	if err != nil {
		t.Fatal(err)
	}
	other := *h.r
	trustCalls := 0
	h.r.cfg.Trust = w15Trust(func(ctx context.Context, _, _ string) TrustDecision {
		trustCalls++
		if _, err := h.inbox.ListReceipts(ctx); err != nil {
			t.Error(err)
		}
		state, err := h.inbox.read(ctx)
		if err != nil {
			t.Error(err)
			return TrustDecision{}
		}
		view := newInboxView(state)
		var competing PullResult
		if err := other.processOne(ctx, &view, state.Entries[1].ReceiptID, local, &competing); err != nil || competing.ReceivedSnapshots != 1 {
			t.Error("competing receiver failed", competing, err)
		}
		return TrustDecision{Trusted: true}
	})
	var result PullResult
	if err := h.r.processPending(ctx, local, &result); err != nil {
		t.Fatal(err)
	}
	if result.ReceivedSnapshots != 0 || result.Rejected != 1 || trustCalls != 1 {
		t.Fatal("stale inventory escaped retry", result, trustCalls)
	}
	receipts, err := h.inbox.ListReceipts(ctx)
	if err != nil || len(receipts) != 2 || receipts[0].Reason != "duplicate" || receipts[1].State != "applied" {
		t.Fatal("unexpected final custody", receipts, err)
	}
}

func TestW15ProposalClassificationPreservesOrderedIssues(t *testing.T) {
	_, _, _, now := w15Manager(t)
	target := validSyncProposal("target", "local", now)
	competitor := validSyncProposal("competitor", "local", now)
	successor := validSyncProposal("successor", target.ProposedSnapshotID, now)
	result := classifyProposalRecords([]RemoteProposalRecord{{Proposal: competitor}, {Proposal: target}, {Proposal: successor}}, target, "local")
	var codes []string
	for _, issue := range result.issues {
		codes = append(codes, issue.Code)
	}
	if !result.duplicate || !reflect.DeepEqual(codes, []string{"competing_proposal_review_required", "duplicate_proposal_id"}) {
		t.Fatal("order or duplicate short-circuit changed", result)
	}
	state := inboxState{Revision: 1, Entries: []inboxEntry{{ReliableInboxReceipt: ReliableInboxReceipt{ReceiptID: "first", State: "pending"}}, {ReliableInboxReceipt: ReliableInboxReceipt{ReceiptID: "second", State: "applied"}, Proposal: &RemoteProposalRecord{Proposal: successor}, DomainDigest: "second"}}}
	view := newInboxView(state)
	view.accepted(inboxEntry{ReliableInboxReceipt: ReliableInboxReceipt{ReceiptID: "first", State: "applied"}, Proposal: &RemoteProposalRecord{Proposal: competitor}, DomainDigest: "first"})
	if view.state.Revision != 2 || len(view.proposals) != 2 || view.proposals[0].Proposal.ProposalID != "competitor" || view.proposals[1].Proposal.ProposalID != "successor" {
		t.Fatal("owned inventory lost inbox order", view)
	}
}

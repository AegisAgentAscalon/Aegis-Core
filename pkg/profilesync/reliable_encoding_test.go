package profilesync

import (
	"bytes"
	"context"
	"encoding/json"
	"testing"
	"time"

	"github.com/AegisAgentAscalon/aegis-core/pkg/relay"
)

func TestReliableRejectsUnserializableDomainAndContinues(t *testing.T) {
	for _, kind := range []string{"snapshot", "proposal"} {
		for _, recoverPending := range []bool{false, true} {
			name := kind + "/ingress"
			if recoverPending {
				name = kind + "/acknowledged-restart"
			}
			t.Run(name, func(t *testing.T) {
				h := newReliableHarness(t)
				ctx := context.Background()
				e := snapshotEnvelope("profile-a", "device-remote", validSyncSnapshot("bad", "", h.now), h.now)
				field := "signed_at"
				if kind == "proposal" {
					e = proposalEnvelope("profile-a", "device-remote", validSyncProposal("bad", "local", h.now), h.now)
					field = "updated_at"
				}
				e.MessageID = "bad"
				raw, err := json.Marshal(e)
				if err != nil {
					t.Fatal(err)
				}
				// Go accepts this offset on decode but cannot marshal it again.
				old := []byte(`"` + field + `":"` + h.now.Format(time.RFC3339Nano) + `"`)
				bad := []byte(`"` + field + `":"` + h.now.Add(24*time.Hour).Format("2006-01-02T15:04:05.999999999") + `+24:00"`)
				if !bytes.Contains(raw, old) {
					t.Fatal("timestamp fixture missing")
				}
				h.send(t, "bad", bytes.Replace(raw, old, bad, 1))
				if recoverPending {
					page, err := h.p.ReceiveBatch(ctx, relay.ReceiveBatchRequest{ProtocolVersion: 2, Mailbox: h.p.Mailbox()})
					if err != nil || len(page.Items) != 1 {
						t.Fatal(page, err)
					}
					if err := h.inbox.accept(ctx, page.Items[0], h.now); err != nil {
						t.Fatal(err)
					}
					if err := h.r.ackPending(ctx); err != nil {
						t.Fatal(err)
					}
					h.restart(t)
				}
				h.snapshot(t, "healthy", "healthy")
				result, err := h.r.PullRemote(ctx)
				if err != nil || result.Rejected != 1 || result.ReceivedSnapshots != 1 || h.pending(t) != 0 {
					t.Fatal("malformed domain blocked healthy peer", result, err)
				}
				h.restart(t)
				receipts, err := h.inbox.ListReceipts(ctx)
				if err != nil || len(receipts) != 2 || receipts[0].State != "rejected" || receipts[0].Reason != "invalid_envelope" || !receipts[0].Acknowledged || receipts[1].State != "applied" {
					t.Fatal("terminal dispositions did not survive restart", receipts, err)
				}
				if result, err := h.r.PullRemote(ctx); err != nil || result.Rejected != 0 || result.ReceivedSnapshots != 0 {
					t.Fatal("terminal records reprocessed", result, err)
				}
			})
		}
	}
}

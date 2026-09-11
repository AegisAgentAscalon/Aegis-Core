package relay

import (
	"bytes"
	"context"
	"errors"
	"os"
	"testing"
)

func TestReliableRejectsInvalidUTF8WithoutPoisoningSpool(t *testing.T) {
	ctx := context.Background()
	p := reliableTestMailbox(t, 3)
	req := reliableTestSend(p, "existing", 10)
	req.Envelope.Metadata = map[string]string{"label": "valid replacement rune: \uFFFD"}
	accepted, err := p.SendReliableEnvelope(ctx, req)
	if err != nil {
		t.Fatal(err)
	}
	before, err := os.ReadFile(p.path)
	if err != nil {
		t.Fatal(err)
	}
	bad := reliableTestSend(p, "bad", 10)
	bad.Envelope.Metadata = map[string]string{"label": string([]byte{0xff})}
	if err := ValidateEnvelope(bad.Envelope); err != nil {
		t.Fatal("legacy validation changed", err)
	}
	if _, err := p.SendReliableEnvelope(ctx, bad); !errors.Is(err, ErrInvalidMetadata) {
		t.Errorf("invalid UTF-8 was not rejected: %v", err)
	}
	after, err := os.ReadFile(p.path)
	if err != nil || !bytes.Equal(before, after) {
		t.Error("invalid send changed the existing spool", err)
	}
	p, err = NewFileReliableMailbox(p.cfg)
	if err != nil {
		t.Fatal("existing mailbox cannot reopen", err)
	}
	page, err := p.ReceiveBatch(ctx, ReceiveBatchRequest{ProtocolVersion: 2, Mailbox: p.Mailbox()})
	if err != nil || len(page.Items) != 1 || page.Items[0].ReceiptID != accepted.ReceiptID {
		t.Fatal("existing delivery lost", page, err)
	}
	if again, err := p.SendReliableEnvelope(ctx, req); err != nil || again != accepted {
		t.Fatal("valid Unicode replay changed", again, err)
	}
}

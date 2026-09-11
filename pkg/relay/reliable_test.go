package relay

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"
)

func reliableTestMailbox(t *testing.T, max int) *FileReliableMailbox {
	t.Helper()
	p, err := NewFileReliableMailbox(FileReliableMailboxConfig{Directory: t.TempDir(), ProviderID: "provider", Namespace: "profile-a", MailboxID: "inbox", OwnerDeviceID: "receiver", MaxRecords: max, MaxPayloadBytes: 800 << 10})
	if err != nil {
		t.Fatal(err)
	}
	return p
}

func reliableTestSend(p *FileReliableMailbox, id string, size int) ReliableSendRequest {
	now := time.Now().UTC()
	payload := bytes.Repeat([]byte("a"), size)
	return ReliableSendRequest{ProtocolVersion: 2, Mailbox: p.Mailbox(), Envelope: RelayEnvelope{RelayEnvelopeMetadata: RelayEnvelopeMetadata{ProtocolVersion: 1, Namespace: "profile-a", SourceDeviceID: "sender", TargetDeviceID: "receiver", TargetMailboxID: "inbox", MessageKind: MessageKindOpaque, MessageID: id, CreatedAt: now, ExpiresAt: now.Add(time.Minute), PayloadHash: PayloadSHA256(payload)}, Payload: payload}}
}

func TestReliableSpoolRestartReplayExpiryAndAck(t *testing.T) {
	ctx := context.Background()
	p := reliableTestMailbox(t, 1)
	req := reliableTestSend(p, "message", 10)
	accepted, err := p.SendReliableEnvelope(ctx, req)
	if err != nil {
		t.Fatal(err)
	}
	reopened, err := NewFileReliableMailbox(p.cfg)
	if err != nil {
		t.Fatal(err)
	}
	p = reopened
	if p.Mailbox() != req.Mailbox {
		t.Fatal("epoch changed on restart")
	}
	p.cfg.Clock = &mutableRelayClock{now: time.Now().Add(24 * time.Hour)}
	if again, err := p.SendReliableEnvelope(ctx, req); err != nil || again != accepted {
		t.Fatalf("expired/full retry: %+v %v", again, err)
	}
	if _, err := p.SendReliableEnvelope(ctx, reliableTestSend(p, "other", 10)); err == nil {
		t.Fatal("accepted beyond quota/expiry")
	}
	pageReq := ReceiveBatchRequest{ProtocolVersion: 2, Mailbox: p.Mailbox()}
	page, err := p.ReceiveBatch(ctx, pageReq)
	if err != nil || len(page.Items) != 1 || page.Items[0].ReceiptID != accepted.ReceiptID {
		t.Fatalf("receive: %+v %v", page, err)
	}
	ack := AcknowledgeBatchRequest{ProtocolVersion: 2, Mailbox: p.Mailbox(), ReceiptIDs: []string{accepted.ReceiptID}}
	result, err := p.AcknowledgeBatch(ctx, ack)
	if err != nil || result.Results[0].Status != "acknowledged" {
		t.Fatal(result, err)
	}
	p, err = NewFileReliableMailbox(p.cfg)
	if err != nil {
		t.Fatal(err)
	}
	result, err = p.AcknowledgeBatch(ctx, ack)
	if err != nil || result.Results[0].Status != "already_acknowledged" {
		t.Fatal(result, err)
	}
	if again, err := p.SendReliableEnvelope(ctx, req); err != nil || again != accepted {
		t.Fatal("lost send retry after ack", err)
	}
	page, err = p.ReceiveBatch(ctx, pageReq)
	if err != nil || len(page.Items) != 0 {
		t.Fatal("ack not persisted", err)
	}
	req.Envelope.Payload = []byte("different")
	req.Envelope.PayloadHash = PayloadSHA256(req.Envelope.Payload)
	if _, err = p.SendReliableEnvelope(ctx, req); !errors.Is(err, ErrDuplicateEnvelope) {
		t.Fatal("conflicting replay", err)
	}
}

func TestReliableSpoolBoundsAndFIFO(t *testing.T) {
	for _, tc := range []struct {
		name        string
		count, size int
	}{{"near-limit", 2, 700 << 10}, {"count", 130, 1}} {
		t.Run(tc.name, func(t *testing.T) {
			ctx := context.Background()
			p := reliableTestMailbox(t, 0)
			for i := 0; i < tc.count; i++ {
				if _, err := p.SendReliableEnvelope(ctx, reliableTestSend(p, fmt.Sprintf("m-%03d", i), tc.size)); err != nil {
					t.Fatal(err)
				}
			}
			seen := 0
			for seen < tc.count {
				req := ReceiveBatchRequest{ProtocolVersion: 2, Mailbox: p.Mailbox()}
				page, err := p.ReceiveBatch(ctx, req)
				if err != nil || ValidateReliableBatch(req, page) != nil || len(page.Items) == 0 {
					t.Fatal("invalid page", err)
				}
				if raw, _ := json.Marshal(page); len(raw)+1 > ReliableBatchBytes {
					t.Fatal("encoded overflow")
				}
				var ids []string
				for _, item := range page.Items {
					if item.Envelope.MessageID != fmt.Sprintf("m-%03d", seen) {
						t.Fatal("FIFO mismatch")
					}
					seen++
					ids = append(ids, item.ReceiptID)
				}
				if _, err := p.AcknowledgeBatch(ctx, AcknowledgeBatchRequest{ProtocolVersion: 2, Mailbox: p.Mailbox(), ReceiptIDs: ids}); err != nil {
					t.Fatal(err)
				}
			}
		})
	}
	p := reliableTestMailbox(t, 0)
	if _, err := p.SendReliableEnvelope(context.Background(), reliableTestSend(p, "too-big", 800<<10)); !errors.Is(err, ErrPayloadTooLarge) {
		t.Fatal("oversize accepted", err)
	}
	for _, req := range []ReceiveBatchRequest{{ProtocolVersion: 2, Mailbox: p.Mailbox(), MaxItems: 65}, {ProtocolVersion: 2, Mailbox: p.Mailbox(), MaxEncodedBytes: 1024}} {
		if _, err := p.ReceiveBatch(context.Background(), req); err == nil {
			t.Fatal("unsupported limits")
		}
	}
}

func TestReliableSpoolWriteFailuresAndCorruption(t *testing.T) {
	ctx := context.Background()
	p := reliableTestMailbox(t, 0)
	req := reliableTestSend(p, "one", 10)
	before, _ := os.ReadFile(p.path)
	write := p.write
	p.write = func(context.Context, string, []byte) error { return errors.New("disk failure") }
	if _, err := p.SendReliableEnvelope(ctx, req); err == nil {
		t.Fatal("accepted failed write")
	}
	after, _ := os.ReadFile(p.path)
	if !bytes.Equal(before, after) {
		t.Fatal("spool changed")
	}
	p.write = write
	accepted, err := p.SendReliableEnvelope(ctx, req)
	if err != nil {
		t.Fatal(err)
	}
	p.write = func(context.Context, string, []byte) error { return errors.New("disk failure") }
	ack := AcknowledgeBatchRequest{ProtocolVersion: 2, Mailbox: p.Mailbox(), ReceiptIDs: []string{accepted.ReceiptID}}
	if _, err := p.AcknowledgeBatch(ctx, ack); err == nil {
		t.Fatal("ack succeeded without commit")
	}
	page, err := p.ReceiveBatch(ctx, ReceiveBatchRequest{ProtocolVersion: 2, Mailbox: p.Mailbox()})
	if err != nil || len(page.Items) != 1 {
		t.Fatal("failed ack lost item", err)
	}
	p.write = write
	cancelCtx, cancel := context.WithCancel(ctx)
	cancel()
	if _, err := p.AcknowledgeBatch(cancelCtx, ack); !errors.Is(err, ErrContextCanceled) {
		t.Fatal(err)
	}
	bad := ack
	bad.Mailbox.Epoch = strings.Repeat("0", 64)
	if _, err := p.AcknowledgeBatch(ctx, bad); err == nil {
		t.Fatal("wrong epoch")
	}
	if err := os.WriteFile(p.path, []byte(`{"version":2}`), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := NewFileReliableMailbox(p.cfg); err == nil {
		t.Fatal("corrupt spool recreated")
	}
}

type reliableClockFunc func() time.Time

func (f reliableClockFunc) Now() time.Time { return f() }

func TestReliableReducedQuotaStillDrainsAndClockCanReenter(t *testing.T) {
	ctx := context.Background()
	p := reliableTestMailbox(t, 2)
	p.cfg.Clock = reliableClockFunc(func() time.Time {
		if _, err := p.ReceiveBatch(ctx, ReceiveBatchRequest{ProtocolVersion: 2, Mailbox: p.Mailbox()}); err != nil {
			t.Error(err)
		}
		return time.Now().UTC()
	})
	var ids []string
	for _, id := range []string{"one", "two"} {
		result, err := p.SendReliableEnvelope(ctx, reliableTestSend(p, id, 2048))
		if err != nil {
			t.Fatal(err)
		}
		ids = append(ids, result.ReceiptID)
	}
	cfg := p.cfg
	cfg.Clock = nil
	cfg.MaxRecords = 1
	cfg.MaxStateBytes = 1024
	reopened, err := NewFileReliableMailbox(cfg)
	if err != nil {
		t.Fatal(err)
	}
	for _, id := range ids {
		if _, err := reopened.AcknowledgeBatch(ctx, AcknowledgeBatchRequest{ProtocolVersion: 2, Mailbox: reopened.Mailbox(), ReceiptIDs: []string{id}}); err != nil {
			t.Fatal("lower admission quota blocked draining", err)
		}
	}
}

func TestReliableHTTPRejectsTruncatedOrMismatchedReplies(t *testing.T) {
	p := reliableTestMailbox(t, 0)
	ctx := context.Background()
	_, err := p.SendReliableEnvelope(ctx, reliableTestSend(p, "one", 10))
	if err != nil {
		t.Fatal(err)
	}
	req := ReceiveBatchRequest{ProtocolVersion: 2, Mailbox: p.Mailbox()}
	page, _ := p.ReceiveBatch(ctx, req)
	for _, kind := range []string{"truncated", "wrong_epoch", "duplicate_receipt", "wrong_digest", "extra_json"} {
		t.Run(kind, func(t *testing.T) {
			copyPage := page
			copyPage.Items = append([]ReliableDelivery{}, page.Items...)
			switch kind {
			case "wrong_epoch":
				copyPage.Mailbox.Epoch = strings.Repeat("0", 64)
			case "duplicate_receipt":
				copyPage.Items = append(copyPage.Items, copyPage.Items[0])
			case "wrong_digest":
				copyPage.Items[0].Digest = strings.Repeat("0", 64)
			}
			raw, _ := json.Marshal(copyPage)
			if kind == "truncated" {
				raw = raw[:len(raw)/2]
			}
			if kind == "extra_json" {
				raw = append(raw, []byte(" {}")...)
			}
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { _, _ = w.Write(raw) }))
			defer server.Close()
			client, _ := NewHTTPRelayClient(HTTPRelayClientConfig{BaseURL: server.URL})
			if _, err := client.ReceiveBatch(ctx, req); err == nil {
				t.Fatal("accepted malformed response")
			}
		})
	}
}

type failedReliableResponse struct{ header http.Header }

func (w *failedReliableResponse) Header() http.Header       { return w.header }
func (w *failedReliableResponse) WriteHeader(int)           {}
func (w *failedReliableResponse) Write([]byte) (int, error) { return 0, errors.New("disconnect") }

func TestReliableHTTPDisconnectAuthorizationAndLostAck(t *testing.T) {
	ctx := context.Background()
	p := reliableTestMailbox(t, 0)
	ref := p.Mailbox()
	authorize := func(r *http.Request, action string, mailbox ReliableMailboxRef, source string) bool {
		return mailbox == ref && ((action == "send" && source == "sender" && r.Header.Get("Authorization") == "Bearer sender") || (action != "send" && r.Header.Get("Authorization") == "Bearer receiver"))
	}
	h, err := NewReliableRelayHandler(ReliableRelayHandlerConfig{Provider: p, Authorize: authorize})
	if err != nil {
		t.Fatal(err)
	}
	server := httptest.NewServer(h)
	defer server.Close()
	sender, _ := NewHTTPRelayClient(HTTPRelayClientConfig{BaseURL: server.URL, Bearer: "sender"})
	receiver, _ := NewHTTPRelayClient(HTTPRelayClientConfig{BaseURL: server.URL, Bearer: "receiver"})
	req := reliableTestSend(p, "one", 100)
	accepted, err := sender.SendReliableEnvelope(ctx, req)
	if err != nil {
		t.Fatal(err)
	}
	pageReq := ReceiveBatchRequest{ProtocolVersion: 2, Mailbox: ref}
	raw, _ := json.Marshal(pageReq)
	r := httptest.NewRequest(http.MethodPost, "/v2/mailboxes/receive", bytes.NewReader(raw))
	r.Header.Set("Authorization", "Bearer receiver")
	h.ServeHTTP(&failedReliableResponse{header: http.Header{}}, r)
	page, err := receiver.ReceiveBatch(ctx, pageReq)
	if err != nil || len(page.Items) != 1 || page.Items[0].ReceiptID != accepted.ReceiptID {
		t.Fatal("disconnect lost message", err)
	}
	if _, err := sender.ReceiveBatch(ctx, pageReq); err == nil {
		t.Fatal("sender received owner queue")
	}
	spoof := req
	spoof.Envelope.SourceDeviceID = "other"
	if _, err := sender.SendReliableEnvelope(ctx, spoof); err == nil {
		t.Fatal("source spoof")
	}
	wrong := pageReq
	wrong.Mailbox.Namespace = "other"
	if _, err := receiver.ReceiveBatch(ctx, wrong); err == nil {
		t.Fatal("namespace spoof")
	}
	ack := AcknowledgeBatchRequest{ProtocolVersion: 2, Mailbox: ref, ReceiptIDs: []string{accepted.ReceiptID}}
	raw, _ = json.Marshal(ack)
	r = httptest.NewRequest(http.MethodPost, "/v2/mailboxes/ack", bytes.NewReader(raw))
	r.Header.Set("Authorization", "Bearer receiver")
	h.ServeHTTP(&failedReliableResponse{header: http.Header{}}, r)
	again, err := receiver.AcknowledgeBatch(ctx, ack)
	if err != nil || again.Results[0].Status != "already_acknowledged" {
		t.Fatal("ack response retry", err)
	}
	if _, err := NewReliableRelayHandler(ReliableRelayHandlerConfig{Provider: p}); err == nil {
		t.Fatal("missing auth accepted")
	}
}

package relay

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestHTTPRelayClientServerLifecycle(t *testing.T) {
	ctx := context.Background()
	now := time.Now().UTC()
	clock := &mutableRelayClock{now: now}
	handler, err := NewHTTPRelayHandler(HTTPRelayHandlerConfig{ProviderID: "network-relay-1", Clock: clock, AllowUnauthenticated: true})
	if err != nil {
		t.Fatalf("NewHTTPRelayHandler returned error: %v", err)
	}
	server := httptest.NewServer(handler)
	defer server.Close()
	client := newHTTPRelayTestClient(t, server.URL, "")

	status := client.GetStatus(ctx)
	if !status.Enabled || !status.Available || status.ProviderID != "network-relay-1" {
		t.Fatalf("unexpected status: %+v", status)
	}

	hint := validEndpointHint(now)
	if err := client.PublishEndpointHint(ctx, hint); err != nil {
		t.Fatalf("PublishEndpointHint returned error: %v", err)
	}
	hints, err := client.ListEndpointHints(ctx, EndpointHintQuery{Namespace: "profile-a", DeviceID: "device-1"})
	if err != nil || len(hints) != 1 {
		t.Fatalf("ListEndpointHints = %+v, %v", hints, err)
	}
	if err := client.RevokeEndpointHint(ctx, EndpointHintRevokeRequest{Namespace: "profile-a", DeviceID: "device-1", EndpointID: "endpoint-1"}); err != nil {
		t.Fatalf("RevokeEndpointHint returned error: %v", err)
	}
	hints, err = client.ListEndpointHints(ctx, EndpointHintQuery{Namespace: "profile-a", DeviceID: "device-1"})
	if err != nil || len(hints) != 0 {
		t.Fatalf("revoked hints = %+v, %v", hints, err)
	}

	announcement := RendezvousAnnouncement{ProtocolVersion: ProtocolVersion, Namespace: "profile-a", ProfileID: "profile-1", DeviceID: "device-1", AnnouncementID: "ann-1", CreatedAt: now, ExpiresAt: now.Add(time.Hour), EndpointHints: []EndpointHint{hint}}
	if err := client.Announce(ctx, announcement); err != nil {
		t.Fatalf("Announce returned error: %v", err)
	}
	peers, err := client.Query(ctx, RendezvousQuery{Namespace: "profile-a", ProfileID: "profile-1"})
	if err != nil || len(peers) != 1 {
		t.Fatalf("Query = %+v, %v", peers, err)
	}
	if err := client.Revoke(ctx, RendezvousRevokeRequest{Namespace: "profile-a", DeviceID: "device-1", AnnouncementID: "ann-1"}); err != nil {
		t.Fatalf("Revoke returned error: %v", err)
	}
	peers, err = client.Query(ctx, RendezvousQuery{Namespace: "profile-a", ProfileID: "profile-1"})
	if err != nil || len(peers) != 0 {
		t.Fatalf("revoked peers = %+v, %v", peers, err)
	}

	mailbox, err := client.OpenMailbox(ctx, MailboxOpenRequest{Namespace: "profile-a", OwnerDeviceID: "device-2", MailboxID: "mbox-http-1", CreatedAt: now, ExpiresAt: now.Add(time.Hour)})
	if err != nil {
		t.Fatalf("OpenMailbox returned error: %v", err)
	}
	payload := []byte("network-relay-ping")
	envelope := validEnvelope(now, payload)
	envelope.TargetDeviceID = ""
	envelope.TargetMailboxID = mailbox.MailboxID
	envelope.PayloadHash = PayloadSHA256(payload)
	receipt, err := client.SendEnvelope(ctx, envelope)
	if err != nil {
		t.Fatalf("SendEnvelope returned error: %v", err)
	}
	if !receipt.Accepted || !receipt.Delivered || strings.Contains(receipt.Summary, string(payload)) {
		t.Fatalf("unsafe or unexpected receipt: %+v", receipt)
	}
	if _, err := client.SendEnvelope(ctx, envelope); !errors.Is(err, ErrDuplicateEnvelope) {
		t.Fatalf("duplicate send error = %v", err)
	}
	received, err := client.ReceiveEnvelopes(ctx, mailbox)
	if err != nil || len(received) != 1 || string(received[0].Payload) != string(payload) {
		t.Fatalf("ReceiveEnvelopes = %+v, %v", received, err)
	}
	received, err = client.ReceiveEnvelopes(ctx, mailbox)
	if err != nil || len(received) != 0 {
		t.Fatalf("mailbox should drain after receive: %+v, %v", received, err)
	}
	assertRelaySafeJSON(t, status)
	assertRelaySafeJSON(t, receipt)
}

func TestHTTPRelayValidationFailuresAreSafe(t *testing.T) {
	ctx := context.Background()
	now := time.Now().UTC()
	clock := &mutableRelayClock{now: now}
	handler, err := NewHTTPRelayHandler(HTTPRelayHandlerConfig{ProviderID: "network-relay-1", Clock: clock, AllowUnauthenticated: true})
	if err != nil {
		t.Fatalf("NewHTTPRelayHandler returned error: %v", err)
	}
	server := httptest.NewServer(handler)
	defer server.Close()
	client := newHTTPRelayTestClient(t, server.URL, "")

	if err := client.PublishEndpointHint(ctx, EndpointHint{ProtocolVersion: ProtocolVersion, Namespace: "../bad", DeviceID: "device-1", EndpointID: "endpoint-1", EndpointType: "mailbox", CreatedAt: now, ExpiresAt: now.Add(time.Hour)}); !errors.Is(err, ErrInvalidNamespace) {
		t.Fatalf("invalid namespace error = %v", err)
	}
	if _, err := client.OpenMailbox(ctx, MailboxOpenRequest{Namespace: "profile-a", OwnerDeviceID: "bad/device", MailboxID: "mbox-1", CreatedAt: now, ExpiresAt: now.Add(time.Hour)}); !errors.Is(err, ErrInvalidDeviceID) {
		t.Fatalf("invalid device error = %v", err)
	}
	mailbox, err := client.OpenMailbox(ctx, MailboxOpenRequest{Namespace: "profile-a", OwnerDeviceID: "device-2", MailboxID: "mbox-http-1", CreatedAt: now, ExpiresAt: now.Add(time.Hour)})
	if err != nil {
		t.Fatalf("OpenMailbox returned error: %v", err)
	}
	cases := []struct {
		name string
		edit func(*RelayEnvelope)
		want error
	}{
		{"unsupported protocol", func(e *RelayEnvelope) { e.ProtocolVersion = 42 }, ErrUnsupportedProtocolVersion},
		{"payload hash mismatch", func(e *RelayEnvelope) { e.PayloadHash = PayloadSHA256([]byte("other")) }, ErrPayloadHashMismatch},
		{"unsafe metadata", func(e *RelayEnvelope) { e.Metadata = map[string]string{"path": `C:\Users\person\file`} }, ErrInvalidMetadata},
		{"oversized payload", func(e *RelayEnvelope) {
			e.Payload = make([]byte, DefaultMaxPayloadSize+1)
			e.PayloadHash = PayloadSHA256(e.Payload)
		}, ErrPayloadTooLarge},
		{"bad source", func(e *RelayEnvelope) { e.SourceDeviceID = "bad/source" }, ErrInvalidDeviceID},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			envelope := validEnvelope(now, []byte("network-relay-ping"))
			envelope.TargetDeviceID = ""
			envelope.TargetMailboxID = mailbox.MailboxID
			tc.edit(&envelope)
			if _, err := client.SendEnvelope(ctx, envelope); !errors.Is(err, tc.want) {
				t.Fatalf("SendEnvelope error = %v, want %v", err, tc.want)
			}
		})
	}

	expiredMailbox, err := client.OpenMailbox(ctx, MailboxOpenRequest{Namespace: "profile-a", OwnerDeviceID: "device-3", MailboxID: "mbox-expired", CreatedAt: now, ExpiresAt: now.Add(time.Minute)})
	if err != nil {
		t.Fatalf("OpenMailbox expired fixture returned error: %v", err)
	}
	clock.now = now.Add(2 * time.Hour)
	if _, err := client.ReceiveEnvelopes(ctx, expiredMailbox); !errors.Is(err, ErrMailboxExpired) {
		t.Fatalf("expired mailbox receive error = %v", err)
	}
}

func TestHTTPRelayMalformedRequestsAuthorizationAndClientFailures(t *testing.T) {
	ctx := context.Background()
	now := time.Now().UTC()
	if _, err := NewHTTPRelayHandler(HTTPRelayHandlerConfig{ProviderID: "network-relay-1", Clock: &mutableRelayClock{now: now}}); !errors.Is(err, ErrInvalidConfig) {
		t.Fatalf("unauthenticated handler error = %v, want invalid config", err)
	}
	handler, err := NewHTTPRelayHandler(HTTPRelayHandlerConfig{ProviderID: "network-relay-1", Clock: &mutableRelayClock{now: now}, Authorizer: BearerRelayAuthorizer{Bearer: "test-relay-access"}})
	if err != nil {
		t.Fatalf("NewHTTPRelayHandler returned error: %v", err)
	}
	server := httptest.NewServer(handler)
	defer server.Close()

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, server.URL+"/mailboxes", strings.NewReader("{"))
	if err != nil {
		t.Fatalf("NewRequest returned error: %v", err)
	}
	req.Header.Set("Authorization", "Bearer test-relay-access")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("malformed request returned client error: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("malformed request status = %d", resp.StatusCode)
	}
	validMailbox, err := json.Marshal(MailboxOpenRequest{Namespace: "profile-a", OwnerDeviceID: "device-1", MailboxID: "mbox-1", CreatedAt: now, ExpiresAt: now.Add(time.Hour)})
	if err != nil {
		t.Fatal(err)
	}
	req, err = http.NewRequestWithContext(ctx, http.MethodPost, server.URL+"/mailboxes", strings.NewReader(string(validMailbox)+` {}`))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Authorization", "Bearer test-relay-access")
	resp, err = http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("trailing JSON request status = %d", resp.StatusCode)
	}

	trailingReq, err := http.NewRequestWithContext(ctx, http.MethodPost, server.URL+"/mailboxes", strings.NewReader(`{"Namespace":"profile-a","OwnerDeviceID":"device-1","MailboxID":"mbox-trailing","CreatedAt":"`+now.Format(time.RFC3339Nano)+`","ExpiresAt":"`+now.Add(time.Hour).Format(time.RFC3339Nano)+`"} {}`))
	if err != nil {
		t.Fatalf("NewRequest returned error: %v", err)
	}
	trailingReq.Header.Set("Authorization", "Bearer test-relay-access")
	trailingResp, err := http.DefaultClient.Do(trailingReq)
	if err != nil {
		t.Fatalf("trailing request returned client error: %v", err)
	}
	trailingResp.Body.Close()
	if trailingResp.StatusCode != http.StatusBadRequest {
		t.Fatalf("trailing request status = %d", trailingResp.StatusCode)
	}

	unauthorizedClient := newHTTPRelayTestClient(t, server.URL, "")
	status := unauthorizedClient.GetStatus(ctx)
	rawStatus, err := json.Marshal(status)
	if err != nil {
		t.Fatalf("marshal unauthorized status: %v", err)
	}
	if status.Available || strings.Contains(strings.ToLower(string(rawStatus)), "test-relay-access") {
		t.Fatalf("unauthorized status leaked or was available: %+v", status)
	}
	client := newHTTPRelayTestClient(t, server.URL, "test-relay-access")
	if !client.GetStatus(ctx).Available {
		t.Fatalf("authorized client should see relay available")
	}

	badJSONServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("{"))
	}))
	defer badJSONServer.Close()
	badJSONClient := newHTTPRelayTestClient(t, badJSONServer.URL, "")
	if status := badJSONClient.GetStatus(ctx); status.Available || !assertStatusSafe(status) {
		t.Fatalf("malformed response status should be sanitized: %+v", status)
	}

	trailingJSONServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"enabled":true,"available":true,"provider_id":"unsafe-accepted"} {}`))
	}))
	defer trailingJSONServer.Close()
	trailingJSONClient := newHTTPRelayTestClient(t, trailingJSONServer.URL, "")
	if status := trailingJSONClient.GetStatus(ctx); status.Available {
		t.Fatalf("client accepted trailing JSON response: %+v", status)
	}

	closedServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	closedURL := closedServer.URL
	closedServer.Close()
	closedClient := newHTTPRelayTestClient(t, closedURL, "")
	if status := closedClient.GetStatus(ctx); status.Available || !assertStatusSafe(status) {
		t.Fatalf("closed server status should be sanitized: %+v", status)
	}
}

func TestHTTPRelayRejectsOversizedRequestBodies(t *testing.T) {
	handler, err := NewHTTPRelayHandler(HTTPRelayHandlerConfig{ProviderID: "network-relay-1", MaxRequestBodyBytes: 32, AllowUnauthenticated: true})
	if err != nil {
		t.Fatal(err)
	}
	server := httptest.NewServer(handler)
	defer server.Close()
	resp, err := http.Post(server.URL+"/mailboxes", "application/json", strings.NewReader(strings.Repeat("x", 64)))
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusRequestEntityTooLarge {
		t.Fatalf("oversized request status = %d, want %d", resp.StatusCode, http.StatusRequestEntityTooLarge)
	}
}

func TestHTTPRelayClientRejectsUnsafeBaseURLsAndUsesFiniteDefaultTimeout(t *testing.T) {
	for _, baseURL := range []string{
		"ftp://example.test",
		"file:///tmp/relay",
		"https://user:pass@example.test",
		"https://example.test?token=value",
		"https://example.test#fragment",
		"example.test/relay",
	} {
		if _, err := NewHTTPRelayClient(HTTPRelayClientConfig{BaseURL: baseURL}); !errors.Is(err, ErrInvalidConfig) {
			t.Fatalf("unsafe base URL %q error = %v", baseURL, err)
		}
	}
	client, err := NewHTTPRelayClient(HTTPRelayClientConfig{BaseURL: "https://example.test/relay"})
	if err != nil {
		t.Fatal(err)
	}
	if client.client == nil || client.client.Timeout != defaultHTTPRelayTimeout {
		t.Fatalf("default HTTP timeout = %v, want %v", client.client.Timeout, defaultHTTPRelayTimeout)
	}
}

func TestHTTPRelayConcurrentSendReceive(t *testing.T) {
	ctx := context.Background()
	now := time.Now().UTC()
	handler, err := NewHTTPRelayHandler(HTTPRelayHandlerConfig{ProviderID: "network-relay-1", Clock: &mutableRelayClock{now: now}, AllowUnauthenticated: true})
	if err != nil {
		t.Fatalf("NewHTTPRelayHandler returned error: %v", err)
	}
	server := httptest.NewServer(handler)
	defer server.Close()
	client := newHTTPRelayTestClient(t, server.URL, "")
	mailbox, err := client.OpenMailbox(ctx, MailboxOpenRequest{Namespace: "profile-a", OwnerDeviceID: "device-2", MailboxID: "mbox-concurrent", CreatedAt: now, ExpiresAt: now.Add(time.Hour)})
	if err != nil {
		t.Fatalf("OpenMailbox returned error: %v", err)
	}
	const count = 12
	var wg sync.WaitGroup
	errs := make(chan error, count)
	for i := 0; i < count; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			payload := []byte("network-payload")
			envelope := validEnvelope(now, payload)
			envelope.MessageID = fmt.Sprintf("msg-http-concurrent-%02d", i)
			envelope.TargetDeviceID = ""
			envelope.TargetMailboxID = mailbox.MailboxID
			envelope.PayloadHash = PayloadSHA256(payload)
			_, err := client.SendEnvelope(ctx, envelope)
			errs <- err
		}(i)
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		if err != nil {
			t.Fatalf("SendEnvelope returned error: %v", err)
		}
	}
	received, err := client.ReceiveEnvelopes(ctx, mailbox)
	if err != nil {
		t.Fatalf("ReceiveEnvelopes returned error: %v", err)
	}
	if len(received) != count {
		t.Fatalf("received count = %d, want %d", len(received), count)
	}
}

func TestHTTPRelayPackageDoesNotImportForbiddenBoundaries(t *testing.T) {
	assertRelayProductionFileClean(t, "http.go")
}

func newHTTPRelayTestClient(t *testing.T, baseURL, bearer string) *HTTPRelayClient {
	t.Helper()
	client, err := NewHTTPRelayClient(HTTPRelayClientConfig{BaseURL: baseURL, Bearer: bearer, ProviderID: "network-relay-1"})
	if err != nil {
		t.Fatalf("NewHTTPRelayClient returned error: %v", err)
	}
	return client
}

func assertStatusSafe(status RelayStatus) bool {
	raw, err := json.Marshal(status)
	if err != nil {
		return false
	}
	text := strings.ToLower(string(raw))
	return !strings.Contains(text, "network-relay-ping") &&
		!strings.Contains(text, "test-relay-access") &&
		!strings.Contains(text, "secret") &&
		!strings.Contains(text, `c:\`)
}

func assertRelayProductionFileClean(t *testing.T, file string) {
	t.Helper()
	raw := readRelayTestFile(t, file)
	for _, forbidden := range []string{"/internal/", "internal/", "examples/", "appbridge", "profilemesh", "profilesync", "devicelink", "named-consumer-app", "named-consumer-current", "named-consumer.local"} {
		if strings.Contains(string(raw), forbidden) {
			t.Fatalf("relay HTTP provider references forbidden boundary text %q in %s", forbidden, file)
		}
	}
}

func readRelayTestFile(t *testing.T, file string) []byte {
	t.Helper()
	raw, err := os.ReadFile(file)
	if err != nil {
		t.Fatalf("read %s: %v", file, err)
	}
	return raw
}

func TestHTTPRelayHandlerValidatesEnvelopeBeforeInjectedProvider(t *testing.T) {
	ctx := context.Background()
	now := time.Now().UTC()
	provider := &acceptingRelayProvider{}
	handler, err := NewHTTPRelayHandler(HTTPRelayHandlerConfig{Provider: provider, ProviderID: "network-relay-1", MaxPayloadBytes: 16, MaxRequestBodyBytes: 4096, AllowUnauthenticated: true})
	if err != nil {
		t.Fatalf("NewHTTPRelayHandler returned error: %v", err)
	}
	server := httptest.NewServer(handler)
	defer server.Close()

	envelope := validEnvelope(now, []byte("this payload is too large"))
	envelope.TargetDeviceID = "device-2"
	envelope.PayloadHash = PayloadSHA256(envelope.Payload)
	raw, err := json.Marshal(envelope)
	if err != nil {
		t.Fatalf("Marshal envelope returned error: %v", err)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, server.URL+"/envelopes", strings.NewReader(string(raw)))
	if err != nil {
		t.Fatalf("NewRequest returned error: %v", err)
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("HTTP request returned error: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusRequestEntityTooLarge {
		t.Fatalf("status = %d, want %d", resp.StatusCode, http.StatusRequestEntityTooLarge)
	}
	if provider.sendCalled {
		t.Fatalf("handler forwarded invalid envelope to injected provider")
	}
}

func TestHTTPRelayHandlerValidatesQueriesBeforeInjectedProvider(t *testing.T) {
	ctx := context.Background()
	provider := &acceptingRelayProvider{}
	rendezvous := &acceptingRendezvousProvider{}
	handler, err := NewHTTPRelayHandler(HTTPRelayHandlerConfig{Provider: provider, Rendezvous: rendezvous, ProviderID: "network-relay-1", AllowUnauthenticated: true})
	if err != nil {
		t.Fatalf("NewHTTPRelayHandler returned error: %v", err)
	}
	server := httptest.NewServer(handler)
	defer server.Close()

	endpointReq, err := http.NewRequestWithContext(ctx, http.MethodGet, server.URL+"/endpoint-hints?namespace=../bad&device_id=device-1", nil)
	if err != nil {
		t.Fatalf("NewRequest returned error: %v", err)
	}
	endpointResp, err := http.DefaultClient.Do(endpointReq)
	if err != nil {
		t.Fatalf("HTTP request returned error: %v", err)
	}
	endpointResp.Body.Close()
	if endpointResp.StatusCode != http.StatusBadRequest {
		t.Fatalf("endpoint-hints status = %d, want %d", endpointResp.StatusCode, http.StatusBadRequest)
	}
	if provider.listCalled {
		t.Fatalf("handler forwarded invalid endpoint query to injected provider")
	}

	rendezvousReq, err := http.NewRequestWithContext(ctx, http.MethodGet, server.URL+"/rendezvous?namespace=profile-a&profile_id=bad/profile", nil)
	if err != nil {
		t.Fatalf("NewRequest returned error: %v", err)
	}
	rendezvousResp, err := http.DefaultClient.Do(rendezvousReq)
	if err != nil {
		t.Fatalf("HTTP request returned error: %v", err)
	}
	rendezvousResp.Body.Close()
	if rendezvousResp.StatusCode != http.StatusBadRequest {
		t.Fatalf("rendezvous status = %d, want %d", rendezvousResp.StatusCode, http.StatusBadRequest)
	}
	if rendezvous.queryCalled {
		t.Fatalf("handler forwarded invalid rendezvous query to injected provider")
	}
}

func TestHTTPRelayClientRejectsMalformedEnvelopeResponse(t *testing.T) {
	ctx := context.Background()
	now := time.Now().UTC()
	badEnvelope := validEnvelope(now, []byte("payload"))
	badEnvelope.TargetDeviceID = ""
	badEnvelope.TargetMailboxID = "mbox-1"
	badEnvelope.PayloadHash = PayloadSHA256([]byte("different"))
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/envelopes/receive" {
			writeRelayJSON(w, http.StatusOK, RelayStatus{Enabled: true, Available: true, ProviderID: "network-relay-1", Summary: "ok"})
			return
		}
		writeRelayJSON(w, http.StatusOK, []RelayEnvelope{badEnvelope})
	}))
	defer server.Close()
	client := newHTTPRelayTestClient(t, server.URL, "")
	mailbox := MailboxRef{Namespace: "profile-a", MailboxID: "mbox-1", OwnerDeviceID: "device-2", ExpiresAt: now.Add(time.Hour)}
	if _, err := client.ReceiveEnvelopes(ctx, mailbox); !errors.Is(err, ErrProviderUnavailable) {
		t.Fatalf("ReceiveEnvelopes error = %v, want provider unavailable", err)
	}
}

type acceptingRelayProvider struct {
	sendCalled bool
	listCalled bool
}

func (p *acceptingRelayProvider) GetStatus(context.Context) RelayStatus {
	return RelayStatus{Enabled: true, Available: true, ProviderID: "accepting-provider", Summary: "accepting provider"}
}

func (p *acceptingRelayProvider) PublishEndpointHint(context.Context, EndpointHint) error { return nil }

func (p *acceptingRelayProvider) ListEndpointHints(context.Context, EndpointHintQuery) ([]EndpointHint, error) {
	p.listCalled = true
	return nil, nil
}

func (p *acceptingRelayProvider) OpenMailbox(context.Context, MailboxOpenRequest) (MailboxRef, error) {
	return MailboxRef{}, ErrProviderUnavailable
}

func (p *acceptingRelayProvider) SendEnvelope(context.Context, RelayEnvelope) (DeliveryReceipt, error) {
	p.sendCalled = true
	return DeliveryReceipt{Accepted: true, Delivered: true, Summary: "accepted"}, nil
}

func (p *acceptingRelayProvider) ReceiveEnvelopes(context.Context, MailboxRef) ([]RelayEnvelope, error) {
	return nil, nil
}

type acceptingRendezvousProvider struct {
	queryCalled bool
}

func (p *acceptingRendezvousProvider) Announce(context.Context, RendezvousAnnouncement) error {
	return nil
}

func (p *acceptingRendezvousProvider) Query(context.Context, RendezvousQuery) ([]RendezvousPeerHint, error) {
	p.queryCalled = true
	return nil, nil
}

func (p *acceptingRendezvousProvider) Revoke(context.Context, RendezvousRevokeRequest) error {
	return nil
}

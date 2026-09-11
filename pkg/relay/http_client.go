package relay

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"strings"
)

type HTTPRelayClientConfig struct {
	BaseURL         string
	HTTPClient      *http.Client
	Bearer          string
	ProviderID      string
	MaxPayloadBytes int
}

// HTTPRelayClient is an HTTP-backed RelayProvider and RendezvousProvider. It
// maps network and server failures to sanitized relay sentinel errors.
type HTTPRelayClient struct {
	baseURL    string
	client     *http.Client
	bearer     string
	providerID string
	maxPayload int
}

func NewHTTPRelayClient(config HTTPRelayClientConfig) (*HTTPRelayClient, error) {
	base := strings.TrimRight(strings.TrimSpace(config.BaseURL), "/")
	parsed, err := url.Parse(base)
	if err != nil || parsed.Host == "" || parsed.User != nil || parsed.RawQuery != "" || parsed.Fragment != "" {
		return nil, ErrInvalidConfig
	}
	if parsed.Scheme != "http" && parsed.Scheme != "https" {
		return nil, ErrInvalidConfig
	}
	providerID := config.ProviderID
	if providerID == "" {
		providerID = defaultHTTPRelayProviderID
	}
	if !validID(providerID) {
		return nil, ErrInvalidConfig
	}
	maxPayload := config.MaxPayloadBytes
	if maxPayload <= 0 {
		maxPayload = DefaultMaxPayloadSize
	}
	client := config.HTTPClient
	if client == nil {
		client = &http.Client{Timeout: defaultHTTPRelayTimeout}
	}
	return &HTTPRelayClient{baseURL: base, client: client, bearer: strings.TrimSpace(config.Bearer), providerID: providerID, maxPayload: maxPayload}, nil
}

func (c *HTTPRelayClient) GetStatus(ctx context.Context) RelayStatus {
	var status RelayStatus
	if err := c.doJSON(ctx, http.MethodGet, "/status", nil, &status); err != nil {
		return RelayStatus{Enabled: true, Available: false, ProviderID: c.safeProviderID(), Summary: "network relay is unavailable", Issues: []RelayIssue{{Code: "network_relay_unavailable", Message: SanitizeProviderError(err).Error(), Blocking: false}}}
	}
	status.Enabled = true
	status.ProviderID = safeID(status.ProviderID, c.safeProviderID())
	status.Summary = safeSummary(status.Summary, "network relay status is available")
	for i, issue := range status.Issues {
		status.Issues[i] = RelayIssue{Code: safeID(issue.Code, "network_relay_issue"), Message: safeSummary(issue.Message, ErrProviderUnavailable.Error()), Blocking: false}
	}
	return status
}

func (c *HTTPRelayClient) PublishEndpointHint(ctx context.Context, hint EndpointHint) error {
	if err := ValidateEndpointHint(hint); err != nil {
		return err
	}
	return c.doJSON(ctx, http.MethodPost, "/endpoint-hints", hint, nil)
}

func (c *HTTPRelayClient) ListEndpointHints(ctx context.Context, query EndpointHintQuery) ([]EndpointHint, error) {
	if !validNamespace(query.Namespace) {
		return nil, ErrInvalidNamespace
	}
	if query.DeviceID != "" && !validDeviceID(query.DeviceID) {
		return nil, ErrInvalidDeviceID
	}
	var out []EndpointHint
	if err := c.doJSON(ctx, http.MethodGet, "/endpoint-hints?namespace="+url.QueryEscape(query.Namespace)+"&device_id="+url.QueryEscape(query.DeviceID), nil, &out); err != nil {
		return nil, err
	}
	for _, hint := range out {
		if err := ValidateEndpointHint(hint); err != nil {
			return nil, ErrProviderUnavailable
		}
	}
	return out, nil
}

func (c *HTTPRelayClient) RevokeEndpointHint(ctx context.Context, request EndpointHintRevokeRequest) error {
	if !validNamespace(request.Namespace) {
		return ErrInvalidNamespace
	}
	if !validDeviceID(request.DeviceID) {
		return ErrInvalidDeviceID
	}
	if !validID(request.EndpointID) {
		return ErrInvalidEndpointHint
	}
	return c.doJSON(ctx, http.MethodPost, "/endpoint-hints/revoke", request, nil)
}

func (c *HTTPRelayClient) Announce(ctx context.Context, announcement RendezvousAnnouncement) error {
	if err := ValidateRendezvousAnnouncement(announcement); err != nil {
		return err
	}
	return c.doJSON(ctx, http.MethodPost, "/rendezvous", announcement, nil)
}

func (c *HTTPRelayClient) Query(ctx context.Context, query RendezvousQuery) ([]RendezvousPeerHint, error) {
	if !validNamespace(query.Namespace) {
		return nil, ErrInvalidNamespace
	}
	if query.ProfileID != "" && !validID(query.ProfileID) {
		return nil, ErrInvalidRendezvous
	}
	if query.DeviceID != "" && !validDeviceID(query.DeviceID) {
		return nil, ErrInvalidDeviceID
	}
	path := "/rendezvous?namespace=" + url.QueryEscape(query.Namespace) + "&profile_id=" + url.QueryEscape(query.ProfileID) + "&device_id=" + url.QueryEscape(query.DeviceID)
	var out []RendezvousPeerHint
	if err := c.doJSON(ctx, http.MethodGet, path, nil, &out); err != nil {
		return nil, err
	}
	for _, peer := range out {
		if err := validateRendezvousPeerHint(peer); err != nil {
			return nil, ErrProviderUnavailable
		}
	}
	return out, nil
}

func (c *HTTPRelayClient) Revoke(ctx context.Context, request RendezvousRevokeRequest) error {
	if !validNamespace(request.Namespace) {
		return ErrInvalidNamespace
	}
	if !validDeviceID(request.DeviceID) || !validID(request.AnnouncementID) {
		return ErrInvalidRendezvous
	}
	return c.doJSON(ctx, http.MethodPost, "/rendezvous/revoke", request, nil)
}

func (c *HTTPRelayClient) OpenMailbox(ctx context.Context, request MailboxOpenRequest) (MailboxRef, error) {
	if err := ValidateMailboxOpenRequest(request); err != nil {
		return MailboxRef{}, err
	}
	var ref MailboxRef
	if err := c.doJSON(ctx, http.MethodPost, "/mailboxes", request, &ref); err != nil {
		return MailboxRef{}, err
	}
	if err := ValidateMailboxRef(ref); err != nil {
		return MailboxRef{}, ErrProviderUnavailable
	}
	return ref, nil
}

func (c *HTTPRelayClient) SendEnvelope(ctx context.Context, envelope RelayEnvelope) (DeliveryReceipt, error) {
	if err := ValidateEnvelopeWithLimit(envelope, c.maxPayload); err != nil {
		return DeliveryReceipt{}, err
	}
	var receipt DeliveryReceipt
	err := c.doJSON(ctx, http.MethodPost, "/envelopes", envelope, &receipt)
	if err != nil {
		return DeliveryReceipt{}, err
	}
	receipt.Summary = safeSummary(receipt.Summary, "network relay accepted envelope metadata")
	return receipt, nil
}

func (c *HTTPRelayClient) ReceiveEnvelopes(ctx context.Context, mailbox MailboxRef) ([]RelayEnvelope, error) {
	if err := ValidateMailboxRef(mailbox); err != nil {
		return nil, err
	}
	var out []RelayEnvelope
	if err := c.doJSON(ctx, http.MethodPost, "/envelopes/receive", mailbox, &out); err != nil {
		return nil, err
	}
	if len(out) > maxReceivePageCount {
		return nil, ErrProviderUnavailable
	}
	for _, envelope := range out {
		if err := ValidateEnvelopeWithLimit(envelope, c.maxPayload); err != nil {
			return nil, ErrProviderUnavailable
		}
	}
	return out, nil
}

func (c *HTTPRelayClient) doJSON(ctx context.Context, method, path string, in any, out any) error {
	if c == nil || c.client == nil || c.baseURL == "" {
		return ErrProviderUnavailable
	}
	var body io.Reader
	if in != nil {
		raw, err := json.Marshal(in)
		if err != nil {
			return ErrProviderUnavailable
		}
		body = bytes.NewReader(raw)
	}
	req, err := http.NewRequestWithContext(ctx, method, c.baseURL+path, body)
	if err != nil {
		return ErrProviderUnavailable
	}
	if in != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	req.Header.Set("Accept", "application/json")
	if c.bearer != "" {
		req.Header.Set("Authorization", "Bearer "+c.bearer)
	}
	resp, err := c.client.Do(req)
	if err != nil {
		return SanitizeProviderError(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return relayHTTPError(resp.Body, resp.StatusCode)
	}
	if out == nil {
		return nil
	}
	limit := int64(c.maxPayload) * 2
	if path == "/envelopes/receive" {
		limit = maxReceivePageBytes
	}
	if err := decodeBoundedJSON(resp.Body, limit, out, false); err != nil {
		return ErrProviderUnavailable
	}
	return nil
}

func (c *HTTPRelayClient) safeProviderID() string {
	if c == nil {
		return defaultHTTPRelayProviderID
	}
	return safeID(c.providerID, defaultHTTPRelayProviderID)
}

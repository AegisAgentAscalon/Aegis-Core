package relay

import (
	"bytes"
	"context"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

const defaultHTTPRelayProviderID = "http-relay"
const defaultHTTPRelayTimeout = 15 * time.Second

// HTTPRelayAuthorizer is a narrow access-control seam for self-hosted relay
// endpoints. Authorization permits relay API access only; it is not device
// trust, profile truth, or sync authority.
type HTTPRelayAuthorizer interface {
	AuthorizeRelayRequest(r *http.Request) bool
}

// BearerRelayAuthorizer checks a static bearer credential for self-hosted
// deployments. Callers own credential provisioning and rotation.
type BearerRelayAuthorizer struct {
	Bearer string
}

func (a BearerRelayAuthorizer) AuthorizeRelayRequest(r *http.Request) bool {
	expected := strings.TrimSpace(a.Bearer)
	if expected == "" {
		return false
	}
	got := strings.TrimSpace(r.Header.Get("Authorization"))
	if !strings.HasPrefix(got, "Bearer ") {
		return false
	}
	token := strings.TrimSpace(strings.TrimPrefix(got, "Bearer "))
	return subtle.ConstantTimeCompare([]byte(token), []byte(expected)) == 1
}

// EndpointHintRevokeProvider is implemented by relay providers that can remove
// previously published endpoint hints.
type EndpointHintRevokeProvider interface {
	RevokeEndpointHint(ctx context.Context, request EndpointHintRevokeRequest) error
}

// HTTPRelayHandlerConfig configures the self-hostable HTTP relay handler.
// If Provider is nil, the handler creates an in-memory LocalDevProvider.
type HTTPRelayHandlerConfig struct {
	Provider           RelayProvider
	Rendezvous         RendezvousProvider
	EndpointHintRevoke EndpointHintRevokeProvider
	Authorizer         HTTPRelayAuthorizer
	// AllowUnauthenticated must be set intentionally for local/dev handlers
	// that should accept relay traffic without an Authorizer.
	AllowUnauthenticated bool
	ProviderID           string
	MaxPayloadBytes      int
	Clock                Clock
	MaxRequestBodyBytes  int64
}

// NewHTTPRelayHandler returns a self-hostable HTTP handler for relay provider
// contracts. It is suitable for local, LAN, or caller-managed deployments; it
// is not a managed relay service and does not implement NAT traversal.
func NewHTTPRelayHandler(config HTTPRelayHandlerConfig) (http.Handler, error) {
	if config.Authorizer == nil && !config.AllowUnauthenticated {
		return nil, ErrInvalidConfig
	}
	provider := config.Provider
	rendezvous := config.Rendezvous
	revoke := config.EndpointHintRevoke
	providerID := config.ProviderID
	if providerID == "" {
		providerID = defaultHTTPRelayProviderID
	}
	if !validID(providerID) {
		return nil, ErrInvalidConfig
	}
	if provider == nil {
		local, err := NewLocalDevProvider(LocalDevProviderConfig{ProviderID: providerID, MaxPayloadBytes: config.MaxPayloadBytes, Clock: config.Clock})
		if err != nil {
			return nil, err
		}
		provider = local
		rendezvous = local
		revoke = local
	}
	if rendezvous == nil {
		rendezvous = providerAsRendezvous(provider)
	}
	if revoke == nil {
		revoke = providerAsEndpointHintRevoke(provider)
	}
	maxPayload := config.MaxPayloadBytes
	if maxPayload <= 0 {
		maxPayload = DefaultMaxPayloadSize
	}
	limit := config.MaxRequestBodyBytes
	if limit <= 0 {
		limit = int64(maxPayload * 2)
	}
	server := &httpRelayHandler{provider: provider, rendezvous: rendezvous, endpointHintRevoke: revoke, authorizer: config.Authorizer, maxRequestBody: limit, maxPayload: maxPayload}
	mux := http.NewServeMux()
	mux.HandleFunc("/status", server.status)
	mux.HandleFunc("/endpoint-hints", server.endpointHints)
	mux.HandleFunc("/endpoint-hints/revoke", server.endpointHintRevokeHandler)
	mux.HandleFunc("/rendezvous", server.rendezvousHandler)
	mux.HandleFunc("/rendezvous/revoke", server.rendezvousRevokeHandler)
	mux.HandleFunc("/mailboxes", server.mailboxes)
	mux.HandleFunc("/envelopes", server.envelopes)
	mux.HandleFunc("/envelopes/receive", server.receiveEnvelopes)
	return server.withAccessControl(mux), nil
}

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
	if err != nil || parsed.Scheme == "" || parsed.Host == "" {
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
	dec := json.NewDecoder(io.LimitReader(resp.Body, int64(c.maxPayload*2)))
	if err := dec.Decode(out); err != nil {
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

type httpRelayHandler struct {
	provider           RelayProvider
	rendezvous         RendezvousProvider
	endpointHintRevoke EndpointHintRevokeProvider
	authorizer         HTTPRelayAuthorizer
	maxRequestBody     int64
	maxPayload         int
}

func (h *httpRelayHandler) withAccessControl(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if h.authorizer != nil && !h.authorizer.AuthorizeRelayRequest(r) {
			writeRelayError(w, http.StatusUnauthorized, ErrProviderUnavailable)
			return
		}
		next.ServeHTTP(w, r)
	})
}

func (h *httpRelayHandler) status(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeRelayError(w, http.StatusMethodNotAllowed, ErrInvalidConfig)
		return
	}
	status := h.provider.GetStatus(r.Context())
	status.Enabled = true
	status.ProviderID = safeID(status.ProviderID, defaultHTTPRelayProviderID)
	status.Summary = safeSummary(status.Summary, "network relay status is available")
	for i, issue := range status.Issues {
		status.Issues[i] = RelayIssue{Code: safeID(issue.Code, "network_relay_issue"), Message: safeSummary(issue.Message, ErrProviderUnavailable.Error()), Blocking: false}
	}
	writeRelayJSON(w, http.StatusOK, status)
}

func (h *httpRelayHandler) endpointHints(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodPost:
		var hint EndpointHint
		if !h.decode(w, r, &hint) {
			return
		}
		if err := h.provider.PublishEndpointHint(r.Context(), hint); err != nil {
			writeRelayError(w, statusForRelayError(err), err)
			return
		}
		writeRelayJSON(w, http.StatusOK, map[string]bool{"accepted": true})
	case http.MethodGet:
		query := EndpointHintQuery{Namespace: r.URL.Query().Get("namespace"), DeviceID: r.URL.Query().Get("device_id")}
		hints, err := h.provider.ListEndpointHints(r.Context(), query)
		if err != nil {
			writeRelayError(w, statusForRelayError(err), err)
			return
		}
		writeRelayJSON(w, http.StatusOK, hints)
	default:
		writeRelayError(w, http.StatusMethodNotAllowed, ErrInvalidConfig)
	}
}

func (h *httpRelayHandler) endpointHintRevokeHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeRelayError(w, http.StatusMethodNotAllowed, ErrInvalidConfig)
		return
	}
	if h.endpointHintRevoke == nil {
		writeRelayError(w, http.StatusNotImplemented, ErrProviderUnavailable)
		return
	}
	var req EndpointHintRevokeRequest
	if !h.decode(w, r, &req) {
		return
	}
	if err := h.endpointHintRevoke.RevokeEndpointHint(r.Context(), req); err != nil {
		writeRelayError(w, statusForRelayError(err), err)
		return
	}
	writeRelayJSON(w, http.StatusOK, map[string]bool{"revoked": true})
}

func (h *httpRelayHandler) rendezvousHandler(w http.ResponseWriter, r *http.Request) {
	if h.rendezvous == nil {
		writeRelayError(w, http.StatusNotImplemented, ErrProviderUnavailable)
		return
	}
	switch r.Method {
	case http.MethodPost:
		var announcement RendezvousAnnouncement
		if !h.decode(w, r, &announcement) {
			return
		}
		if err := h.rendezvous.Announce(r.Context(), announcement); err != nil {
			writeRelayError(w, statusForRelayError(err), err)
			return
		}
		writeRelayJSON(w, http.StatusOK, map[string]bool{"accepted": true})
	case http.MethodGet:
		query := RendezvousQuery{Namespace: r.URL.Query().Get("namespace"), ProfileID: r.URL.Query().Get("profile_id"), DeviceID: r.URL.Query().Get("device_id")}
		peers, err := h.rendezvous.Query(r.Context(), query)
		if err != nil {
			writeRelayError(w, statusForRelayError(err), err)
			return
		}
		writeRelayJSON(w, http.StatusOK, peers)
	default:
		writeRelayError(w, http.StatusMethodNotAllowed, ErrInvalidConfig)
	}
}

func (h *httpRelayHandler) rendezvousRevokeHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeRelayError(w, http.StatusMethodNotAllowed, ErrInvalidConfig)
		return
	}
	if h.rendezvous == nil {
		writeRelayError(w, http.StatusNotImplemented, ErrProviderUnavailable)
		return
	}
	var req RendezvousRevokeRequest
	if !h.decode(w, r, &req) {
		return
	}
	if err := h.rendezvous.Revoke(r.Context(), req); err != nil {
		writeRelayError(w, statusForRelayError(err), err)
		return
	}
	writeRelayJSON(w, http.StatusOK, map[string]bool{"revoked": true})
}

func (h *httpRelayHandler) mailboxes(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeRelayError(w, http.StatusMethodNotAllowed, ErrInvalidConfig)
		return
	}
	var req MailboxOpenRequest
	if !h.decode(w, r, &req) {
		return
	}
	ref, err := h.provider.OpenMailbox(r.Context(), req)
	if err != nil {
		writeRelayError(w, statusForRelayError(err), err)
		return
	}
	writeRelayJSON(w, http.StatusOK, ref)
}

func (h *httpRelayHandler) envelopes(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeRelayError(w, http.StatusMethodNotAllowed, ErrInvalidConfig)
		return
	}
	var envelope RelayEnvelope
	if !h.decode(w, r, &envelope) {
		return
	}
	if err := ValidateEnvelopeWithLimit(envelope, h.maxPayload); err != nil {
		writeRelayError(w, statusForRelayError(err), err)
		return
	}
	receipt, err := h.provider.SendEnvelope(r.Context(), envelope)
	if err != nil {
		writeRelayError(w, statusForRelayError(err), err)
		return
	}
	receipt.Summary = safeSummary(receipt.Summary, "network relay accepted envelope metadata")
	writeRelayJSON(w, http.StatusOK, receipt)
}

func (h *httpRelayHandler) receiveEnvelopes(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeRelayError(w, http.StatusMethodNotAllowed, ErrInvalidConfig)
		return
	}
	var mailbox MailboxRef
	if !h.decode(w, r, &mailbox) {
		return
	}
	envelopes, err := h.provider.ReceiveEnvelopes(r.Context(), mailbox)
	if err != nil {
		writeRelayError(w, statusForRelayError(err), err)
		return
	}
	writeRelayJSON(w, http.StatusOK, envelopes)
}

func (h *httpRelayHandler) decode(w http.ResponseWriter, r *http.Request, out any) bool {
	if r.Body == nil {
		writeRelayError(w, http.StatusBadRequest, ErrInvalidConfig)
		return false
	}
	defer r.Body.Close()
	r.Body = http.MaxBytesReader(w, r.Body, h.maxRequestBody)
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()
	if err := dec.Decode(out); err != nil {
		writeRelayError(w, http.StatusBadRequest, ErrInvalidConfig)
		return false
	}
	var trailing any
	if err := dec.Decode(&trailing); !errors.Is(err, io.EOF) {
		writeRelayError(w, http.StatusBadRequest, ErrInvalidConfig)
		return false
	}
	return true
}

type relayHTTPErrorBody struct {
	Code    string `json:"code"`
	Message string `json:"message"`
}

func writeRelayError(w http.ResponseWriter, status int, err error) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(relayHTTPErrorBody{Code: codeForRelayError(err), Message: messageForRelayError(err)})
}

func writeRelayJSON(w http.ResponseWriter, status int, value any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(value)
}

func relayHTTPError(body io.Reader, status int) error {
	var safe relayHTTPErrorBody
	_ = json.NewDecoder(io.LimitReader(body, 4096)).Decode(&safe)
	if err := errorForRelayCode(safe.Code); err != nil {
		return err
	}
	switch status {
	case http.StatusBadRequest:
		return ErrInvalidConfig
	case http.StatusUnauthorized, http.StatusForbidden, http.StatusInternalServerError, http.StatusBadGateway, http.StatusServiceUnavailable, http.StatusGatewayTimeout:
		return ErrProviderUnavailable
	case http.StatusNotFound:
		return ErrMailboxNotFound
	case http.StatusConflict:
		return ErrDuplicateEnvelope
	case http.StatusRequestEntityTooLarge:
		return ErrPayloadTooLarge
	default:
		return ErrProviderUnavailable
	}
}

func statusForRelayError(err error) int {
	switch {
	case errors.Is(err, ErrDuplicateEnvelope):
		return http.StatusConflict
	case errors.Is(err, ErrMailboxNotFound):
		return http.StatusNotFound
	case errors.Is(err, ErrMailboxExpired), errors.Is(err, ErrEnvelopeExpired), errors.Is(err, ErrExpiredEndpointHint), errors.Is(err, ErrStaleRendezvous):
		return http.StatusGone
	case errors.Is(err, ErrPayloadTooLarge):
		return http.StatusRequestEntityTooLarge
	case errors.Is(err, ErrProviderTimeout):
		return http.StatusGatewayTimeout
	case errors.Is(err, ErrProviderUnavailable), errors.Is(err, ErrDisabled), errors.Is(err, ErrContextCanceled):
		return http.StatusServiceUnavailable
	default:
		return http.StatusBadRequest
	}
}

func codeForRelayError(err error) string {
	switch {
	case errors.Is(err, ErrInvalidNamespace):
		return "invalid_namespace"
	case errors.Is(err, ErrInvalidDeviceID):
		return "invalid_device_id"
	case errors.Is(err, ErrInvalidEndpointHint):
		return "invalid_endpoint_hint"
	case errors.Is(err, ErrExpiredEndpointHint):
		return "expired_endpoint_hint"
	case errors.Is(err, ErrInvalidRendezvous):
		return "invalid_rendezvous"
	case errors.Is(err, ErrStaleRendezvous):
		return "stale_rendezvous"
	case errors.Is(err, ErrInvalidMailbox):
		return "invalid_mailbox"
	case errors.Is(err, ErrMailboxNotFound):
		return "mailbox_not_found"
	case errors.Is(err, ErrMailboxExpired):
		return "mailbox_expired"
	case errors.Is(err, ErrInvalidEnvelope):
		return "invalid_envelope"
	case errors.Is(err, ErrEnvelopeExpired):
		return "envelope_expired"
	case errors.Is(err, ErrUnsupportedProtocolVersion):
		return "unsupported_protocol_version"
	case errors.Is(err, ErrPayloadTooLarge):
		return "payload_too_large"
	case errors.Is(err, ErrMissingPayloadHash):
		return "missing_payload_hash"
	case errors.Is(err, ErrPayloadHashMismatch):
		return "payload_hash_mismatch"
	case errors.Is(err, ErrInvalidMetadata):
		return "invalid_metadata"
	case errors.Is(err, ErrDuplicateEnvelope):
		return "duplicate_envelope"
	case errors.Is(err, ErrProviderTimeout):
		return "provider_timeout"
	case errors.Is(err, ErrContextCanceled):
		return "context_canceled"
	case errors.Is(err, ErrDisabled):
		return "relay_disabled"
	case errors.Is(err, ErrProviderUnavailable):
		return "provider_unavailable"
	default:
		return "relay_error"
	}
}

func messageForRelayError(err error) string {
	if mapped := errorForRelayCode(codeForRelayError(err)); mapped != nil {
		return mapped.Error()
	}
	return ErrProviderUnavailable.Error()
}

func errorForRelayCode(code string) error {
	switch safeID(code, "") {
	case "invalid_namespace":
		return ErrInvalidNamespace
	case "invalid_device_id":
		return ErrInvalidDeviceID
	case "invalid_endpoint_hint":
		return ErrInvalidEndpointHint
	case "expired_endpoint_hint":
		return ErrExpiredEndpointHint
	case "invalid_rendezvous":
		return ErrInvalidRendezvous
	case "stale_rendezvous":
		return ErrStaleRendezvous
	case "invalid_mailbox":
		return ErrInvalidMailbox
	case "mailbox_not_found":
		return ErrMailboxNotFound
	case "mailbox_expired":
		return ErrMailboxExpired
	case "invalid_envelope":
		return ErrInvalidEnvelope
	case "envelope_expired":
		return ErrEnvelopeExpired
	case "unsupported_protocol_version":
		return ErrUnsupportedProtocolVersion
	case "payload_too_large":
		return ErrPayloadTooLarge
	case "missing_payload_hash":
		return ErrMissingPayloadHash
	case "payload_hash_mismatch":
		return ErrPayloadHashMismatch
	case "invalid_metadata":
		return ErrInvalidMetadata
	case "duplicate_envelope":
		return ErrDuplicateEnvelope
	case "provider_timeout":
		return ErrProviderTimeout
	case "context_canceled":
		return ErrContextCanceled
	case "relay_disabled":
		return ErrDisabled
	case "provider_unavailable":
		return ErrProviderUnavailable
	default:
		return nil
	}
}

func validateRendezvousPeerHint(peer RendezvousPeerHint) error {
	if !validNamespace(peer.Namespace) {
		return ErrInvalidNamespace
	}
	if !validDeviceID(peer.DeviceID) {
		return ErrInvalidDeviceID
	}
	if peer.ProfileID != "" && !validID(peer.ProfileID) {
		return ErrInvalidRendezvous
	}
	if err := validateTimes(peer.LastSeen, peer.ExpiresAt, time.Now().UTC(), ErrStaleRendezvous); err != nil {
		return err
	}
	if err := ValidateMetadata(peer.Metadata); err != nil {
		return err
	}
	for _, hint := range peer.EndpointHints {
		if err := ValidateEndpointHint(hint); err != nil {
			return err
		}
		if hint.Namespace != peer.Namespace || hint.DeviceID != peer.DeviceID {
			return ErrInvalidRendezvous
		}
	}
	return nil
}

func providerAsRendezvous(provider RelayProvider) RendezvousProvider {
	if out, ok := provider.(RendezvousProvider); ok {
		return out
	}
	return nil
}

func providerAsEndpointHintRevoke(provider RelayProvider) EndpointHintRevokeProvider {
	if out, ok := provider.(EndpointHintRevokeProvider); ok {
		return out
	}
	return nil
}

func safeID(value, fallback string) string {
	value = strings.TrimSpace(value)
	if validID(value) {
		return value
	}
	return fallback
}

func safeSummary(value, fallback string) string {
	value = strings.TrimSpace(value)
	if value == "" || containsUnsafeDetail(value) {
		return fallback
	}
	return value
}

var _ RelayProvider = (*HTTPRelayClient)(nil)
var _ RendezvousProvider = (*HTTPRelayClient)(nil)
var _ EndpointHintRevokeProvider = (*HTTPRelayClient)(nil)

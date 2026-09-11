package relay

import (
	"errors"
	"net/http"
)

// HTTPRelayHandlerConfig configures the self-hostable HTTP relay handler.
// If Provider is nil, the handler creates an in-memory LocalDevProvider.
type HTTPRelayHandlerConfig struct {
	Provider           RelayProvider
	Rendezvous         RendezvousProvider
	EndpointHintRevoke EndpointHintRevokeProvider
	Authorizer         HTTPRelayAuthorizer
	// AllowUnauthenticated must be set intentionally for local/dev handlers
	// that should accept relay traffic without an Authorizer. Access control is
	// route-wide, including /status, so public health checks need a separate
	// caller-owned handler.
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
		if !validNamespace(query.Namespace) {
			writeRelayError(w, statusForRelayError(ErrInvalidNamespace), ErrInvalidNamespace)
			return
		}
		if query.DeviceID != "" && !validDeviceID(query.DeviceID) {
			writeRelayError(w, statusForRelayError(ErrInvalidDeviceID), ErrInvalidDeviceID)
			return
		}
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
		if !validNamespace(query.Namespace) {
			writeRelayError(w, statusForRelayError(ErrInvalidNamespace), ErrInvalidNamespace)
			return
		}
		if query.ProfileID != "" && !validID(query.ProfileID) {
			writeRelayError(w, statusForRelayError(ErrInvalidRendezvous), ErrInvalidRendezvous)
			return
		}
		if query.DeviceID != "" && !validDeviceID(query.DeviceID) {
			writeRelayError(w, statusForRelayError(ErrInvalidDeviceID), ErrInvalidDeviceID)
			return
		}
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
	err := decodeBoundedJSON(r.Body, h.maxRequestBody, out, true)
	if errors.Is(err, ErrPayloadTooLarge) {
		writeRelayError(w, http.StatusRequestEntityTooLarge, ErrPayloadTooLarge)
		return false
	}
	if err != nil {
		writeRelayError(w, http.StatusBadRequest, ErrInvalidConfig)
		return false
	}
	return true
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

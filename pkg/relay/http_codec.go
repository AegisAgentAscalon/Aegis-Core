package relay

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strings"
	"time"
)

const defaultHTTPRelayProviderID = "http-relay"

const defaultHTTPRelayTimeout = 15 * time.Second

// EndpointHintRevokeProvider is implemented by relay providers that can remove
// previously published endpoint hints.
type EndpointHintRevokeProvider interface {
	RevokeEndpointHint(ctx context.Context, request EndpointHintRevokeRequest) error
}

func decodeBoundedJSON(r io.Reader, limit int64, out any, disallowUnknown bool) error {
	if r == nil || limit <= 0 {
		return ErrInvalidConfig
	}
	payload, err := io.ReadAll(io.LimitReader(r, limit+1))
	if err != nil {
		return ErrProviderUnavailable
	}
	if int64(len(payload)) > limit {
		return ErrPayloadTooLarge
	}
	dec := json.NewDecoder(bytes.NewReader(payload))
	if disallowUnknown {
		dec.DisallowUnknownFields()
	}
	if err := dec.Decode(out); err != nil {
		return ErrInvalidConfig
	}
	var trailing any
	if err := dec.Decode(&trailing); !errors.Is(err, io.EOF) {
		return ErrInvalidConfig
	}
	return nil
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

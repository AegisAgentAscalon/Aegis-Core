package relay

import (
	"context"
	"net/http"
)

// ReliableRelayAuthorizer must authenticate credentials from r and authorize
// that principal for action (send/receive/ack), the exact mailbox lifetime and,
// for send, the asserted source device. Request fields and receipts are not
// credentials. Core delegates membership policy to this trusted host callback.
type ReliableRelayAuthorizer func(r *http.Request, action string, mailbox ReliableMailboxRef, sourceDeviceID string) bool

type ReliableRelayHandlerConfig struct {
	Provider  ReliableRelayProvider
	Authorize ReliableRelayAuthorizer
}

// NewReliableRelayHandler exposes only v2 routes and has no unauthenticated or
// destructive fallback. Mailbox provisioning remains a trusted host operation.
func NewReliableRelayHandler(cfg ReliableRelayHandlerConfig) (http.Handler, error) {
	if cfg.Provider == nil || cfg.Authorize == nil {
		return nil, ErrInvalidConfig
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			writeRelayError(w, http.StatusMethodNotAllowed, ErrInvalidConfig)
			return
		}
		decode := func(out any) bool {
			err := decodeBoundedJSON(r.Body, ReliableBatchBytes, out, true)
			if err != nil {
				writeRelayError(w, statusForRelayError(err), err)
				return false
			}
			return true
		}
		authorize := func(version int, action string, ref ReliableMailboxRef, source string) bool {
			if err := reliableRequest(version, ref); err != nil {
				writeRelayError(w, statusForRelayError(err), err)
				return false
			}
			if !cfg.Authorize(r, action, ref, source) {
				writeRelayError(w, http.StatusForbidden, ErrProviderUnavailable)
				return false
			}
			return true
		}
		var out any
		var err error
		switch r.URL.Path {
		case "/v2/envelopes":
			var req ReliableSendRequest
			if !decode(&req) || !authorize(req.ProtocolVersion, "send", req.Mailbox, req.Envelope.SourceDeviceID) {
				return
			}
			var result ReliableSendResult
			result, err = cfg.Provider.SendReliableEnvelope(r.Context(), req)
			if err == nil {
				err = validateReliableSend(req, result)
			}
			out = result
		case "/v2/mailboxes/receive":
			var req ReceiveBatchRequest
			if !decode(&req) || !authorize(req.ProtocolVersion, "receive", req.Mailbox, "") {
				return
			}
			if _, err = receiveLimit(req); err != nil {
				break
			}
			var result ReceiveBatchResult
			result, err = cfg.Provider.ReceiveBatch(r.Context(), req)
			if err == nil {
				err = ValidateReliableBatch(req, result)
			}
			out = result
		case "/v2/mailboxes/ack":
			var req AcknowledgeBatchRequest
			if !decode(&req) || !authorize(req.ProtocolVersion, "ack", req.Mailbox, "") {
				return
			}
			if err = ackRequest(req); err != nil {
				break
			}
			var result AcknowledgeBatchResult
			result, err = cfg.Provider.AcknowledgeBatch(r.Context(), req)
			if err == nil {
				err = validateAcknowledgement(req, result)
			}
			out = result
		default:
			writeRelayError(w, http.StatusNotFound, ErrUnsupportedProtocolVersion)
			return
		}
		if err != nil {
			writeRelayError(w, statusForRelayError(err), err)
			return
		}
		raw, err := encodedReliable(out)
		if err != nil {
			writeRelayError(w, statusForRelayError(err), err)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		// A failed response never acknowledges a receive. Send/ack ambiguity is
		// resolved by persisted identities on the caller's explicit retry.
		_, _ = w.Write(raw)
	}), nil
}

func validateReliableSend(req ReliableSendRequest, result ReliableSendResult) error {
	digest, err := ReliableEnvelopeDigest(req.Envelope)
	if err != nil || result.ProtocolVersion != 2 || result.Mailbox != req.Mailbox || !reliableID(result.ReceiptID) || result.Digest != digest {
		return ErrInvalidEnvelope
	}
	return nil
}

func reliableContext(ctx context.Context) context.Context {
	if ctx == nil {
		return context.Background()
	}
	return ctx
}

func (c *HTTPRelayClient) SendReliableEnvelope(ctx context.Context, req ReliableSendRequest) (ReliableSendResult, error) {
	if err := reliableRequest(req.ProtocolVersion, req.Mailbox); err != nil {
		return ReliableSendResult{}, err
	}
	var result ReliableSendResult
	if err := c.doJSON(reliableContext(ctx), http.MethodPost, "/v2/envelopes", req, &result); err != nil {
		return result, err
	}
	return result, validateReliableSend(req, result)
}

func (c *HTTPRelayClient) ReceiveBatch(ctx context.Context, req ReceiveBatchRequest) (ReceiveBatchResult, error) {
	if _, err := receiveLimit(req); err != nil {
		return ReceiveBatchResult{}, err
	}
	var result ReceiveBatchResult
	if err := c.doJSON(reliableContext(ctx), http.MethodPost, "/v2/mailboxes/receive", req, &result); err != nil {
		return result, err
	}
	return result, ValidateReliableBatch(req, result)
}

func (c *HTTPRelayClient) AcknowledgeBatch(ctx context.Context, req AcknowledgeBatchRequest) (AcknowledgeBatchResult, error) {
	if err := ackRequest(req); err != nil {
		return AcknowledgeBatchResult{}, err
	}
	var result AcknowledgeBatchResult
	if err := c.doJSON(reliableContext(ctx), http.MethodPost, "/v2/mailboxes/ack", req, &result); err != nil {
		return result, err
	}
	return result, validateAcknowledgement(req, result)
}

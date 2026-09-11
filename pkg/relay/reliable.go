package relay

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"strings"
)

const ReliableProtocolVersion = 2
const ReliableBatchBytes = 1 << 20
const ReliableBatchItems = 64

// ReliableMailboxRef binds receipts to one host-provisioned mailbox lifetime.
// None of these fields is an authentication credential.
type ReliableMailboxRef struct {
	ProviderID    string `json:"provider_id"`
	Namespace     string `json:"namespace"`
	MailboxID     string `json:"mailbox_id"`
	OwnerDeviceID string `json:"owner_device_id"`
	Epoch         string `json:"epoch"`
}

type ReliableSendRequest struct {
	ProtocolVersion int                `json:"protocol_version"`
	Mailbox         ReliableMailboxRef `json:"mailbox"`
	Envelope        RelayEnvelope      `json:"envelope"`
}

type ReliableSendResult struct {
	ProtocolVersion int                `json:"protocol_version"`
	Mailbox         ReliableMailboxRef `json:"mailbox"`
	ReceiptID       string             `json:"receipt_id"`
	Digest          string             `json:"digest"`
}

type ReceiveBatchRequest struct {
	ProtocolVersion int                `json:"protocol_version"`
	Mailbox         ReliableMailboxRef `json:"mailbox"`
	MaxItems        int                `json:"max_items,omitempty"`
	MaxEncodedBytes int                `json:"max_encoded_bytes,omitempty"`
}

type ReliableDelivery struct {
	ReceiptID string        `json:"receipt_id"`
	Digest    string        `json:"digest"`
	Envelope  RelayEnvelope `json:"envelope"`
}

type ReceiveBatchResult struct {
	ProtocolVersion int                `json:"protocol_version"`
	Mailbox         ReliableMailboxRef `json:"mailbox"`
	Items           []ReliableDelivery `json:"items"`
	HasMore         bool               `json:"has_more"`
}

type AcknowledgeBatchRequest struct {
	ProtocolVersion int                `json:"protocol_version"`
	Mailbox         ReliableMailboxRef `json:"mailbox"`
	ReceiptIDs      []string           `json:"receipt_ids"`
}

type AcknowledgeResult struct {
	ReceiptID string `json:"receipt_id"`
	Status    string `json:"status"`
}

type AcknowledgeBatchResult struct {
	ProtocolVersion int                 `json:"protocol_version"`
	Mailbox         ReliableMailboxRef  `json:"mailbox"`
	Results         []AcknowledgeResult `json:"results"`
}

// ReliableRelayProvider is deliberately separate from destructive RelayProvider.
// Direct invocation is host-trusted; HTTP deployments must authorize each action.
type ReliableRelayProvider interface {
	SendReliableEnvelope(context.Context, ReliableSendRequest) (ReliableSendResult, error)
	ReceiveBatch(context.Context, ReceiveBatchRequest) (ReceiveBatchResult, error)
	AcknowledgeBatch(context.Context, AcknowledgeBatchRequest) (AcknowledgeBatchResult, error)
}

func ValidateReliableMailbox(ref ReliableMailboxRef) error {
	for _, part := range []string{ref.ProviderID, ref.Namespace, ref.MailboxID, ref.OwnerDeviceID} {
		if strings.TrimSpace(part) != part {
			return ErrInvalidMailbox
		}
	}
	if !validID(ref.ProviderID) || !validNamespace(ref.Namespace) || !validID(ref.MailboxID) || !validDeviceID(ref.OwnerDeviceID) || !reliableID(ref.Epoch) {
		return ErrInvalidMailbox
	}
	return nil
}

// ReliableEnvelopeDigest hashes encoding/json.Marshal of the typed envelope.
// This is Go JSON encoding, not a cross-language canonical JSON standard.
func ReliableEnvelopeDigest(envelope RelayEnvelope) (string, error) {
	raw, err := json.Marshal(envelope)
	if err != nil {
		return "", ErrInvalidEnvelope
	}
	sum := sha256.Sum256(raw)
	return hex.EncodeToString(sum[:]), nil
}

func reliableID(id string) bool {
	if len(id) != 64 {
		return false
	}
	for _, c := range id {
		if !(c >= '0' && c <= '9' || c >= 'a' && c <= 'f') {
			return false
		}
	}
	return true
}

func reliableRequest(version int, ref ReliableMailboxRef) error {
	if version != ReliableProtocolVersion {
		return ErrUnsupportedProtocolVersion
	}
	return ValidateReliableMailbox(ref)
}

func receiveLimit(req ReceiveBatchRequest) (int, error) {
	if err := reliableRequest(req.ProtocolVersion, req.Mailbox); err != nil {
		return 0, err
	}
	if req.MaxItems < 0 || req.MaxItems > ReliableBatchItems || req.MaxEncodedBytes != 0 && req.MaxEncodedBytes != ReliableBatchBytes {
		return 0, ErrInvalidConfig
	}
	if req.MaxItems == 0 {
		return ReliableBatchItems, nil
	}
	return req.MaxItems, nil
}

func ackRequest(req AcknowledgeBatchRequest) error {
	if err := reliableRequest(req.ProtocolVersion, req.Mailbox); err != nil {
		return err
	}
	if len(req.ReceiptIDs) == 0 || len(req.ReceiptIDs) > ReliableBatchItems {
		return ErrInvalidConfig
	}
	seen := map[string]bool{}
	for _, id := range req.ReceiptIDs {
		if !reliableID(id) || seen[id] {
			return ErrInvalidConfig
		}
		seen[id] = true
	}
	return nil
}

func encodedReliable(value any) ([]byte, error) {
	raw, err := json.Marshal(value)
	if err != nil {
		return nil, ErrInvalidConfig
	}
	if len(raw)+1 > ReliableBatchBytes {
		return nil, ErrPayloadTooLarge
	}
	return append(raw, '\n'), nil
}

// ValidateReliableBatch validates the whole response before a consumer accepts
// any item. Age is a domain disposition, not a reason to discard custody.
func ValidateReliableBatch(req ReceiveBatchRequest, result ReceiveBatchResult) error {
	limit, err := receiveLimit(req)
	if err != nil {
		return err
	}
	if result.ProtocolVersion != ReliableProtocolVersion || result.Mailbox != req.Mailbox || len(result.Items) > limit || result.HasMore && len(result.Items) == 0 {
		return ErrInvalidEnvelope
	}
	if _, err := encodedReliable(result); err != nil {
		return err
	}
	seen := map[string]bool{}
	for _, item := range result.Items {
		digest, err := ReliableEnvelopeDigest(item.Envelope)
		if err != nil || !reliableID(item.ReceiptID) || seen[item.ReceiptID] || digest != item.Digest {
			return ErrInvalidEnvelope
		}
		if !reliableTarget(item.Envelope, req.Mailbox) || validateEnvelopeAt(item.Envelope, ReliableBatchBytes, item.Envelope.CreatedAt) != nil {
			return ErrInvalidEnvelope
		}
		seen[item.ReceiptID] = true
	}
	return nil
}

func reliableTarget(e RelayEnvelope, ref ReliableMailboxRef) bool {
	return e.Namespace == ref.Namespace && e.TargetMailboxID == ref.MailboxID && e.TargetDeviceID == ref.OwnerDeviceID
}

func validateAcknowledgement(req AcknowledgeBatchRequest, result AcknowledgeBatchResult) error {
	if err := ackRequest(req); err != nil {
		return err
	}
	if result.ProtocolVersion != ReliableProtocolVersion || result.Mailbox != req.Mailbox || len(result.Results) != len(req.ReceiptIDs) {
		return ErrInvalidEnvelope
	}
	for i, item := range result.Results {
		if item.ReceiptID != req.ReceiptIDs[i] || item.Status != "acknowledged" && item.Status != "already_acknowledged" && item.Status != "unknown" {
			return ErrInvalidEnvelope
		}
	}
	return nil
}

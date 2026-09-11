package relay

import (
	"context"
	"errors"
	"regexp"
	"time"
)

const (
	ProtocolVersion        = 1
	DefaultMaxPayloadSize  = 64 * 1024
	maxMetadataEntries     = 32
	maxMetadataKeyLength   = 64
	maxMetadataValueLength = 256
	defaultClockSkew       = 2 * time.Minute
)

var (
	ErrDisabled                   = errors.New("relay is disabled")
	ErrInvalidConfig              = errors.New("invalid relay config")
	ErrInvalidNamespace           = errors.New("invalid relay namespace")
	ErrInvalidDeviceID            = errors.New("invalid relay device id")
	ErrInvalidEndpointHint        = errors.New("invalid endpoint hint")
	ErrExpiredEndpointHint        = errors.New("endpoint hint is expired")
	ErrInvalidRendezvous          = errors.New("invalid rendezvous announcement")
	ErrStaleRendezvous            = errors.New("rendezvous announcement is stale")
	ErrInvalidMailbox             = errors.New("invalid relay mailbox")
	ErrMailboxNotFound            = errors.New("relay mailbox is not available")
	ErrMailboxExpired             = errors.New("relay mailbox is expired")
	ErrInvalidEnvelope            = errors.New("invalid relay envelope")
	ErrEnvelopeExpired            = errors.New("relay envelope is expired")
	ErrUnsupportedProtocolVersion = errors.New("unsupported relay protocol version")
	ErrPayloadTooLarge            = errors.New("relay payload is too large")
	ErrMissingPayloadHash         = errors.New("relay payload hash is required")
	ErrPayloadHashMismatch        = errors.New("relay payload hash mismatch")
	ErrInvalidMetadata            = errors.New("invalid relay metadata")
	ErrDuplicateEnvelope          = errors.New("relay envelope was already accepted")
	ErrProviderUnavailable        = errors.New("relay provider unavailable")
	ErrProviderTimeout            = errors.New("relay provider timed out")
	ErrContextCanceled            = errors.New("relay operation canceled")
)

var (
	safeNamePattern     = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9._-]{0,127}$`)
	safeIDPattern       = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9._:-]{0,127}$`)
	safeMetadataKey     = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9._:-]{0,63}$`)
	sha256HexPattern    = regexp.MustCompile(`^[a-fA-F0-9]{64}$`)
	localPathIndicators = []string{`:\`, `/home/`, `/Users/`, `/tmp/`, `\\`}
	secretIndicators    = []string{"access_token", "refresh_token", "id_token", "client_secret", "pkce", "verifier", "private_key", "password", "secret"}
)

type RelayProvider interface {
	GetStatus(ctx context.Context) RelayStatus
	PublishEndpointHint(ctx context.Context, hint EndpointHint) error
	ListEndpointHints(ctx context.Context, query EndpointHintQuery) ([]EndpointHint, error)
	OpenMailbox(ctx context.Context, request MailboxOpenRequest) (MailboxRef, error)
	SendEnvelope(ctx context.Context, envelope RelayEnvelope) (DeliveryReceipt, error)
	ReceiveEnvelopes(ctx context.Context, mailbox MailboxRef) ([]RelayEnvelope, error)
}

type RendezvousProvider interface {
	Announce(ctx context.Context, announcement RendezvousAnnouncement) error
	Query(ctx context.Context, query RendezvousQuery) ([]RendezvousPeerHint, error)
	Revoke(ctx context.Context, request RendezvousRevokeRequest) error
}

type RelayConfig struct {
	Enabled         bool
	Namespace       string
	ProviderID      string
	MaxPayloadBytes int
	ClockSkew       time.Duration
}

type RelayStatus struct {
	Enabled    bool         `json:"enabled"`
	Available  bool         `json:"available"`
	ProviderID string       `json:"provider_id,omitempty"`
	Summary    string       `json:"summary,omitempty"`
	Issues     []RelayIssue `json:"issues,omitempty"`
}

type RelayIssue struct {
	Code     string `json:"code"`
	Message  string `json:"message"`
	Blocking bool   `json:"blocking"`
}

type MessageKind string

const (
	MessageKindDeviceProof  MessageKind = "device_proof"
	MessageKindPresence     MessageKind = "presence"
	MessageKindResourceHint MessageKind = "resource_hint"
	MessageKindMailboxPing  MessageKind = "mailbox_ping"
	MessageKindOpaque       MessageKind = "opaque"
)

type EndpointHint struct {
	ProtocolVersion int               `json:"protocol_version"`
	Namespace       string            `json:"namespace"`
	DeviceID        string            `json:"device_id"`
	EndpointID      string            `json:"endpoint_id"`
	EndpointType    string            `json:"endpoint_type"`
	Address         string            `json:"address,omitempty"`
	ProviderID      string            `json:"provider_id,omitempty"`
	CreatedAt       time.Time         `json:"created_at"`
	ExpiresAt       time.Time         `json:"expires_at"`
	Capabilities    []string          `json:"capabilities,omitempty"`
	Metadata        map[string]string `json:"metadata,omitempty"`
}

type EndpointHintQuery struct {
	Namespace string
	DeviceID  string
	Now       time.Time
}

type RendezvousAnnouncement struct {
	ProtocolVersion int               `json:"protocol_version"`
	Namespace       string            `json:"namespace"`
	ProfileID       string            `json:"profile_id,omitempty"`
	DeviceID        string            `json:"device_id"`
	AnnouncementID  string            `json:"announcement_id"`
	CreatedAt       time.Time         `json:"created_at"`
	ExpiresAt       time.Time         `json:"expires_at"`
	EndpointHints   []EndpointHint    `json:"endpoint_hints,omitempty"`
	Metadata        map[string]string `json:"metadata,omitempty"`
}

type RendezvousQuery struct {
	Namespace string
	ProfileID string
	DeviceID  string
	Now       time.Time
}

type RendezvousPeerHint struct {
	Namespace     string            `json:"namespace"`
	ProfileID     string            `json:"profile_id,omitempty"`
	DeviceID      string            `json:"device_id"`
	EndpointHints []EndpointHint    `json:"endpoint_hints,omitempty"`
	LastSeen      time.Time         `json:"last_seen"`
	ExpiresAt     time.Time         `json:"expires_at"`
	Metadata      map[string]string `json:"metadata,omitempty"`
}

type RendezvousRevokeRequest struct {
	Namespace      string
	DeviceID       string
	AnnouncementID string
}

type MailboxOpenRequest struct {
	Namespace     string
	OwnerDeviceID string
	MailboxID     string
	CreatedAt     time.Time
	ExpiresAt     time.Time
	Metadata      map[string]string
}

type MailboxRef struct {
	Namespace     string            `json:"namespace"`
	MailboxID     string            `json:"mailbox_id"`
	OwnerDeviceID string            `json:"owner_device_id"`
	ProviderID    string            `json:"provider_id,omitempty"`
	ExpiresAt     time.Time         `json:"expires_at"`
	Metadata      map[string]string `json:"metadata,omitempty"`
}

type RelayEnvelopeMetadata struct {
	ProtocolVersion int               `json:"protocol_version"`
	Namespace       string            `json:"namespace"`
	SourceDeviceID  string            `json:"source_device_id"`
	TargetDeviceID  string            `json:"target_device_id,omitempty"`
	TargetMailboxID string            `json:"target_mailbox_id,omitempty"`
	MessageKind     MessageKind       `json:"message_kind"`
	CreatedAt       time.Time         `json:"created_at"`
	ExpiresAt       time.Time         `json:"expires_at"`
	MessageID       string            `json:"message_id"`
	PayloadHash     string            `json:"payload_hash"`
	Metadata        map[string]string `json:"metadata,omitempty"`
}

type RelayEnvelope struct {
	RelayEnvelopeMetadata
	Payload []byte `json:"payload,omitempty"`
}

type DeliveryReceipt struct {
	MessageID  string    `json:"message_id"`
	Accepted   bool      `json:"accepted"`
	Delivered  bool      `json:"delivered"`
	ReceivedAt time.Time `json:"received_at"`
	Summary    string    `json:"summary,omitempty"`
}

type DeliveryAttemptSummary struct {
	MessageID       string    `json:"message_id"`
	AttemptedAt     time.Time `json:"attempted_at"`
	ProviderID      string    `json:"provider_id,omitempty"`
	Accepted        bool      `json:"accepted"`
	Delivered       bool      `json:"delivered"`
	SafeFailureCode string    `json:"safe_failure_code,omitempty"`
}

func DisabledStatus() RelayStatus {
	return RelayStatus{Enabled: false, Available: false, Summary: "relay is disabled"}
}

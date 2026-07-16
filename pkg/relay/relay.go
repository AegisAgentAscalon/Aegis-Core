// Package relay defines optional relay and rendezvous contracts for Aegis setup
// infrastructure. Relay providers are untrusted transport helpers, not trust,
// profile, sync, routing, or resource ownership authorities.
package relay

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"regexp"
	"strings"
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

func PayloadSHA256(payload []byte) string {
	sum := sha256.Sum256(payload)
	return hex.EncodeToString(sum[:])
}

func SanitizeProviderError(err error) error {
	if err == nil {
		return nil
	}
	if errors.Is(err, context.Canceled) {
		return ErrContextCanceled
	}
	if errors.Is(err, context.DeadlineExceeded) {
		return ErrProviderTimeout
	}
	return ErrProviderUnavailable
}

func ValidateConfig(config RelayConfig) error {
	if !config.Enabled {
		return nil
	}
	if !validNamespace(config.Namespace) {
		return ErrInvalidNamespace
	}
	if config.ProviderID != "" && !validID(config.ProviderID) {
		return ErrInvalidConfig
	}
	if config.MaxPayloadBytes < 0 {
		return ErrInvalidConfig
	}
	return nil
}

func ValidateEndpointHint(hint EndpointHint) error {
	return validateEndpointHintAt(hint, nowFrom(hint.CreatedAt))
}

func ValidateRendezvousAnnouncement(announcement RendezvousAnnouncement) error {
	now := nowFrom(announcement.CreatedAt)
	if announcement.ProtocolVersion != ProtocolVersion {
		return ErrUnsupportedProtocolVersion
	}
	if !validNamespace(announcement.Namespace) || !validID(announcement.AnnouncementID) {
		return ErrInvalidRendezvous
	}
	if !validDeviceID(announcement.DeviceID) {
		return ErrInvalidDeviceID
	}
	if announcement.ProfileID != "" && !validID(announcement.ProfileID) {
		return ErrInvalidRendezvous
	}
	if err := validateTimes(announcement.CreatedAt, announcement.ExpiresAt, now, ErrStaleRendezvous); err != nil {
		return err
	}
	if err := ValidateMetadata(announcement.Metadata); err != nil {
		return err
	}
	for _, hint := range announcement.EndpointHints {
		if err := validateEndpointHintAt(hint, now); err != nil {
			return err
		}
		if hint.Namespace != announcement.Namespace || hint.DeviceID != announcement.DeviceID {
			return ErrInvalidRendezvous
		}
	}
	return nil
}

func ValidateMailboxOpenRequest(req MailboxOpenRequest) error {
	now := nowFrom(req.CreatedAt)
	if !validNamespace(req.Namespace) {
		return ErrInvalidNamespace
	}
	if !validDeviceID(req.OwnerDeviceID) {
		return ErrInvalidDeviceID
	}
	if req.MailboxID != "" {
		if err := ValidateMailboxID(req.MailboxID); err != nil {
			return err
		}
	}
	if err := validateTimes(req.CreatedAt, req.ExpiresAt, now, ErrMailboxExpired); err != nil {
		return err
	}
	if err := ValidateMetadata(req.Metadata); err != nil {
		return err
	}
	return nil
}

func ValidateMailboxRef(ref MailboxRef) error {
	now := time.Now().UTC()
	if !validNamespace(ref.Namespace) {
		return ErrInvalidNamespace
	}
	if !validDeviceID(ref.OwnerDeviceID) {
		return ErrInvalidDeviceID
	}
	if err := ValidateMailboxID(ref.MailboxID); err != nil {
		return err
	}
	if ref.ProviderID != "" && !validID(ref.ProviderID) {
		return ErrInvalidMailbox
	}
	if ref.ExpiresAt.IsZero() || ref.ExpiresAt.Before(now.Add(-defaultClockSkew)) {
		return ErrMailboxExpired
	}
	return ValidateMetadata(ref.Metadata)
}

// ValidateMailboxID validates a standalone relay mailbox identifier without
// requiring callers to construct a mailbox request or reference.
func ValidateMailboxID(mailboxID string) error {
	if mailboxID != strings.TrimSpace(mailboxID) || !validID(mailboxID) {
		return ErrInvalidMailbox
	}
	return nil
}

func ValidateEnvelope(envelope RelayEnvelope) error {
	return ValidateEnvelopeWithLimit(envelope, DefaultMaxPayloadSize)
}

func ValidateEnvelopeWithLimit(envelope RelayEnvelope, maxPayloadBytes int) error {
	now := nowFrom(envelope.CreatedAt)
	if envelope.ProtocolVersion != ProtocolVersion {
		return ErrUnsupportedProtocolVersion
	}
	if !validNamespace(envelope.Namespace) {
		return ErrInvalidNamespace
	}
	if !validDeviceID(envelope.SourceDeviceID) {
		return ErrInvalidDeviceID
	}
	if envelope.TargetDeviceID == "" && envelope.TargetMailboxID == "" {
		return ErrInvalidEnvelope
	}
	if envelope.TargetDeviceID != "" && !validDeviceID(envelope.TargetDeviceID) {
		return ErrInvalidDeviceID
	}
	if envelope.TargetMailboxID != "" {
		if err := ValidateMailboxID(envelope.TargetMailboxID); err != nil {
			return err
		}
	}
	if !validMessageID(envelope.MessageID) || !validMessageKind(envelope.MessageKind) {
		return ErrInvalidEnvelope
	}
	if err := validateTimes(envelope.CreatedAt, envelope.ExpiresAt, now, ErrEnvelopeExpired); err != nil {
		return err
	}
	if maxPayloadBytes <= 0 {
		maxPayloadBytes = DefaultMaxPayloadSize
	}
	if len(envelope.Payload) > maxPayloadBytes {
		return ErrPayloadTooLarge
	}
	if strings.TrimSpace(envelope.PayloadHash) == "" {
		return ErrMissingPayloadHash
	}
	if !sha256HexPattern.MatchString(envelope.PayloadHash) {
		return ErrMissingPayloadHash
	}
	if !strings.EqualFold(envelope.PayloadHash, PayloadSHA256(envelope.Payload)) {
		return ErrPayloadHashMismatch
	}
	if err := ValidateMetadata(envelope.Metadata); err != nil {
		return err
	}
	return nil
}

func ValidateMetadata(metadata map[string]string) error {
	if len(metadata) > maxMetadataEntries {
		return ErrInvalidMetadata
	}
	for key, value := range metadata {
		key = strings.TrimSpace(key)
		value = strings.TrimSpace(value)
		if key == "" || len(key) > maxMetadataKeyLength || !safeMetadataKey.MatchString(key) || len(value) > maxMetadataValueLength {
			return ErrInvalidMetadata
		}
		if containsUnsafeDetail(key) || containsUnsafeDetail(value) {
			return ErrInvalidMetadata
		}
	}
	return nil
}

func validateEndpointHintAt(hint EndpointHint, now time.Time) error {
	if hint.ProtocolVersion != ProtocolVersion {
		return ErrUnsupportedProtocolVersion
	}
	if !validNamespace(hint.Namespace) {
		return ErrInvalidNamespace
	}
	if !validDeviceID(hint.DeviceID) {
		return ErrInvalidDeviceID
	}
	if !validID(hint.EndpointID) || strings.TrimSpace(hint.EndpointType) == "" {
		return ErrInvalidEndpointHint
	}
	if hint.ProviderID != "" && !validID(hint.ProviderID) {
		return ErrInvalidEndpointHint
	}
	if containsUnsafeDetail(hint.Address) {
		return ErrInvalidEndpointHint
	}
	if err := validateTimes(hint.CreatedAt, hint.ExpiresAt, now, ErrExpiredEndpointHint); err != nil {
		return err
	}
	return ValidateMetadata(hint.Metadata)
}

func validateTimes(createdAt, expiresAt, now time.Time, expiredErr error) error {
	if createdAt.IsZero() || expiresAt.IsZero() || !expiresAt.After(createdAt) {
		return expiredErr
	}
	if now.IsZero() {
		now = time.Now().UTC()
	}
	if createdAt.After(now.Add(defaultClockSkew)) {
		return expiredErr
	}
	if expiresAt.Before(now.Add(-defaultClockSkew)) {
		return expiredErr
	}
	return nil
}

func nowFrom(createdAt time.Time) time.Time {
	if createdAt.IsZero() {
		return time.Now().UTC()
	}
	now := time.Now().UTC()
	if createdAt.After(now.Add(defaultClockSkew)) {
		return now
	}
	return now
}

func validNamespace(s string) bool {
	s = strings.TrimSpace(s)
	return safeNamePattern.MatchString(s) && !strings.Contains(s, "..") && !strings.ContainsAny(s, `/\`) && !isReservedWindowsName(s)
}

func validDeviceID(s string) bool {
	return validID(s)
}

func validMessageID(s string) bool {
	return validID(s)
}

func validID(s string) bool {
	s = strings.TrimSpace(s)
	return safeIDPattern.MatchString(s) && !strings.Contains(s, "..") && !strings.ContainsAny(s, `/\`) && !containsUnsafeDetail(s)
}

func validMessageKind(kind MessageKind) bool {
	switch kind {
	case MessageKindDeviceProof, MessageKindPresence, MessageKindResourceHint, MessageKindMailboxPing, MessageKindOpaque:
		return true
	default:
		return false
	}
}

func containsUnsafeDetail(s string) bool {
	lower := strings.ToLower(strings.TrimSpace(s))
	if lower == "" {
		return false
	}
	for _, marker := range secretIndicators {
		if strings.Contains(lower, marker) {
			return true
		}
	}
	for _, marker := range localPathIndicators {
		if strings.Contains(s, marker) {
			return true
		}
	}
	return false
}

func isReservedWindowsName(s string) bool {
	switch strings.ToUpper(strings.TrimSpace(s)) {
	case "CON", "PRN", "AUX", "NUL", "COM1", "COM2", "COM3", "COM4", "COM5", "COM6", "COM7", "COM8", "COM9", "LPT1", "LPT2", "LPT3", "LPT4", "LPT5", "LPT6", "LPT7", "LPT8", "LPT9":
		return true
	default:
		return false
	}
}

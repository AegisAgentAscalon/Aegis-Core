package relay

import (
	"crypto/sha256"
	"encoding/hex"
	"strings"
	"time"
)

func PayloadSHA256(payload []byte) string {
	sum := sha256.Sum256(payload)
	return hex.EncodeToString(sum[:])
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
	if strings.ContainsAny(s, `/\`) {
		return true
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

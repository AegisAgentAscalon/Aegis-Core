// Package devicelink contains the private implementation for Aegis Device Link.
package devicelink

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"net"
	"regexp"
	"strings"
	"time"
)

const (
	SchemaVersion           = 1
	MetadataVersion         = 1
	defaultLinkTTL          = 15 * time.Minute
	defaultStaleAfter       = 5 * time.Minute
	defaultFutureSkew       = 2 * time.Minute
	defaultTransportTimeout = 5 * time.Second
)

var safeNamePattern = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9._-]{0,127}$`)

var (
	ErrNotConfigured           = errors.New("device link is not configured")
	ErrInvalidNamespace        = errors.New("invalid app id or namespace")
	ErrCurrentDeviceNotFound   = errors.New("current device is not bootstrapped")
	ErrDeviceAlreadyExists     = errors.New("device already exists with different trust data")
	ErrDeviceNotFound          = errors.New("device not found")
	ErrDeviceNotTrusted        = errors.New("device is not trusted")
	ErrDeviceRevoked           = errors.New("device is revoked")
	ErrDeviceStale             = errors.New("device is stale")
	ErrInvalidRegistrySnapshot = errors.New("invalid registry snapshot")
	ErrFingerprintMismatch     = errors.New("device fingerprint mismatch")
	ErrInvalidPublicKey        = errors.New("invalid device public key")
	ErrHandshakeFailed         = errors.New("handshake failed")
	ErrInvalidSessionID        = errors.New("invalid handshake session id")
	ErrChallengeExpired        = errors.New("handshake challenge expired")
	ErrChallengeReplay         = errors.New("handshake challenge already used")
	ErrTransportUnavailable    = errors.New("transport unavailable")
	ErrDiscoveryUnavailable    = errors.New("discovery unavailable")
	ErrStorageUnavailable      = errors.New("device link storage unavailable")
	ErrInvalidResource         = errors.New("invalid resource advertisement")
	ErrContextCanceled         = errors.New("device link operation canceled")
)

type TrustStatus string

const (
	TrustUnknown TrustStatus = "unknown"
	TrustPending TrustStatus = "pending"
	TrustTrusted TrustStatus = "trusted"
	TrustRevoked TrustStatus = "revoked"
	TrustStale   TrustStatus = "stale"
)

type ResourceType string

const (
	ResourceService   ResourceType = "service"
	ResourceData      ResourceType = "kb"
	ResourceConnector ResourceType = "connector"
	ResourceRuntime   ResourceType = "runtime"
	ResourceTool      ResourceType = "tool"
	ResourceOther     ResourceType = "other"
)

type ResourceAvailability string

const (
	ResourceAvailable   ResourceAvailability = "available"
	ResourceUnavailable ResourceAvailability = "unavailable"
	ResourceUnknown     ResourceAvailability = "unknown"
)

type AppConfig struct {
	AppID       string
	DisplayName string
	DataDir     string
	Namespace   string
}

type Option func(*options)

type options struct {
	discovery DiscoveryProvider
	transport Transport
	clock     Clock
}

type Clock interface {
	Now() time.Time
}

type realClock struct{}

func (realClock) Now() time.Time { return time.Now().UTC() }

type BootstrapDeviceRequest struct {
	DisplayName  string
	Capabilities []string
}

type DeviceIdentity struct {
	DeviceID             string    `json:"device_id"`
	DisplayName          string    `json:"display_name"`
	AppID                string    `json:"app_id"`
	Namespace            string    `json:"namespace"`
	PublicKey            string    `json:"public_key"`
	PublicKeyFingerprint string    `json:"public_key_fingerprint"`
	CreatedAt            time.Time `json:"created_at"`
	UpdatedAt            time.Time `json:"updated_at"`
	Capabilities         []string  `json:"capabilities"`
	MetadataVersion      int       `json:"metadata_version"`
}

type TrustedDevice struct {
	DeviceID               string      `json:"device_id"`
	DisplayName            string      `json:"display_name"`
	PublicKey              string      `json:"public_key"`
	PublicKeyFingerprint   string      `json:"public_key_fingerprint"`
	TrustStatus            TrustStatus `json:"trust_status"`
	TrustedAt              time.Time   `json:"trusted_at,omitempty"`
	RevokedAt              *time.Time  `json:"revoked_at,omitempty"`
	LastSeen               time.Time   `json:"last_seen,omitempty"`
	Capabilities           []string    `json:"capabilities"`
	ProfileMetadataVersion int         `json:"profile_metadata_version"`
}

type TrustDeviceRequest struct {
	DeviceID             string
	DisplayName          string
	PublicKey            string
	PublicKeyFingerprint string
	Capabilities         []string
}

type DeviceTrustStatus struct {
	DeviceID    string      `json:"device_id"`
	TrustStatus TrustStatus `json:"trust_status"`
	Trusted     bool        `json:"trusted"`
	Reason      string      `json:"reason,omitempty"`
}

type RegistrySnapshot struct {
	SchemaVersion          int             `json:"schema_version"`
	AppID                  string          `json:"app_id"`
	Namespace              string          `json:"namespace"`
	Devices                []TrustedDevice `json:"devices"`
	CreatedAt              time.Time       `json:"created_at"`
	UpdatedAt              time.Time       `json:"updated_at"`
	OriginDeviceID         string          `json:"origin_device_id,omitempty"`
	SnapshotFingerprint    string          `json:"snapshot_fingerprint,omitempty"`
	ProfileMetadataVersion int             `json:"profile_metadata_version"`
}

type EndpointHint struct {
	Kind    string `json:"kind"`
	Address string `json:"address"`
}

type ResourceSummary struct {
	Type  ResourceType `json:"type"`
	Count int          `json:"count"`
}

type PresenceRecord struct {
	SchemaVersion        int               `json:"schema_version"`
	DeviceID             string            `json:"device_id"`
	DisplayName          string            `json:"display_name"`
	EndpointHints        []EndpointHint    `json:"endpoint_hints"`
	Capabilities         []string          `json:"capabilities"`
	ResourcesSummary     []ResourceSummary `json:"resources_summary"`
	LastSeen             time.Time         `json:"last_seen"`
	PublicKeyFingerprint string            `json:"public_key_fingerprint"`
}

type DiscoveredPeer struct {
	Presence    PresenceRecord `json:"presence"`
	TrustStatus TrustStatus    `json:"trust_status"`
	Stale       bool           `json:"stale"`
}

type ResourceDescriptor struct {
	ResourceID    string               `json:"resource_id"`
	Type          ResourceType         `json:"type"`
	DisplayName   string               `json:"display_name"`
	OwnerDeviceID string               `json:"owner_device_id"`
	Availability  ResourceAvailability `json:"availability"`
	Tags          []string             `json:"tags"`
	Metadata      map[string]string    `json:"metadata"`
	LastUpdated   time.Time            `json:"last_updated"`
}

type RemoteResourceDescriptor struct {
	ResourceDescriptor
	DeviceDisplayName    string      `json:"device_display_name,omitempty"`
	DeviceTrustStatus    TrustStatus `json:"device_trust_status"`
	PublicKeyFingerprint string      `json:"public_key_fingerprint"`
}

type ResourceAdvertisementRequest struct {
	Resources []ResourceDescriptor
}

type HandshakeStartResult struct {
	SessionID                 string    `json:"session_id"`
	PeerDeviceID              string    `json:"peer_device_id"`
	Challenge                 string    `json:"challenge"`
	ExpiresAt                 time.Time `json:"expires_at"`
	LocalDeviceID             string    `json:"local_device_id"`
	LocalPublicKeyFingerprint string    `json:"local_public_key_fingerprint"`
}

type HandshakeChallengeRequest struct {
	ChallengerDeviceID string
	Challenge          string
}

type HandshakeChallengeResponse struct {
	DeviceID             string `json:"device_id"`
	PublicKeyFingerprint string `json:"public_key_fingerprint"`
	Signature            string `json:"signature"`
}

type HandshakeCompleteRequest struct {
	SessionID    string
	PeerDeviceID string
	Signature    string
}

type LinkSession struct {
	SessionID     string    `json:"session_id"`
	LocalDeviceID string    `json:"local_device_id"`
	PeerDeviceID  string    `json:"peer_device_id"`
	EstablishedAt time.Time `json:"established_at"`
	ExpiresAt     time.Time `json:"expires_at"`
	Status        string    `json:"status"`
}

type LinkTestResult struct {
	DeviceID      string `json:"device_id"`
	OK            bool   `json:"ok"`
	Status        string `json:"status"`
	LatencyMillis int64  `json:"latency_millis"`
	Message       string `json:"message,omitempty"`
}

type ConnectionStatus struct {
	DeviceID    string      `json:"device_id"`
	TrustStatus TrustStatus `json:"trust_status"`
	Reachable   bool        `json:"reachable"`
	LastSeen    time.Time   `json:"last_seen,omitempty"`
	Stale       bool        `json:"stale"`
	Message     string      `json:"message,omitempty"`
}

type Message struct {
	Kind         string            `json:"kind"`
	FromDeviceID string            `json:"from_device_id,omitempty"`
	ToDeviceID   string            `json:"to_device_id,omitempty"`
	Payload      map[string]string `json:"payload,omitempty"`
	CreatedAt    time.Time         `json:"created_at"`
}

type DiscoveryProvider interface {
	Publish(ctx context.Context, record PresenceRecord) error
	Discover(ctx context.Context) ([]PresenceRecord, error)
}

type Transport interface {
	Open(ctx context.Context, peer DiscoveredPeer) (Connection, error)
}

type Connection interface {
	Send(ctx context.Context, msg Message) error
	Receive(ctx context.Context) (Message, error)
	Close() error
}

type ProfileMetadataProvider interface {
	LoadRegistrySnapshot(ctx context.Context) (RegistrySnapshot, error)
	SaveRegistrySnapshot(ctx context.Context, snapshot RegistrySnapshot) error
}

type privateKeyFile struct {
	PrivateKey string `json:"private_key"`
}

type registryFile struct {
	SchemaVersion int             `json:"schema_version"`
	Devices       []TrustedDevice `json:"devices"`
	UpdatedAt     time.Time       `json:"updated_at"`
}

type resourceFile struct {
	SchemaVersion int                  `json:"schema_version"`
	Resources     []ResourceDescriptor `json:"resources"`
	UpdatedAt     time.Time            `json:"updated_at"`
}

type peerFile struct {
	SchemaVersion int              `json:"schema_version"`
	Peers         []PresenceRecord `json:"peers"`
	UpdatedAt     time.Time        `json:"updated_at"`
}

type handshakeSession struct {
	SessionID          string    `json:"session_id"`
	ChallengerDeviceID string    `json:"challenger_device_id"`
	PeerDeviceID       string    `json:"peer_device_id"`
	Challenge          string    `json:"challenge"`
	ExpiresAt          time.Time `json:"expires_at"`
	Consumed           bool      `json:"consumed"`
}

type linkStatusFile struct {
	SchemaVersion int                `json:"schema_version"`
	Links         []ConnectionStatus `json:"links"`
	UpdatedAt     time.Time          `json:"updated_at"`
}

func NormalizeConfig(cfg AppConfig) AppConfig {
	cfg.AppID = strings.TrimSpace(cfg.AppID)
	cfg.DisplayName = strings.TrimSpace(cfg.DisplayName)
	cfg.DataDir = strings.TrimSpace(cfg.DataDir)
	cfg.Namespace = strings.TrimSpace(cfg.Namespace)
	return cfg
}

func ValidateConfig(cfg AppConfig) error {
	cfg = NormalizeConfig(cfg)
	switch {
	case cfg.AppID == "":
		return errors.New("app id is required")
	case !validSafeName(cfg.AppID):
		return ErrInvalidNamespace
	case cfg.DisplayName == "":
		return errors.New("display name is required")
	case cfg.DataDir == "":
		return errors.New("data dir is required")
	case cfg.Namespace == "":
		return errors.New("namespace is required")
	case !validSafeName(cfg.Namespace):
		return ErrInvalidNamespace
	}
	return nil
}

func validSafeName(s string) bool {
	s = strings.TrimSpace(s)
	if !safeNamePattern.MatchString(s) {
		return false
	}
	if strings.Contains(s, "..") || strings.ContainsAny(s, `/\`) {
		return false
	}
	upper := strings.ToUpper(s)
	if i := strings.IndexByte(upper, '.'); i >= 0 {
		upper = upper[:i]
	}
	reserved := map[string]bool{
		"CON": true, "PRN": true, "AUX": true, "NUL": true,
		"COM1": true, "COM2": true, "COM3": true, "COM4": true, "COM5": true, "COM6": true, "COM7": true, "COM8": true, "COM9": true,
		"LPT1": true, "LPT2": true, "LPT3": true, "LPT4": true, "LPT5": true, "LPT6": true, "LPT7": true, "LPT8": true, "LPT9": true,
	}
	return !reserved[upper]
}

func validSessionID(id string) bool {
	id = strings.TrimSpace(id)
	if id == "" || strings.ContainsAny(id, `/\.`) || strings.Contains(id, "..") {
		return false
	}
	if !strings.HasPrefix(id, "hs_") {
		return false
	}
	return safeNamePattern.MatchString(id)
}

func randomID(prefix string, n int) (string, error) {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return prefix + base64.RawURLEncoding.EncodeToString(b), nil
}

func fingerprintPublicKey(publicKey []byte) string {
	sum := sha256.Sum256(publicKey)
	return hex.EncodeToString(sum[:])[:16]
}

func encodePublicKey(publicKey ed25519.PublicKey) string {
	return base64.RawStdEncoding.EncodeToString(publicKey)
}

func decodePublicKey(encoded string) (ed25519.PublicKey, error) {
	raw, err := base64.RawStdEncoding.DecodeString(strings.TrimSpace(encoded))
	if err != nil {
		return nil, ErrInvalidPublicKey
	}
	if len(raw) != ed25519.PublicKeySize {
		return nil, ErrInvalidPublicKey
	}
	return ed25519.PublicKey(raw), nil
}

func decodePrivateKey(encoded string) (ed25519.PrivateKey, error) {
	raw, err := base64.RawStdEncoding.DecodeString(strings.TrimSpace(encoded))
	if err != nil {
		return nil, ErrStorageUnavailable
	}
	if len(raw) != ed25519.PrivateKeySize {
		return nil, ErrStorageUnavailable
	}
	return ed25519.PrivateKey(raw), nil
}

func normalizeContext(ctx context.Context) context.Context {
	if ctx == nil {
		return context.Background()
	}
	return ctx
}

func isContextCanceled(ctx context.Context) bool {
	return ctx != nil && ctx.Err() != nil
}

func contextError(ctx context.Context) error {
	if isContextCanceled(ctx) {
		return ErrContextCanceled
	}
	return nil
}

func isStale(now, lastSeen time.Time) bool {
	return !lastSeen.IsZero() && (lastSeen.After(now.Add(defaultFutureSkew)) || now.Sub(lastSeen) > defaultStaleAfter)
}

func endpointLooksLocal(address string) bool {
	host, _, err := net.SplitHostPort(address)
	if err != nil {
		host = address
	}
	ip := net.ParseIP(strings.Trim(host, "[]"))
	return ip == nil || ip.IsLoopback() || ip.IsPrivate()
}

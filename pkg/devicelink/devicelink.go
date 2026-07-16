// Package devicelink exposes the public, app-safe Device Link v0.1 foundation.
//
// Device Link is app-agnostic, hostless, device-trusted, LAN-first, and
// relay-later. v0.1 provides local identity, trusted registry, resource
// presence, discovery/transport abstractions, signed handshake, and link tests.
package devicelink

import (
	"context"
	"sync"
	"time"

	internal "github.com/AegisAgentAscalon/aegis-core/internal/devicelink"
)

var (
	ErrNotConfigured           = internal.ErrNotConfigured
	ErrInvalidNamespace        = internal.ErrInvalidNamespace
	ErrCurrentDeviceNotFound   = internal.ErrCurrentDeviceNotFound
	ErrDeviceAlreadyExists     = internal.ErrDeviceAlreadyExists
	ErrDeviceNotFound          = internal.ErrDeviceNotFound
	ErrDeviceNotTrusted        = internal.ErrDeviceNotTrusted
	ErrDeviceRevoked           = internal.ErrDeviceRevoked
	ErrDeviceStale             = internal.ErrDeviceStale
	ErrInvalidRegistrySnapshot = internal.ErrInvalidRegistrySnapshot
	ErrFingerprintMismatch     = internal.ErrFingerprintMismatch
	ErrInvalidPublicKey        = internal.ErrInvalidPublicKey
	ErrInvalidIdentityBundle   = internal.ErrInvalidIdentityBundle
	ErrHandshakeFailed         = internal.ErrHandshakeFailed
	ErrInvalidSessionID        = internal.ErrInvalidSessionID
	ErrChallengeExpired        = internal.ErrChallengeExpired
	ErrChallengeReplay         = internal.ErrChallengeReplay
	ErrTransportUnavailable    = internal.ErrTransportUnavailable
	ErrDiscoveryUnavailable    = internal.ErrDiscoveryUnavailable
	ErrStorageUnavailable      = internal.ErrStorageUnavailable
	ErrInvalidResource         = internal.ErrInvalidResource
	ErrContextCanceled         = internal.ErrContextCanceled
)

type TrustStatus string

const (
	TrustUnknown TrustStatus = "unknown"
	TrustPending TrustStatus = "pending"
	TrustTrusted TrustStatus = "trusted"
	TrustRevoked TrustStatus = "revoked"
	TrustStale   TrustStatus = "stale"
)

type BootstrapState string

const (
	BootstrapAbsent  BootstrapState = "absent"
	BootstrapPartial BootstrapState = "partial"
	BootstrapReady   BootstrapState = "ready"
	BootstrapInvalid BootstrapState = "invalid"
)

type RegistrySnapshotPurpose string

const RegistrySnapshotLocalBackup RegistrySnapshotPurpose = "local_backup"

type ProofState string

const (
	ProofStateUnverified ProofState = "unverified"
	ProofStateVerified   ProofState = "verified"
	ProofStateExpired    ProofState = "expired"
	ProofStateRejected   ProofState = "rejected"
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

// Option configures a public Device Link service without exposing internal
// implementation option types as public API.
type Option func(*options)

type options struct {
	discovery DiscoveryProvider
	transport Transport
	clock     Clock
}

type Clock interface {
	Now() time.Time
}

type BootstrapDeviceRequest struct {
	DisplayName  string
	Capabilities []string
}

type BootstrapStatus struct {
	State             BootstrapState `json:"state"`
	Bootstrapped      bool           `json:"bootstrapped"`
	Ready             bool           `json:"ready"`
	IdentityPresent   bool           `json:"identity_present"`
	PrivateKeyPresent bool           `json:"private_key_present"`
	DeviceID          string         `json:"device_id,omitempty"`
	Message           string         `json:"message,omitempty"`
}

type DeviceIdentity struct {
	DeviceID             string    `json:"device_id"`
	DisplayName          string    `json:"display_name"`
	AppID                string    `json:"app_id"`
	Namespace            string    `json:"namespace"`
	PublicKey            string    `json:"-"`
	PublicKeyFingerprint string    `json:"public_key_fingerprint"`
	CreatedAt            time.Time `json:"created_at"`
	UpdatedAt            time.Time `json:"updated_at"`
	Capabilities         []string  `json:"capabilities"`
	MetadataVersion      int       `json:"metadata_version"`
}

// PublicIdentityBundle is deliberately public-key-bearing exchange metadata.
// Validation does not grant membership, trust, proof, or payload authority.
type PublicIdentityBundle struct {
	SchemaVersion        int       `json:"schema_version"`
	BundleVersion        int       `json:"bundle_version"`
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
	BundleFingerprint    string    `json:"bundle_fingerprint"`
}

type TrustedDevice struct {
	DeviceID               string      `json:"device_id"`
	DisplayName            string      `json:"display_name"`
	PublicKey              string      `json:"-"`
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
	SchemaVersion          int                     `json:"schema_version"`
	Purpose                RegistrySnapshotPurpose `json:"purpose"`
	AppID                  string                  `json:"app_id"`
	Namespace              string                  `json:"namespace"`
	Devices                []TrustedDevice         `json:"devices"`
	CreatedAt              time.Time               `json:"created_at"`
	UpdatedAt              time.Time               `json:"updated_at"`
	OriginDeviceID         string                  `json:"origin_device_id,omitempty"`
	SnapshotFingerprint    string                  `json:"snapshot_fingerprint,omitempty"`
	ProfileMetadataVersion int                     `json:"profile_metadata_version"`
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
	SessionID     string        `json:"session_id"`
	LocalDeviceID string        `json:"local_device_id"`
	PeerDeviceID  string        `json:"peer_device_id"`
	EstablishedAt time.Time     `json:"established_at"`
	ExpiresAt     time.Time     `json:"expires_at"`
	Status        string        `json:"status"`
	ProofReceipt  *ProofReceipt `json:"proof_receipt,omitempty"`
}

type ProofReceipt struct {
	SchemaVersion            int       `json:"schema_version"`
	SessionID                string    `json:"session_id"`
	LocalDeviceID            string    `json:"local_device_id"`
	PeerDeviceID             string    `json:"peer_device_id"`
	PeerPublicKeyFingerprint string    `json:"peer_public_key_fingerprint"`
	ChallengeFingerprint     string    `json:"challenge_fingerprint"`
	SignatureFingerprint     string    `json:"signature_fingerprint"`
	VerifiedAt               time.Time `json:"verified_at"`
	ExpiresAt                time.Time `json:"expires_at"`
	ReceiptFingerprint       string    `json:"receipt_fingerprint"`
}

type ProofEvaluation struct {
	DeviceID    string        `json:"device_id"`
	TrustStatus TrustStatus   `json:"trust_status"`
	State       ProofState    `json:"state"`
	Satisfied   bool          `json:"satisfied"`
	Reachable   bool          `json:"reachable"`
	EvaluatedAt time.Time     `json:"evaluated_at"`
	Receipt     *ProofReceipt `json:"receipt,omitempty"`
	Reason      string        `json:"reason,omitempty"`
}

type LinkTestResult struct {
	DeviceID      string `json:"device_id"`
	OK            bool   `json:"ok"`
	Status        string `json:"status"`
	LatencyMillis int64  `json:"latency_millis"`
	Message       string `json:"message,omitempty"`
}

type ConnectionStatus struct {
	DeviceID     string        `json:"device_id"`
	TrustStatus  TrustStatus   `json:"trust_status"`
	Reachable    bool          `json:"reachable"`
	LastSeen     time.Time     `json:"last_seen,omitempty"`
	Stale        bool          `json:"stale"`
	ProofState   ProofState    `json:"proof_state"`
	ProofReceipt *ProofReceipt `json:"proof_receipt,omitempty"`
	Message      string        `json:"message,omitempty"`
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

type MessageHandler func(context.Context, Message) (Message, error)

type Service struct {
	svc *internal.Service
}

func WithDiscoveryProvider(provider DiscoveryProvider) Option {
	return func(opts *options) {
		opts.discovery = provider
	}
}

func WithTransport(transport Transport) Option {
	return func(opts *options) {
		opts.transport = transport
	}
}

func WithClock(clock Clock) Option {
	return func(opts *options) {
		opts.clock = clock
	}
}

// InspectBootstrap reports bootstrap readiness without creating directories or
// writing Device Link state.
func InspectBootstrap(config AppConfig) (BootstrapStatus, error) {
	status, err := internal.InspectBootstrap(toInternalConfig(config))
	return BootstrapStatus{
		State:             BootstrapState(status.State),
		Bootstrapped:      status.Bootstrapped,
		Ready:             status.Ready,
		IdentityPresent:   status.IdentityPresent,
		PrivateKeyPresent: status.PrivateKeyPresent,
		DeviceID:          status.DeviceID,
		Message:           status.Message,
	}, err
}

// ValidatePublicIdentityBundle validates exchange metadata consistency only.
// Callers still own membership, passphrase, trust, and payload authorization.
func ValidatePublicIdentityBundle(bundle PublicIdentityBundle) error {
	return internal.ValidatePublicIdentityBundle(toInternalPublicIdentityBundle(bundle))
}

func NewService(config AppConfig, opts ...Option) (*Service, error) {
	publicOptions := options{}
	for _, opt := range opts {
		if opt != nil {
			opt(&publicOptions)
		}
	}
	var internalOptions []internal.Option
	if publicOptions.discovery != nil {
		internalOptions = append(internalOptions, internal.WithDiscoveryProvider(discoveryAdapter{provider: publicOptions.discovery}))
	}
	if publicOptions.transport != nil {
		internalOptions = append(internalOptions, internal.WithTransport(transportAdapter{transport: publicOptions.transport}))
	}
	if publicOptions.clock != nil {
		internalOptions = append(internalOptions, internal.WithClock(publicOptions.clock))
	}
	svc, err := internal.NewService(toInternalConfig(config), internalOptions...)
	if err != nil {
		return nil, err
	}
	return &Service{svc: svc}, nil
}

func NewMemoryDiscoveryProvider() *MemoryDiscoveryProvider {
	return &MemoryDiscoveryProvider{records: map[string]PresenceRecord{}}
}

func NewMemoryTransport() *MemoryTransport {
	return &MemoryTransport{handlers: map[string]MessageHandler{}}
}

func (s *Service) ValidateConfig() error {
	return s.svc.ValidateConfig()
}

func (s *Service) BootstrapCurrentDevice(ctx context.Context, req BootstrapDeviceRequest) (DeviceIdentity, error) {
	id, err := s.svc.BootstrapCurrentDevice(ctx, internal.BootstrapDeviceRequest{
		DisplayName:  req.DisplayName,
		Capabilities: append([]string{}, req.Capabilities...),
	})
	return fromInternalIdentity(id), err
}

func (s *Service) GetCurrentDevice(ctx context.Context) (DeviceIdentity, error) {
	id, err := s.svc.GetCurrentDevice(ctx)
	return fromInternalIdentity(id), err
}

// ExportPublicIdentityBundle exports the public-key-bearing metadata needed for
// explicit identity exchange without granting trust or network authorization.
func (s *Service) ExportPublicIdentityBundle(ctx context.Context) (PublicIdentityBundle, error) {
	bundle, err := s.svc.ExportPublicIdentityBundle(ctx)
	return fromInternalPublicIdentityBundle(bundle), err
}

func (s *Service) ListTrustedDevices(ctx context.Context) ([]TrustedDevice, error) {
	devices, err := s.svc.ListTrustedDevices(ctx)
	return fromInternalTrustedDevices(devices), err
}

func (s *Service) TrustDevice(ctx context.Context, req TrustDeviceRequest) (TrustedDevice, error) {
	dev, err := s.svc.TrustDevice(ctx, internal.TrustDeviceRequest{
		DeviceID:             req.DeviceID,
		DisplayName:          req.DisplayName,
		PublicKey:            req.PublicKey,
		PublicKeyFingerprint: req.PublicKeyFingerprint,
		Capabilities:         append([]string{}, req.Capabilities...),
	})
	return fromInternalTrustedDevice(dev), err
}

func (s *Service) RevokeDevice(ctx context.Context, deviceID string) error {
	return s.svc.RevokeDevice(ctx, deviceID)
}

func (s *Service) GetDeviceTrustStatus(ctx context.Context, deviceID string) (DeviceTrustStatus, error) {
	status, err := s.svc.GetDeviceTrustStatus(ctx, deviceID)
	return fromInternalTrustStatus(status), err
}

func (s *Service) ExportRegistrySnapshot(ctx context.Context) (RegistrySnapshot, error) {
	snapshot, err := s.svc.ExportRegistrySnapshot(ctx)
	return fromInternalRegistrySnapshot(snapshot), err
}

// ImportRegistrySnapshot restores a local backup only. It clears durable link
// and proof state and must not be used to authorize a network peer.
func (s *Service) ImportRegistrySnapshot(ctx context.Context, snapshot RegistrySnapshot) error {
	return s.svc.ImportRegistrySnapshot(ctx, toInternalRegistrySnapshot(snapshot))
}

func (s *Service) AdvertiseResources(ctx context.Context, req ResourceAdvertisementRequest) error {
	return s.svc.AdvertiseResources(ctx, internal.ResourceAdvertisementRequest{Resources: toInternalResources(req.Resources)})
}

func (s *Service) ListLocalResources(ctx context.Context) ([]ResourceDescriptor, error) {
	resources, err := s.svc.ListLocalResources(ctx)
	return fromInternalResources(resources), err
}

func (s *Service) ListKnownRemoteResources(ctx context.Context) ([]RemoteResourceDescriptor, error) {
	resources, err := s.svc.ListKnownRemoteResources(ctx)
	return fromInternalRemoteResources(resources), err
}

func (s *Service) PublishPresence(ctx context.Context) (PresenceRecord, error) {
	record, err := s.svc.PublishPresence(ctx)
	return fromInternalPresence(record), err
}

func (s *Service) DiscoverPeers(ctx context.Context) ([]DiscoveredPeer, error) {
	peers, err := s.svc.DiscoverPeers(ctx)
	return fromInternalDiscoveredPeers(peers), err
}

func (s *Service) StartHandshake(ctx context.Context, peer DiscoveredPeer) (HandshakeStartResult, error) {
	result, err := s.svc.StartHandshake(ctx, toInternalDiscoveredPeer(peer))
	return fromInternalHandshakeStart(result), err
}

func (s *Service) SignHandshakeChallenge(ctx context.Context, req HandshakeChallengeRequest) (HandshakeChallengeResponse, error) {
	response, err := s.svc.SignHandshakeChallenge(ctx, internal.HandshakeChallengeRequest(req))
	return HandshakeChallengeResponse(response), err
}

func (s *Service) CompleteHandshake(ctx context.Context, req HandshakeCompleteRequest) (LinkSession, error) {
	session, err := s.svc.CompleteHandshake(ctx, internal.HandshakeCompleteRequest(req))
	return fromInternalLinkSession(session), err
}

func (s *Service) TestLink(ctx context.Context, deviceID string) (LinkTestResult, error) {
	result, err := s.svc.TestLink(ctx, deviceID)
	return LinkTestResult(result), err
}

func (s *Service) GetConnectionStatus(ctx context.Context, deviceID string) (ConnectionStatus, error) {
	status, err := s.svc.GetConnectionStatus(ctx, deviceID)
	return fromInternalConnectionStatus(status), err
}

// EvaluateProof evaluates durable signed-handshake evidence independently of
// reachability and caller-owned membership or payload policy.
func (s *Service) EvaluateProof(ctx context.Context, deviceID string) (ProofEvaluation, error) {
	evaluation, err := s.svc.EvaluateProof(ctx, deviceID)
	return fromInternalProofEvaluation(evaluation), err
}

type MemoryDiscoveryProvider struct {
	mu      sync.Mutex
	records map[string]PresenceRecord
	err     error
}

func (p *MemoryDiscoveryProvider) SetError(err error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.err = err
}

func (p *MemoryDiscoveryProvider) Publish(ctx context.Context, record PresenceRecord) error {
	if err := publicContextError(ctx); err != nil {
		return err
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.err != nil {
		return ErrDiscoveryUnavailable
	}
	p.records[record.DeviceID] = record
	return nil
}

func (p *MemoryDiscoveryProvider) Discover(ctx context.Context) ([]PresenceRecord, error) {
	if err := publicContextError(ctx); err != nil {
		return nil, err
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.err != nil {
		return nil, ErrDiscoveryUnavailable
	}
	out := make([]PresenceRecord, 0, len(p.records))
	for _, record := range p.records {
		out = append(out, record)
	}
	return out, nil
}

type MemoryTransport struct {
	mu       sync.Mutex
	handlers map[string]MessageHandler
	err      error
}

func (t *MemoryTransport) RegisterHandler(deviceID string, handler MessageHandler) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.handlers[deviceID] = handler
}

func (t *MemoryTransport) SetError(err error) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.err = err
}

func (t *MemoryTransport) Open(ctx context.Context, peer DiscoveredPeer) (Connection, error) {
	if err := publicContextError(ctx); err != nil {
		return nil, err
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.err != nil {
		return nil, ErrTransportUnavailable
	}
	handler := t.handlers[peer.Presence.DeviceID]
	if handler == nil {
		return nil, ErrTransportUnavailable
	}
	return &memoryConnection{handler: handler}, nil
}

type memoryConnection struct {
	handler MessageHandler
	last    Message
	closed  bool
}

func (c *memoryConnection) Send(ctx context.Context, msg Message) error {
	if c.closed {
		return ErrTransportUnavailable
	}
	if err := publicContextError(ctx); err != nil {
		return err
	}
	c.last = msg
	return nil
}

func (c *memoryConnection) Receive(ctx context.Context) (Message, error) {
	if c.closed {
		return Message{}, ErrTransportUnavailable
	}
	if err := publicContextError(ctx); err != nil {
		return Message{}, err
	}
	return c.handler(ctx, c.last)
}

func (c *memoryConnection) Close() error {
	c.closed = true
	return nil
}

type discoveryAdapter struct {
	provider DiscoveryProvider
}

func (a discoveryAdapter) Publish(ctx context.Context, record internal.PresenceRecord) error {
	return a.provider.Publish(ctx, fromInternalPresence(record))
}

func (a discoveryAdapter) Discover(ctx context.Context) ([]internal.PresenceRecord, error) {
	records, err := a.provider.Discover(ctx)
	return toInternalPresenceRecords(records), err
}

type transportAdapter struct {
	transport Transport
}

func (a transportAdapter) Open(ctx context.Context, peer internal.DiscoveredPeer) (internal.Connection, error) {
	conn, err := a.transport.Open(ctx, fromInternalDiscoveredPeer(peer))
	if err != nil {
		return nil, err
	}
	if conn == nil {
		return nil, ErrTransportUnavailable
	}
	return connectionAdapter{conn: conn}, nil
}

type connectionAdapter struct {
	conn Connection
}

func (a connectionAdapter) Send(ctx context.Context, msg internal.Message) error {
	return a.conn.Send(ctx, fromInternalMessage(msg))
}

func (a connectionAdapter) Receive(ctx context.Context) (internal.Message, error) {
	msg, err := a.conn.Receive(ctx)
	return toInternalMessage(msg), err
}

func (a connectionAdapter) Close() error {
	return a.conn.Close()
}

func toInternalConfig(cfg AppConfig) internal.AppConfig {
	return internal.AppConfig{AppID: cfg.AppID, DisplayName: cfg.DisplayName, DataDir: cfg.DataDir, Namespace: cfg.Namespace}
}

func fromInternalIdentity(id internal.DeviceIdentity) DeviceIdentity {
	return DeviceIdentity{
		DeviceID:             id.DeviceID,
		DisplayName:          id.DisplayName,
		AppID:                id.AppID,
		Namespace:            id.Namespace,
		PublicKey:            id.PublicKey,
		PublicKeyFingerprint: id.PublicKeyFingerprint,
		CreatedAt:            id.CreatedAt,
		UpdatedAt:            id.UpdatedAt,
		Capabilities:         append([]string{}, id.Capabilities...),
		MetadataVersion:      id.MetadataVersion,
	}
}

func fromInternalPublicIdentityBundle(bundle internal.PublicIdentityBundle) PublicIdentityBundle {
	return PublicIdentityBundle{
		SchemaVersion:        bundle.SchemaVersion,
		BundleVersion:        bundle.BundleVersion,
		DeviceID:             bundle.DeviceID,
		DisplayName:          bundle.DisplayName,
		AppID:                bundle.AppID,
		Namespace:            bundle.Namespace,
		PublicKey:            bundle.PublicKey,
		PublicKeyFingerprint: bundle.PublicKeyFingerprint,
		CreatedAt:            bundle.CreatedAt,
		UpdatedAt:            bundle.UpdatedAt,
		Capabilities:         append([]string{}, bundle.Capabilities...),
		MetadataVersion:      bundle.MetadataVersion,
		BundleFingerprint:    bundle.BundleFingerprint,
	}
}

func toInternalPublicIdentityBundle(bundle PublicIdentityBundle) internal.PublicIdentityBundle {
	return internal.PublicIdentityBundle{
		SchemaVersion:        bundle.SchemaVersion,
		BundleVersion:        bundle.BundleVersion,
		DeviceID:             bundle.DeviceID,
		DisplayName:          bundle.DisplayName,
		AppID:                bundle.AppID,
		Namespace:            bundle.Namespace,
		PublicKey:            bundle.PublicKey,
		PublicKeyFingerprint: bundle.PublicKeyFingerprint,
		CreatedAt:            bundle.CreatedAt,
		UpdatedAt:            bundle.UpdatedAt,
		Capabilities:         append([]string{}, bundle.Capabilities...),
		MetadataVersion:      bundle.MetadataVersion,
		BundleFingerprint:    bundle.BundleFingerprint,
	}
}

func fromInternalTrustedDevice(dev internal.TrustedDevice) TrustedDevice {
	return TrustedDevice{
		DeviceID:               dev.DeviceID,
		DisplayName:            dev.DisplayName,
		PublicKey:              dev.PublicKey,
		PublicKeyFingerprint:   dev.PublicKeyFingerprint,
		TrustStatus:            TrustStatus(dev.TrustStatus),
		TrustedAt:              dev.TrustedAt,
		RevokedAt:              dev.RevokedAt,
		LastSeen:               dev.LastSeen,
		Capabilities:           append([]string{}, dev.Capabilities...),
		ProfileMetadataVersion: dev.ProfileMetadataVersion,
	}
}

func toInternalTrustedDevice(dev TrustedDevice) internal.TrustedDevice {
	return internal.TrustedDevice{
		DeviceID:               dev.DeviceID,
		DisplayName:            dev.DisplayName,
		PublicKey:              dev.PublicKey,
		PublicKeyFingerprint:   dev.PublicKeyFingerprint,
		TrustStatus:            internal.TrustStatus(dev.TrustStatus),
		TrustedAt:              dev.TrustedAt,
		RevokedAt:              dev.RevokedAt,
		LastSeen:               dev.LastSeen,
		Capabilities:           append([]string{}, dev.Capabilities...),
		ProfileMetadataVersion: dev.ProfileMetadataVersion,
	}
}

func fromInternalTrustedDevices(in []internal.TrustedDevice) []TrustedDevice {
	out := make([]TrustedDevice, 0, len(in))
	for _, dev := range in {
		out = append(out, fromInternalTrustedDevice(dev))
	}
	return out
}

func toInternalTrustedDevices(in []TrustedDevice) []internal.TrustedDevice {
	out := make([]internal.TrustedDevice, 0, len(in))
	for _, dev := range in {
		out = append(out, toInternalTrustedDevice(dev))
	}
	return out
}

func fromInternalTrustStatus(status internal.DeviceTrustStatus) DeviceTrustStatus {
	return DeviceTrustStatus{DeviceID: status.DeviceID, TrustStatus: TrustStatus(status.TrustStatus), Trusted: status.Trusted, Reason: status.Reason}
}

func fromInternalRegistrySnapshot(snapshot internal.RegistrySnapshot) RegistrySnapshot {
	return RegistrySnapshot{
		SchemaVersion:          snapshot.SchemaVersion,
		Purpose:                RegistrySnapshotPurpose(snapshot.Purpose),
		AppID:                  snapshot.AppID,
		Namespace:              snapshot.Namespace,
		Devices:                fromInternalTrustedDevices(snapshot.Devices),
		CreatedAt:              snapshot.CreatedAt,
		UpdatedAt:              snapshot.UpdatedAt,
		OriginDeviceID:         snapshot.OriginDeviceID,
		SnapshotFingerprint:    snapshot.SnapshotFingerprint,
		ProfileMetadataVersion: snapshot.ProfileMetadataVersion,
	}
}

func toInternalRegistrySnapshot(snapshot RegistrySnapshot) internal.RegistrySnapshot {
	return internal.RegistrySnapshot{
		SchemaVersion:          snapshot.SchemaVersion,
		Purpose:                internal.RegistrySnapshotPurpose(snapshot.Purpose),
		AppID:                  snapshot.AppID,
		Namespace:              snapshot.Namespace,
		Devices:                toInternalTrustedDevices(snapshot.Devices),
		CreatedAt:              snapshot.CreatedAt,
		UpdatedAt:              snapshot.UpdatedAt,
		OriginDeviceID:         snapshot.OriginDeviceID,
		SnapshotFingerprint:    snapshot.SnapshotFingerprint,
		ProfileMetadataVersion: snapshot.ProfileMetadataVersion,
	}
}

func fromInternalEndpointHint(hint internal.EndpointHint) EndpointHint {
	return EndpointHint{Kind: hint.Kind, Address: hint.Address}
}

func toInternalEndpointHint(hint EndpointHint) internal.EndpointHint {
	return internal.EndpointHint{Kind: hint.Kind, Address: hint.Address}
}

func fromInternalEndpointHints(in []internal.EndpointHint) []EndpointHint {
	out := make([]EndpointHint, 0, len(in))
	for _, hint := range in {
		out = append(out, fromInternalEndpointHint(hint))
	}
	return out
}

func toInternalEndpointHints(in []EndpointHint) []internal.EndpointHint {
	out := make([]internal.EndpointHint, 0, len(in))
	for _, hint := range in {
		out = append(out, toInternalEndpointHint(hint))
	}
	return out
}

func fromInternalResourceSummary(summary internal.ResourceSummary) ResourceSummary {
	return ResourceSummary{Type: ResourceType(summary.Type), Count: summary.Count}
}

func toInternalResourceSummary(summary ResourceSummary) internal.ResourceSummary {
	return internal.ResourceSummary{Type: internal.ResourceType(summary.Type), Count: summary.Count}
}

func fromInternalResourceSummaries(in []internal.ResourceSummary) []ResourceSummary {
	out := make([]ResourceSummary, 0, len(in))
	for _, summary := range in {
		out = append(out, fromInternalResourceSummary(summary))
	}
	return out
}

func toInternalResourceSummaries(in []ResourceSummary) []internal.ResourceSummary {
	out := make([]internal.ResourceSummary, 0, len(in))
	for _, summary := range in {
		out = append(out, toInternalResourceSummary(summary))
	}
	return out
}

func fromInternalPresence(record internal.PresenceRecord) PresenceRecord {
	return PresenceRecord{
		SchemaVersion:        record.SchemaVersion,
		DeviceID:             record.DeviceID,
		DisplayName:          record.DisplayName,
		EndpointHints:        fromInternalEndpointHints(record.EndpointHints),
		Capabilities:         append([]string{}, record.Capabilities...),
		ResourcesSummary:     fromInternalResourceSummaries(record.ResourcesSummary),
		LastSeen:             record.LastSeen,
		PublicKeyFingerprint: record.PublicKeyFingerprint,
	}
}

func toInternalPresence(record PresenceRecord) internal.PresenceRecord {
	return internal.PresenceRecord{
		SchemaVersion:        record.SchemaVersion,
		DeviceID:             record.DeviceID,
		DisplayName:          record.DisplayName,
		EndpointHints:        toInternalEndpointHints(record.EndpointHints),
		Capabilities:         append([]string{}, record.Capabilities...),
		ResourcesSummary:     toInternalResourceSummaries(record.ResourcesSummary),
		LastSeen:             record.LastSeen,
		PublicKeyFingerprint: record.PublicKeyFingerprint,
	}
}

func toInternalPresenceRecords(in []PresenceRecord) []internal.PresenceRecord {
	out := make([]internal.PresenceRecord, 0, len(in))
	for _, record := range in {
		out = append(out, toInternalPresence(record))
	}
	return out
}

func fromInternalDiscoveredPeer(peer internal.DiscoveredPeer) DiscoveredPeer {
	return DiscoveredPeer{Presence: fromInternalPresence(peer.Presence), TrustStatus: TrustStatus(peer.TrustStatus), Stale: peer.Stale}
}

func toInternalDiscoveredPeer(peer DiscoveredPeer) internal.DiscoveredPeer {
	return internal.DiscoveredPeer{Presence: toInternalPresence(peer.Presence), TrustStatus: internal.TrustStatus(peer.TrustStatus), Stale: peer.Stale}
}

func fromInternalDiscoveredPeers(in []internal.DiscoveredPeer) []DiscoveredPeer {
	out := make([]DiscoveredPeer, 0, len(in))
	for _, peer := range in {
		out = append(out, fromInternalDiscoveredPeer(peer))
	}
	return out
}

func fromInternalResource(resource internal.ResourceDescriptor) ResourceDescriptor {
	return ResourceDescriptor{
		ResourceID:    resource.ResourceID,
		Type:          ResourceType(resource.Type),
		DisplayName:   resource.DisplayName,
		OwnerDeviceID: resource.OwnerDeviceID,
		Availability:  ResourceAvailability(resource.Availability),
		Tags:          append([]string{}, resource.Tags...),
		Metadata:      cloneMap(resource.Metadata),
		LastUpdated:   resource.LastUpdated,
	}
}

func toInternalResource(resource ResourceDescriptor) internal.ResourceDescriptor {
	return internal.ResourceDescriptor{
		ResourceID:    resource.ResourceID,
		Type:          internal.ResourceType(resource.Type),
		DisplayName:   resource.DisplayName,
		OwnerDeviceID: resource.OwnerDeviceID,
		Availability:  internal.ResourceAvailability(resource.Availability),
		Tags:          append([]string{}, resource.Tags...),
		Metadata:      cloneMap(resource.Metadata),
		LastUpdated:   resource.LastUpdated,
	}
}

func fromInternalResources(in []internal.ResourceDescriptor) []ResourceDescriptor {
	out := make([]ResourceDescriptor, 0, len(in))
	for _, resource := range in {
		out = append(out, fromInternalResource(resource))
	}
	return out
}

func toInternalResources(in []ResourceDescriptor) []internal.ResourceDescriptor {
	out := make([]internal.ResourceDescriptor, 0, len(in))
	for _, resource := range in {
		out = append(out, toInternalResource(resource))
	}
	return out
}

func fromInternalRemoteResource(resource internal.RemoteResourceDescriptor) RemoteResourceDescriptor {
	return RemoteResourceDescriptor{
		ResourceDescriptor:   fromInternalResource(resource.ResourceDescriptor),
		DeviceDisplayName:    resource.DeviceDisplayName,
		DeviceTrustStatus:    TrustStatus(resource.DeviceTrustStatus),
		PublicKeyFingerprint: resource.PublicKeyFingerprint,
	}
}

func fromInternalRemoteResources(in []internal.RemoteResourceDescriptor) []RemoteResourceDescriptor {
	out := make([]RemoteResourceDescriptor, 0, len(in))
	for _, resource := range in {
		out = append(out, fromInternalRemoteResource(resource))
	}
	return out
}

func fromInternalHandshakeStart(result internal.HandshakeStartResult) HandshakeStartResult {
	return HandshakeStartResult{
		SessionID:                 result.SessionID,
		PeerDeviceID:              result.PeerDeviceID,
		Challenge:                 result.Challenge,
		ExpiresAt:                 result.ExpiresAt,
		LocalDeviceID:             result.LocalDeviceID,
		LocalPublicKeyFingerprint: result.LocalPublicKeyFingerprint,
	}
}

func fromInternalProofReceipt(receipt *internal.ProofReceipt) *ProofReceipt {
	if receipt == nil {
		return nil
	}
	return &ProofReceipt{
		SchemaVersion:            receipt.SchemaVersion,
		SessionID:                receipt.SessionID,
		LocalDeviceID:            receipt.LocalDeviceID,
		PeerDeviceID:             receipt.PeerDeviceID,
		PeerPublicKeyFingerprint: receipt.PeerPublicKeyFingerprint,
		ChallengeFingerprint:     receipt.ChallengeFingerprint,
		SignatureFingerprint:     receipt.SignatureFingerprint,
		VerifiedAt:               receipt.VerifiedAt,
		ExpiresAt:                receipt.ExpiresAt,
		ReceiptFingerprint:       receipt.ReceiptFingerprint,
	}
}

func fromInternalLinkSession(session internal.LinkSession) LinkSession {
	return LinkSession{
		SessionID:     session.SessionID,
		LocalDeviceID: session.LocalDeviceID,
		PeerDeviceID:  session.PeerDeviceID,
		EstablishedAt: session.EstablishedAt,
		ExpiresAt:     session.ExpiresAt,
		Status:        session.Status,
		ProofReceipt:  fromInternalProofReceipt(session.ProofReceipt),
	}
}

func fromInternalProofEvaluation(evaluation internal.ProofEvaluation) ProofEvaluation {
	return ProofEvaluation{
		DeviceID:    evaluation.DeviceID,
		TrustStatus: TrustStatus(evaluation.TrustStatus),
		State:       ProofState(evaluation.State),
		Satisfied:   evaluation.Satisfied,
		Reachable:   evaluation.Reachable,
		EvaluatedAt: evaluation.EvaluatedAt,
		Receipt:     fromInternalProofReceipt(evaluation.Receipt),
		Reason:      evaluation.Reason,
	}
}

func fromInternalConnectionStatus(status internal.ConnectionStatus) ConnectionStatus {
	return ConnectionStatus{
		DeviceID:     status.DeviceID,
		TrustStatus:  TrustStatus(status.TrustStatus),
		Reachable:    status.Reachable,
		LastSeen:     status.LastSeen,
		Stale:        status.Stale,
		ProofState:   ProofState(status.ProofState),
		ProofReceipt: fromInternalProofReceipt(status.ProofReceipt),
		Message:      status.Message,
	}
}

func fromInternalMessage(msg internal.Message) Message {
	return Message{
		Kind:         msg.Kind,
		FromDeviceID: msg.FromDeviceID,
		ToDeviceID:   msg.ToDeviceID,
		Payload:      cloneMap(msg.Payload),
		CreatedAt:    msg.CreatedAt,
	}
}

func toInternalMessage(msg Message) internal.Message {
	return internal.Message{
		Kind:         msg.Kind,
		FromDeviceID: msg.FromDeviceID,
		ToDeviceID:   msg.ToDeviceID,
		Payload:      cloneMap(msg.Payload),
		CreatedAt:    msg.CreatedAt,
	}
}

func cloneMap(in map[string]string) map[string]string {
	if in == nil {
		return nil
	}
	out := map[string]string{}
	for key, value := range in {
		out[key] = value
	}
	return out
}

func publicContextError(ctx context.Context) error {
	if ctx != nil && ctx.Err() != nil {
		return ErrContextCanceled
	}
	return nil
}

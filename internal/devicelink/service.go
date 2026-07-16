package devicelink

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"slices"
	"sort"
	"strings"
	"sync"
	"time"
)

type Service struct {
	cfg       AppConfig
	store     *store
	discovery DiscoveryProvider
	transport Transport
	clock     Clock
	mu        sync.Mutex
}

func WithDiscoveryProvider(provider DiscoveryProvider) Option {
	return func(o *options) { o.discovery = provider }
}

func WithTransport(transport Transport) Option {
	return func(o *options) { o.transport = transport }
}

func WithClock(clock Clock) Option {
	return func(o *options) { o.clock = clock }
}

func NewService(config AppConfig, opts ...Option) (*Service, error) {
	cfg := NormalizeConfig(config)
	if err := ValidateConfig(cfg); err != nil {
		return nil, err
	}
	st, err := newStore(cfg)
	if err != nil {
		return nil, err
	}
	options := options{discovery: noopDiscoveryProvider{}, clock: realClock{}}
	for _, opt := range opts {
		if opt != nil {
			opt(&options)
		}
	}
	if options.discovery == nil {
		options.discovery = noopDiscoveryProvider{}
	}
	if options.clock == nil {
		options.clock = realClock{}
	}
	return &Service{cfg: cfg, store: st, discovery: options.discovery, transport: options.transport, clock: options.clock}, nil
}

func (s *Service) ValidateConfig() error {
	return ValidateConfig(s.cfg)
}

// InspectBootstrap reports Device Link bootstrap state without creating the
// configured storage directory or writing any state.
func InspectBootstrap(config AppConfig) (BootstrapStatus, error) {
	cfg := NormalizeConfig(config)
	if err := ValidateConfig(cfg); err != nil {
		return BootstrapStatus{}, err
	}
	st := storeForConfig(cfg)
	identityPresent, err := regularFileExists(st.identityPath())
	if err != nil {
		return BootstrapStatus{}, err
	}
	privateKeyPresent, err := regularFileExists(st.privateKeyPath())
	if err != nil {
		return BootstrapStatus{}, err
	}
	status := BootstrapStatus{
		State:             BootstrapAbsent,
		IdentityPresent:   identityPresent,
		PrivateKeyPresent: privateKeyPresent,
		Message:           "device link is not bootstrapped",
	}
	if !identityPresent && !privateKeyPresent {
		return status, nil
	}
	if !identityPresent || !privateKeyPresent {
		status.State = BootstrapPartial
		status.Message = "device link bootstrap is incomplete"
		return status, nil
	}
	identity, identityErr := st.readIdentity()
	encodedPrivateKey, privateKeyErr := st.readPrivateKey()
	if identityErr != nil || privateKeyErr != nil {
		status.State = BootstrapInvalid
		status.Message = "device link bootstrap storage is invalid"
		return status, nil
	}
	privateKey, err := decodePrivateKey(encodedPrivateKey)
	bundle := publicIdentityBundleFromIdentity(identity)
	if err != nil || identity.AppID != cfg.AppID || identity.Namespace != cfg.Namespace || validateIdentityKeyPair(identity, privateKey) != nil || ValidatePublicIdentityBundle(bundle) != nil {
		status.State = BootstrapInvalid
		status.Message = "device link bootstrap identity is invalid"
		return status, nil
	}
	status.State = BootstrapReady
	status.Bootstrapped = true
	status.Ready = true
	status.DeviceID = identity.DeviceID
	status.Message = "device link bootstrap is ready"
	return status, nil
}

func regularFileExists(path string) (bool, error) {
	info, err := os.Stat(path)
	if errors.Is(err, os.ErrNotExist) {
		return false, nil
	}
	if err != nil {
		return false, ErrStorageUnavailable
	}
	if !info.Mode().IsRegular() {
		return true, nil
	}
	return true, nil
}

func (s *Service) BootstrapCurrentDevice(ctx context.Context, req BootstrapDeviceRequest) (DeviceIdentity, error) {
	if err := contextError(ctx); err != nil {
		return DeviceIdentity{}, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if existing, err := s.store.readIdentity(); err == nil {
		privateKey, keyErr := s.privateKey()
		if keyErr != nil {
			return DeviceIdentity{}, keyErr
		}
		bundle := publicIdentityBundleFromIdentity(existing)
		if existing.AppID != s.cfg.AppID || existing.Namespace != s.cfg.Namespace || validateIdentityKeyPair(existing, privateKey) != nil || ValidatePublicIdentityBundle(bundle) != nil {
			return DeviceIdentity{}, ErrStorageUnavailable
		}
		return existing, nil
	} else if !errors.Is(err, ErrCurrentDeviceNotFound) {
		return DeviceIdentity{}, err
	}
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return DeviceIdentity{}, ErrStorageUnavailable
	}
	deviceID, err := randomID("dev_", 16)
	if err != nil {
		return DeviceIdentity{}, ErrStorageUnavailable
	}
	now := s.clock.Now().UTC()
	displayName := strings.TrimSpace(req.DisplayName)
	if displayName == "" {
		displayName = s.cfg.DisplayName
	}
	id := DeviceIdentity{
		DeviceID:             deviceID,
		DisplayName:          displayName,
		AppID:                s.cfg.AppID,
		Namespace:            s.cfg.Namespace,
		PublicKey:            encodePublicKey(publicKey),
		PublicKeyFingerprint: fingerprintPublicKey(publicKey),
		CreatedAt:            now,
		UpdatedAt:            now,
		Capabilities:         compactStrings(req.Capabilities),
		MetadataVersion:      MetadataVersion,
	}
	if err := s.store.writePrivateKey(base64.RawStdEncoding.EncodeToString(privateKey)); err != nil {
		return DeviceIdentity{}, err
	}
	if err := s.store.writeIdentity(id); err != nil {
		return DeviceIdentity{}, err
	}
	return id, nil
}

func (s *Service) GetCurrentDevice(ctx context.Context) (DeviceIdentity, error) {
	if err := contextError(ctx); err != nil {
		return DeviceIdentity{}, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.store.readIdentity()
}

// ExportPublicIdentityBundle returns public key and identity metadata intended
// for explicit identity exchange. The bundle does not grant membership,
// establish trust, prove possession, or authorize payloads.
func (s *Service) ExportPublicIdentityBundle(ctx context.Context) (PublicIdentityBundle, error) {
	if err := contextError(ctx); err != nil {
		return PublicIdentityBundle{}, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	identity, err := s.store.readIdentity()
	if err != nil {
		return PublicIdentityBundle{}, err
	}
	privateKey, err := s.privateKey()
	if err != nil {
		return PublicIdentityBundle{}, err
	}
	if err := validateIdentityKeyPair(identity, privateKey); err != nil {
		return PublicIdentityBundle{}, err
	}
	bundle := publicIdentityBundleFromIdentity(identity)
	if err := ValidatePublicIdentityBundle(bundle); err != nil {
		return PublicIdentityBundle{}, ErrStorageUnavailable
	}
	return bundle, nil
}

// ValidatePublicIdentityBundle validates public identity consistency only. A
// valid bundle is not network authorization or proof of key possession.
func ValidatePublicIdentityBundle(bundle PublicIdentityBundle) error {
	if bundle.SchemaVersion != SchemaVersion || bundle.BundleVersion != IdentityBundleVersion || bundle.MetadataVersion != MetadataVersion {
		return ErrInvalidIdentityBundle
	}
	if !validSafeName(bundle.DeviceID) || !validSafeName(bundle.AppID) || !validSafeName(bundle.Namespace) {
		return ErrInvalidIdentityBundle
	}
	if strings.TrimSpace(bundle.DisplayName) == "" || bundle.DisplayName != strings.TrimSpace(bundle.DisplayName) {
		return ErrInvalidIdentityBundle
	}
	if bundle.CreatedAt.IsZero() || bundle.UpdatedAt.IsZero() || bundle.UpdatedAt.Before(bundle.CreatedAt) {
		return ErrInvalidIdentityBundle
	}
	publicKey, err := decodePublicKey(bundle.PublicKey)
	if err != nil || fingerprintPublicKey(publicKey) != bundle.PublicKeyFingerprint {
		return ErrInvalidIdentityBundle
	}
	if !slices.Equal(bundle.Capabilities, compactStrings(bundle.Capabilities)) {
		return ErrInvalidIdentityBundle
	}
	if bundle.BundleFingerprint == "" || bundle.BundleFingerprint != publicIdentityBundleFingerprint(bundle) {
		return ErrInvalidIdentityBundle
	}
	return nil
}

func (s *Service) ListTrustedDevices(ctx context.Context) ([]TrustedDevice, error) {
	if err := contextError(ctx); err != nil {
		return nil, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	reg, err := s.store.readRegistry()
	if err != nil {
		return nil, err
	}
	out := append([]TrustedDevice{}, reg.Devices...)
	sort.Slice(out, func(i, j int) bool { return out[i].DeviceID < out[j].DeviceID })
	return out, nil
}

func (s *Service) TrustDevice(ctx context.Context, req TrustDeviceRequest) (TrustedDevice, error) {
	if err := contextError(ctx); err != nil {
		return TrustedDevice{}, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.trustDeviceLocked(req)
}

func (s *Service) trustDeviceLocked(req TrustDeviceRequest) (TrustedDevice, error) {
	req.DeviceID = strings.TrimSpace(req.DeviceID)
	req.DisplayName = strings.TrimSpace(req.DisplayName)
	if req.DeviceID == "" || !validSafeName(req.DeviceID) {
		return TrustedDevice{}, ErrDeviceNotFound
	}
	publicKey, err := decodePublicKey(req.PublicKey)
	if err != nil {
		return TrustedDevice{}, err
	}
	fp := fingerprintPublicKey(publicKey)
	if strings.TrimSpace(req.PublicKeyFingerprint) != "" && req.PublicKeyFingerprint != fp {
		return TrustedDevice{}, ErrFingerprintMismatch
	}
	reg, err := s.store.readRegistry()
	if err != nil {
		return TrustedDevice{}, err
	}
	now := s.clock.Now().UTC()
	for i, dev := range reg.Devices {
		if dev.DeviceID != req.DeviceID {
			continue
		}
		if dev.PublicKeyFingerprint != fp {
			return TrustedDevice{}, ErrDeviceAlreadyExists
		}
		dev.DisplayName = req.DisplayName
		if dev.DisplayName == "" {
			dev.DisplayName = req.DeviceID
		}
		dev.PublicKey = req.PublicKey
		dev.TrustStatus = TrustTrusted
		dev.RevokedAt = nil
		dev.Capabilities = compactStrings(req.Capabilities)
		dev.ProfileMetadataVersion = MetadataVersion
		if dev.TrustedAt.IsZero() {
			dev.TrustedAt = now
		}
		reg.Devices[i] = dev
		reg.UpdatedAt = now
		if err := s.store.writeRegistry(reg); err != nil {
			return TrustedDevice{}, err
		}
		return dev, nil
	}
	dev := TrustedDevice{
		DeviceID:               req.DeviceID,
		DisplayName:            req.DisplayName,
		PublicKey:              req.PublicKey,
		PublicKeyFingerprint:   fp,
		TrustStatus:            TrustTrusted,
		TrustedAt:              now,
		Capabilities:           compactStrings(req.Capabilities),
		ProfileMetadataVersion: MetadataVersion,
	}
	if dev.DisplayName == "" {
		dev.DisplayName = req.DeviceID
	}
	reg.Devices = append(reg.Devices, dev)
	reg.UpdatedAt = now
	if err := s.store.writeRegistry(reg); err != nil {
		return TrustedDevice{}, err
	}
	return dev, nil
}

func (s *Service) RevokeDevice(ctx context.Context, deviceID string) error {
	if err := contextError(ctx); err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	reg, err := s.store.readRegistry()
	if err != nil {
		return err
	}
	for i, dev := range reg.Devices {
		if dev.DeviceID == deviceID {
			now := s.clock.Now().UTC()
			dev.TrustStatus = TrustRevoked
			dev.RevokedAt = &now
			reg.Devices[i] = dev
			reg.UpdatedAt = now
			return s.store.writeRegistry(reg)
		}
	}
	return ErrDeviceNotFound
}

func (s *Service) GetDeviceTrustStatus(ctx context.Context, deviceID string) (DeviceTrustStatus, error) {
	if err := contextError(ctx); err != nil {
		return DeviceTrustStatus{}, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	dev, found, err := s.findTrustedDeviceLocked(deviceID)
	if err != nil {
		return DeviceTrustStatus{}, err
	}
	if !found {
		return DeviceTrustStatus{DeviceID: deviceID, TrustStatus: TrustUnknown, Reason: "device is not trusted"}, nil
	}
	status := DeviceTrustStatus{DeviceID: deviceID, TrustStatus: dev.TrustStatus, Trusted: dev.TrustStatus == TrustTrusted}
	if dev.TrustStatus == TrustRevoked {
		status.Reason = "device is revoked"
	}
	return status, nil
}

func (s *Service) ExportRegistrySnapshot(ctx context.Context) (RegistrySnapshot, error) {
	if err := contextError(ctx); err != nil {
		return RegistrySnapshot{}, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	reg, err := s.store.readRegistry()
	if err != nil {
		return RegistrySnapshot{}, err
	}
	origin := ""
	if id, err := s.store.readIdentity(); err == nil {
		origin = id.DeviceID
	}
	now := s.clock.Now().UTC()
	snap := RegistrySnapshot{
		SchemaVersion:          SchemaVersion,
		Purpose:                RegistrySnapshotLocalBackup,
		AppID:                  s.cfg.AppID,
		Namespace:              s.cfg.Namespace,
		Devices:                append([]TrustedDevice{}, reg.Devices...),
		CreatedAt:              now,
		UpdatedAt:              now,
		OriginDeviceID:         origin,
		ProfileMetadataVersion: MetadataVersion,
	}
	snap.SnapshotFingerprint = snapshotFingerprint(snap)
	return snap, nil
}

func (s *Service) ImportRegistrySnapshot(ctx context.Context, snapshot RegistrySnapshot) error {
	if err := contextError(ctx); err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := validateRegistryBackupSnapshot(s.cfg, snapshot); err != nil {
		return err
	}
	// Registry backup restore never restores link reachability or signed proof.
	if err := s.store.writeLinks(linkStatusFile{SchemaVersion: SchemaVersion, Links: []ConnectionStatus{}, UpdatedAt: s.clock.Now().UTC()}); err != nil {
		return err
	}
	return s.store.writeRegistry(registryFile{SchemaVersion: SchemaVersion, Devices: append([]TrustedDevice{}, snapshot.Devices...), UpdatedAt: snapshot.UpdatedAt})
}

func (s *Service) AdvertiseResources(ctx context.Context, req ResourceAdvertisementRequest) error {
	if err := contextError(ctx); err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	current, err := s.store.readIdentity()
	if err != nil {
		return err
	}
	seen := map[string]bool{}
	out := make([]ResourceDescriptor, 0, len(req.Resources))
	for _, res := range req.Resources {
		res.ResourceID = strings.TrimSpace(res.ResourceID)
		res.DisplayName = strings.TrimSpace(res.DisplayName)
		if res.ResourceID == "" || seen[res.ResourceID] || !validResourceType(res.Type) {
			return ErrInvalidResource
		}
		seen[res.ResourceID] = true
		if res.OwnerDeviceID == "" {
			res.OwnerDeviceID = current.DeviceID
		}
		if res.OwnerDeviceID != current.DeviceID {
			return ErrInvalidResource
		}
		if res.Availability == "" {
			res.Availability = ResourceUnknown
		}
		if res.LastUpdated.IsZero() {
			res.LastUpdated = s.clock.Now().UTC()
		}
		if res.Metadata == nil {
			res.Metadata = map[string]string{}
		}
		out = append(out, res)
	}
	return s.store.writeResources(resourceFile{SchemaVersion: SchemaVersion, Resources: out, UpdatedAt: s.clock.Now().UTC()})
}

func (s *Service) ListLocalResources(ctx context.Context) ([]ResourceDescriptor, error) {
	if err := contextError(ctx); err != nil {
		return nil, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	res, err := s.store.readResources()
	if err != nil {
		return nil, err
	}
	return append([]ResourceDescriptor{}, res.Resources...), nil
}

func (s *Service) ListKnownRemoteResources(ctx context.Context) ([]RemoteResourceDescriptor, error) {
	if err := contextError(ctx); err != nil {
		return nil, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	peers, err := s.store.readPeers()
	if err != nil {
		return nil, err
	}
	reg, err := s.store.readRegistry()
	if err != nil {
		return nil, err
	}
	trust := map[string]TrustedDevice{}
	for _, dev := range reg.Devices {
		trust[dev.DeviceID] = dev
	}
	var out []RemoteResourceDescriptor
	now := s.clock.Now().UTC()
	for _, peer := range peers.Peers {
		dev := trust[peer.DeviceID]
		availability := remoteResourceAvailability(now, peer, dev)
		for _, summary := range peer.ResourcesSummary {
			out = append(out, RemoteResourceDescriptor{
				ResourceDescriptor: ResourceDescriptor{
					ResourceID:    peer.DeviceID + ":" + string(summary.Type),
					Type:          summary.Type,
					DisplayName:   string(summary.Type),
					OwnerDeviceID: peer.DeviceID,
					Availability:  availability,
					LastUpdated:   peer.LastSeen,
				},
				DeviceDisplayName:    peer.DisplayName,
				DeviceTrustStatus:    dev.TrustStatus,
				PublicKeyFingerprint: peer.PublicKeyFingerprint,
			})
		}
	}
	return out, nil
}

func (s *Service) PublishPresence(ctx context.Context) (PresenceRecord, error) {
	ctx = normalizeContext(ctx)
	if err := contextError(ctx); err != nil {
		return PresenceRecord{}, err
	}
	s.mu.Lock()
	current, err := s.store.readIdentity()
	if err != nil {
		s.mu.Unlock()
		return PresenceRecord{}, err
	}
	resources, err := s.store.readResources()
	if err != nil {
		s.mu.Unlock()
		return PresenceRecord{}, err
	}
	record := PresenceRecord{
		SchemaVersion:        SchemaVersion,
		DeviceID:             current.DeviceID,
		DisplayName:          current.DisplayName,
		Capabilities:         append([]string{}, current.Capabilities...),
		ResourcesSummary:     summarizeResources(resources.Resources),
		LastSeen:             s.clock.Now().UTC(),
		PublicKeyFingerprint: current.PublicKeyFingerprint,
	}
	discovery := s.discovery
	s.mu.Unlock()
	if err := discovery.Publish(ctx, record); err != nil {
		return PresenceRecord{}, ErrDiscoveryUnavailable
	}
	return record, nil
}

func (s *Service) DiscoverPeers(ctx context.Context) ([]DiscoveredPeer, error) {
	ctx = normalizeContext(ctx)
	if err := contextError(ctx); err != nil {
		return nil, err
	}
	s.mu.Lock()
	discovery := s.discovery
	s.mu.Unlock()
	records, err := discovery.Discover(ctx)
	if err != nil {
		return nil, ErrDiscoveryUnavailable
	}
	if err := contextError(ctx); err != nil {
		return nil, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	current, _ := s.store.readIdentity()
	reg, err := s.store.readRegistry()
	if err != nil {
		return nil, err
	}
	trust := map[string]TrustedDevice{}
	for _, dev := range reg.Devices {
		trust[dev.DeviceID] = dev
	}
	var peers []PresenceRecord
	var out []DiscoveredPeer
	now := s.clock.Now().UTC()
	for _, rec := range records {
		rec = clonePresenceRecord(rec)
		if rec.DeviceID == "" || rec.PublicKeyFingerprint == "" || rec.SchemaVersion != SchemaVersion {
			continue
		}
		if current.DeviceID != "" && rec.DeviceID == current.DeviceID {
			continue
		}
		dev := trust[rec.DeviceID]
		status := dev.TrustStatus
		if status == "" {
			status = TrustUnknown
		}
		stale := isStale(now, rec.LastSeen)
		if stale && status == TrustTrusted {
			status = TrustStale
		}
		if dev.TrustStatus == TrustTrusted {
			dev.LastSeen = rec.LastSeen
			trust[rec.DeviceID] = dev
		}
		peers = append(peers, rec)
		out = append(out, DiscoveredPeer{Presence: rec, TrustStatus: status, Stale: stale})
	}
	if err := s.store.writePeers(peerFile{SchemaVersion: SchemaVersion, Peers: peers, UpdatedAt: now}); err != nil {
		return nil, err
	}
	for i, dev := range reg.Devices {
		if updated, ok := trust[dev.DeviceID]; ok {
			reg.Devices[i] = updated
		}
	}
	if err := s.store.writeRegistry(reg); err != nil {
		return nil, err
	}
	return out, nil
}

func remoteResourceAvailability(now time.Time, peer PresenceRecord, dev TrustedDevice) ResourceAvailability {
	switch dev.TrustStatus {
	case TrustTrusted:
		if isStale(now, peer.LastSeen) || dev.PublicKeyFingerprint == "" || dev.PublicKeyFingerprint != peer.PublicKeyFingerprint {
			return ResourceUnavailable
		}
		return ResourceAvailable
	case TrustRevoked, TrustStale:
		return ResourceUnavailable
	default:
		return ResourceUnknown
	}
}

func clonePresenceRecord(record PresenceRecord) PresenceRecord {
	record.EndpointHints = append([]EndpointHint{}, record.EndpointHints...)
	record.Capabilities = append([]string{}, record.Capabilities...)
	record.ResourcesSummary = append([]ResourceSummary{}, record.ResourcesSummary...)
	return record
}

func (s *Service) StartHandshake(ctx context.Context, peer DiscoveredPeer) (HandshakeStartResult, error) {
	if err := contextError(ctx); err != nil {
		return HandshakeStartResult{}, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	current, err := s.store.readIdentity()
	if err != nil {
		return HandshakeStartResult{}, err
	}
	trusted, found, err := s.findTrustedDeviceLocked(peer.Presence.DeviceID)
	if err != nil {
		return HandshakeStartResult{}, err
	}
	if !found || trusted.TrustStatus != TrustTrusted {
		return HandshakeStartResult{}, trustError(trusted.TrustStatus)
	}
	if trusted.PublicKeyFingerprint != peer.Presence.PublicKeyFingerprint {
		return HandshakeStartResult{}, ErrFingerprintMismatch
	}
	sessionID, err := randomID("hs_", 16)
	if err != nil {
		return HandshakeStartResult{}, ErrStorageUnavailable
	}
	challenge, err := randomID("ch_", 32)
	if err != nil {
		return HandshakeStartResult{}, ErrStorageUnavailable
	}
	expires := s.clock.Now().UTC().Add(defaultLinkTTL)
	if err := s.store.writeHandshake(handshakeSession{SessionID: sessionID, ChallengerDeviceID: current.DeviceID, PeerDeviceID: peer.Presence.DeviceID, Challenge: challenge, ExpiresAt: expires}); err != nil {
		return HandshakeStartResult{}, err
	}
	return HandshakeStartResult{SessionID: sessionID, PeerDeviceID: peer.Presence.DeviceID, Challenge: challenge, ExpiresAt: expires, LocalDeviceID: current.DeviceID, LocalPublicKeyFingerprint: current.PublicKeyFingerprint}, nil
}

func (s *Service) SignHandshakeChallenge(ctx context.Context, req HandshakeChallengeRequest) (HandshakeChallengeResponse, error) {
	if err := contextError(ctx); err != nil {
		return HandshakeChallengeResponse{}, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if strings.TrimSpace(req.Challenge) == "" {
		return HandshakeChallengeResponse{}, ErrHandshakeFailed
	}
	current, err := s.store.readIdentity()
	if err != nil {
		return HandshakeChallengeResponse{}, err
	}
	if req.ChallengerDeviceID != "" {
		dev, found, err := s.findTrustedDeviceLocked(req.ChallengerDeviceID)
		if err != nil {
			return HandshakeChallengeResponse{}, err
		}
		if !found || dev.TrustStatus != TrustTrusted {
			return HandshakeChallengeResponse{}, trustError(dev.TrustStatus)
		}
	}
	privateKey, err := s.privateKey()
	if err != nil {
		return HandshakeChallengeResponse{}, err
	}
	payload := handshakePayload(s.cfg.AppID, s.cfg.Namespace, req.ChallengerDeviceID, current.DeviceID, req.Challenge)
	sig := ed25519.Sign(privateKey, payload)
	return HandshakeChallengeResponse{DeviceID: current.DeviceID, PublicKeyFingerprint: current.PublicKeyFingerprint, Signature: base64.RawStdEncoding.EncodeToString(sig)}, nil
}

func (s *Service) CompleteHandshake(ctx context.Context, req HandshakeCompleteRequest) (LinkSession, error) {
	if err := contextError(ctx); err != nil {
		return LinkSession{}, err
	}
	if !validSessionID(req.SessionID) {
		return LinkSession{}, ErrInvalidSessionID
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	h, err := s.store.readHandshake(req.SessionID)
	if err != nil {
		return LinkSession{}, err
	}
	if h.Consumed {
		return LinkSession{}, ErrChallengeReplay
	}
	if s.clock.Now().UTC().After(h.ExpiresAt) {
		return LinkSession{}, ErrChallengeExpired
	}
	if h.PeerDeviceID != req.PeerDeviceID {
		return LinkSession{}, ErrHandshakeFailed
	}
	trusted, found, err := s.findTrustedDeviceLocked(req.PeerDeviceID)
	if err != nil {
		return LinkSession{}, err
	}
	if !found || trusted.TrustStatus != TrustTrusted {
		return LinkSession{}, trustError(trusted.TrustStatus)
	}
	publicKey, err := decodePublicKey(trusted.PublicKey)
	if err != nil {
		return LinkSession{}, err
	}
	signature, err := base64.RawStdEncoding.DecodeString(req.Signature)
	payload := handshakePayload(s.cfg.AppID, s.cfg.Namespace, h.ChallengerDeviceID, req.PeerDeviceID, h.Challenge)
	if err != nil || !ed25519.Verify(publicKey, payload, signature) {
		return LinkSession{}, ErrHandshakeFailed
	}
	h.Consumed = true
	if err := s.store.writeHandshake(h); err != nil {
		return LinkSession{}, err
	}
	now := s.clock.Now().UTC()
	receipt := ProofReceipt{
		SchemaVersion:            SchemaVersion,
		SessionID:                req.SessionID,
		LocalDeviceID:            h.ChallengerDeviceID,
		PeerDeviceID:             req.PeerDeviceID,
		PeerPublicKeyFingerprint: trusted.PublicKeyFingerprint,
		ChallengeFingerprint:     sha256String(h.Challenge)[:16],
		SignatureFingerprint:     sha256String(req.Signature)[:16],
		VerifiedAt:               now,
		ExpiresAt:                now.Add(defaultLinkTTL),
	}
	receipt.ReceiptFingerprint = proofReceiptFingerprint(receipt)
	if err := s.upsertProofStatusLocked(req.PeerDeviceID, receipt); err != nil {
		return LinkSession{}, err
	}
	session := LinkSession{
		SessionID:     req.SessionID,
		LocalDeviceID: h.ChallengerDeviceID,
		PeerDeviceID:  req.PeerDeviceID,
		EstablishedAt: now,
		ExpiresAt:     receipt.ExpiresAt,
		Status:        "linked",
		ProofReceipt:  &receipt,
	}
	return session, nil
}

func (s *Service) TestLink(ctx context.Context, deviceID string) (LinkTestResult, error) {
	ctx = normalizeContext(ctx)
	if err := contextError(ctx); err != nil {
		return LinkTestResult{}, err
	}
	linkCtx := ctx
	var cancel context.CancelFunc
	if _, ok := ctx.Deadline(); !ok {
		linkCtx, cancel = context.WithTimeout(ctx, defaultTransportTimeout)
		defer cancel()
	}
	s.mu.Lock()
	peer, err := s.peerForDeviceLocked(deviceID)
	if err != nil {
		s.mu.Unlock()
		return LinkTestResult{}, err
	}
	transport := s.transport
	s.mu.Unlock()
	if transport == nil {
		return LinkTestResult{}, ErrTransportUnavailable
	}
	start := s.clock.Now()
	conn, err := transport.Open(linkCtx, peer)
	if err != nil {
		if safeErr := transportPublicError(linkCtx, err); safeErr != nil {
			return LinkTestResult{}, safeErr
		}
		return LinkTestResult{}, ErrTransportUnavailable
	}
	defer conn.Close()
	if err := conn.Send(linkCtx, Message{Kind: "ping", ToDeviceID: deviceID, CreatedAt: s.clock.Now().UTC()}); err != nil {
		return LinkTestResult{}, transportPublicError(linkCtx, err)
	}
	msg, err := conn.Receive(linkCtx)
	if err != nil {
		return LinkTestResult{}, transportPublicError(linkCtx, err)
	}
	if msg.Kind != "pong" || (msg.FromDeviceID != "" && msg.FromDeviceID != deviceID) {
		return LinkTestResult{}, ErrTransportUnavailable
	}
	latency := s.clock.Now().Sub(start).Milliseconds()
	s.mu.Lock()
	if err := s.upsertReachabilityStatusLocked(deviceID, true, "reachable"); err != nil {
		s.mu.Unlock()
		return LinkTestResult{}, err
	}
	s.mu.Unlock()
	return LinkTestResult{DeviceID: deviceID, OK: true, Status: "ok", LatencyMillis: latency, Message: "link reachable"}, nil
}

// EvaluateProof evaluates only durable signed-handshake evidence. Reachability,
// registry import, app membership, passphrases, and payload policy cannot make
// this result satisfied.
func (s *Service) EvaluateProof(ctx context.Context, deviceID string) (ProofEvaluation, error) {
	if err := contextError(ctx); err != nil {
		return ProofEvaluation{}, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	now := s.clock.Now().UTC()
	dev, found, err := s.findTrustedDeviceLocked(deviceID)
	if err != nil {
		return ProofEvaluation{}, err
	}
	if !found {
		return ProofEvaluation{DeviceID: deviceID, TrustStatus: TrustUnknown, State: ProofStateUnverified, EvaluatedAt: now, Reason: "no signed proof is recorded"}, nil
	}
	links, err := s.store.readLinks()
	if err != nil {
		return ProofEvaluation{}, err
	}
	link := ConnectionStatus{DeviceID: deviceID, TrustStatus: dev.TrustStatus, ProofState: ProofStateUnverified}
	for _, candidate := range links.Links {
		if candidate.DeviceID == deviceID {
			link = candidate
			break
		}
	}
	localDeviceID := ""
	if link.ProofReceipt != nil {
		current, err := s.store.readIdentity()
		if err != nil {
			return ProofEvaluation{}, err
		}
		localDeviceID = current.DeviceID
	}
	return evaluateProof(now, localDeviceID, dev, link), nil
}

func (s *Service) GetConnectionStatus(ctx context.Context, deviceID string) (ConnectionStatus, error) {
	if err := contextError(ctx); err != nil {
		return ConnectionStatus{}, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	dev, found, err := s.findTrustedDeviceLocked(deviceID)
	if err != nil {
		return ConnectionStatus{}, err
	}
	if !found {
		return ConnectionStatus{DeviceID: deviceID, TrustStatus: TrustUnknown, ProofState: ProofStateUnverified, Message: "device is not trusted"}, nil
	}
	if dev.TrustStatus == TrustRevoked {
		return ConnectionStatus{DeviceID: deviceID, TrustStatus: TrustRevoked, ProofState: ProofStateRejected, Message: "device is revoked"}, nil
	}
	links, err := s.store.readLinks()
	if err != nil {
		return ConnectionStatus{}, err
	}
	for _, link := range links.Links {
		if link.DeviceID == deviceID {
			link.TrustStatus = dev.TrustStatus
			link.Stale = isStale(s.clock.Now().UTC(), link.LastSeen)
			if link.ProofState == "" {
				link.ProofState = ProofStateUnverified
			}
			if link.ProofReceipt != nil {
				current, err := s.store.readIdentity()
				if err != nil {
					return ConnectionStatus{}, err
				}
				link.ProofState = evaluateProof(s.clock.Now().UTC(), current.DeviceID, dev, link).State
			}
			if link.Stale {
				link.Message = "device is stale"
			}
			return link, nil
		}
	}
	return ConnectionStatus{DeviceID: deviceID, TrustStatus: dev.TrustStatus, LastSeen: dev.LastSeen, Stale: isStale(s.clock.Now().UTC(), dev.LastSeen), ProofState: ProofStateUnverified, Message: "no active link"}, nil
}

func transportContextError(ctx context.Context, err error) error {
	if errors.Is(err, ErrContextCanceled) || contextError(ctx) != nil {
		return ErrContextCanceled
	}
	return err
}

func transportPublicError(ctx context.Context, err error) error {
	if errors.Is(err, ErrContextCanceled) || contextError(ctx) != nil {
		return ErrContextCanceled
	}
	return ErrTransportUnavailable
}

func (s *Service) privateKey() (ed25519.PrivateKey, error) {
	encoded, err := s.store.readPrivateKey()
	if err != nil {
		return nil, err
	}
	return decodePrivateKey(encoded)
}

func (s *Service) findTrustedDeviceLocked(deviceID string) (TrustedDevice, bool, error) {
	reg, err := s.store.readRegistry()
	if err != nil {
		return TrustedDevice{}, false, err
	}
	for _, dev := range reg.Devices {
		if dev.DeviceID == deviceID {
			return dev, true, nil
		}
	}
	return TrustedDevice{}, false, nil
}

func (s *Service) peerForDeviceLocked(deviceID string) (DiscoveredPeer, error) {
	dev, found, err := s.findTrustedDeviceLocked(deviceID)
	if err != nil {
		return DiscoveredPeer{}, err
	}
	if !found || dev.TrustStatus != TrustTrusted {
		return DiscoveredPeer{}, trustError(dev.TrustStatus)
	}
	peers, err := s.store.readPeers()
	if err != nil {
		return DiscoveredPeer{}, err
	}
	for _, rec := range peers.Peers {
		if rec.DeviceID == deviceID {
			if rec.PublicKeyFingerprint != dev.PublicKeyFingerprint {
				return DiscoveredPeer{}, ErrFingerprintMismatch
			}
			return DiscoveredPeer{Presence: rec, TrustStatus: dev.TrustStatus, Stale: isStale(s.clock.Now().UTC(), rec.LastSeen)}, nil
		}
	}
	return DiscoveredPeer{}, ErrTransportUnavailable
}

func (s *Service) upsertReachabilityStatusLocked(deviceID string, reachable bool, message string) error {
	links, err := s.store.readLinks()
	if err != nil {
		return err
	}
	now := s.clock.Now().UTC()
	for i, link := range links.Links {
		if link.DeviceID == deviceID {
			link.TrustStatus = TrustTrusted
			link.Reachable = reachable
			link.LastSeen = now
			link.Message = message
			if link.ProofState == "" {
				link.ProofState = ProofStateUnverified
			}
			links.Links[i] = link
			links.UpdatedAt = now
			return s.store.writeLinks(links)
		}
	}
	next := ConnectionStatus{DeviceID: deviceID, TrustStatus: TrustTrusted, Reachable: reachable, LastSeen: now, ProofState: ProofStateUnverified, Message: message}
	links.Links = append(links.Links, next)
	links.UpdatedAt = now
	return s.store.writeLinks(links)
}

func (s *Service) upsertProofStatusLocked(deviceID string, receipt ProofReceipt) error {
	links, err := s.store.readLinks()
	if err != nil {
		return err
	}
	now := s.clock.Now().UTC()
	for i, link := range links.Links {
		if link.DeviceID != deviceID {
			continue
		}
		link.TrustStatus = TrustTrusted
		link.Reachable = true
		link.LastSeen = now
		link.ProofState = ProofStateVerified
		link.ProofReceipt = &receipt
		link.Message = "signed proof verified"
		links.Links[i] = link
		links.UpdatedAt = now
		return s.store.writeLinks(links)
	}
	links.Links = append(links.Links, ConnectionStatus{
		DeviceID:     deviceID,
		TrustStatus:  TrustTrusted,
		Reachable:    true,
		LastSeen:     now,
		ProofState:   ProofStateVerified,
		ProofReceipt: &receipt,
		Message:      "signed proof verified",
	})
	links.UpdatedAt = now
	return s.store.writeLinks(links)
}

func trustError(status TrustStatus) error {
	switch status {
	case TrustRevoked:
		return ErrDeviceRevoked
	case TrustStale:
		return ErrDeviceStale
	default:
		return ErrDeviceNotTrusted
	}
}

func validResourceType(rt ResourceType) bool {
	switch rt {
	case ResourceService, ResourceData, ResourceConnector, ResourceRuntime, ResourceTool, ResourceOther:
		return true
	default:
		return false
	}
}

func compactStrings(in []string) []string {
	seen := map[string]bool{}
	var out []string
	for _, item := range in {
		item = strings.TrimSpace(item)
		if item == "" || seen[item] {
			continue
		}
		seen[item] = true
		out = append(out, item)
	}
	sort.Strings(out)
	return out
}

func summarizeResources(resources []ResourceDescriptor) []ResourceSummary {
	counts := map[ResourceType]int{}
	for _, res := range resources {
		counts[res.Type]++
	}
	var out []ResourceSummary
	for rt, count := range counts {
		out = append(out, ResourceSummary{Type: rt, Count: count})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Type < out[j].Type })
	return out
}

func snapshotFingerprint(snapshot RegistrySnapshot) string {
	canonical := snapshot
	canonical.SnapshotFingerprint = ""
	canonical.Devices = append([]TrustedDevice{}, snapshot.Devices...)
	for i := range canonical.Devices {
		canonical.Devices[i].Capabilities = append([]string{}, canonical.Devices[i].Capabilities...)
		sort.Strings(canonical.Devices[i].Capabilities)
	}
	sort.Slice(canonical.Devices, func(i, j int) bool {
		if canonical.Devices[i].DeviceID == canonical.Devices[j].DeviceID {
			return canonical.Devices[i].PublicKeyFingerprint < canonical.Devices[j].PublicKeyFingerprint
		}
		return canonical.Devices[i].DeviceID < canonical.Devices[j].DeviceID
	})
	raw, _ := json.Marshal(canonical)
	sum := sha256String(string(raw))
	return sum[:16]
}

func validateRegistryBackupSnapshot(cfg AppConfig, snapshot RegistrySnapshot) error {
	if snapshot.SchemaVersion != SchemaVersion || snapshot.Purpose != RegistrySnapshotLocalBackup || snapshot.AppID != cfg.AppID || snapshot.Namespace != cfg.Namespace {
		return ErrInvalidRegistrySnapshot
	}
	if snapshot.ProfileMetadataVersion != MetadataVersion || snapshot.CreatedAt.IsZero() || snapshot.UpdatedAt.IsZero() || snapshot.UpdatedAt.Before(snapshot.CreatedAt) {
		return ErrInvalidRegistrySnapshot
	}
	if snapshot.OriginDeviceID != "" && !validSafeName(snapshot.OriginDeviceID) {
		return ErrInvalidRegistrySnapshot
	}
	if snapshot.SnapshotFingerprint == "" || snapshot.SnapshotFingerprint != snapshotFingerprint(snapshot) {
		return ErrInvalidRegistrySnapshot
	}
	seen := map[string]string{}
	for _, dev := range snapshot.Devices {
		if !validSafeName(dev.DeviceID) || strings.TrimSpace(dev.DisplayName) == "" || dev.DisplayName != strings.TrimSpace(dev.DisplayName) || dev.PublicKey == "" {
			return ErrInvalidRegistrySnapshot
		}
		if !validTrustStatus(dev.TrustStatus) || dev.ProfileMetadataVersion != MetadataVersion || !slices.Equal(dev.Capabilities, compactStrings(dev.Capabilities)) {
			return ErrInvalidRegistrySnapshot
		}
		if (dev.TrustStatus == TrustTrusted || dev.TrustStatus == TrustRevoked) && dev.TrustedAt.IsZero() {
			return ErrInvalidRegistrySnapshot
		}
		if dev.TrustStatus == TrustRevoked {
			if dev.RevokedAt == nil || dev.RevokedAt.Before(dev.TrustedAt) {
				return ErrInvalidRegistrySnapshot
			}
		} else if dev.RevokedAt != nil {
			return ErrInvalidRegistrySnapshot
		}
		publicKey, err := decodePublicKey(dev.PublicKey)
		if err != nil {
			return err
		}
		fingerprint := fingerprintPublicKey(publicKey)
		if dev.PublicKeyFingerprint != fingerprint {
			return ErrFingerprintMismatch
		}
		if old, ok := seen[dev.DeviceID]; ok {
			if old != fingerprint {
				return ErrFingerprintMismatch
			}
			return ErrInvalidRegistrySnapshot
		}
		seen[dev.DeviceID] = fingerprint
	}
	return nil
}

func validTrustStatus(status TrustStatus) bool {
	switch status {
	case TrustUnknown, TrustPending, TrustTrusted, TrustRevoked, TrustStale:
		return true
	default:
		return false
	}
}

func validateIdentityKeyPair(identity DeviceIdentity, privateKey ed25519.PrivateKey) error {
	publicKey, err := decodePublicKey(identity.PublicKey)
	if err != nil || identity.PublicKeyFingerprint != fingerprintPublicKey(publicKey) {
		return ErrStorageUnavailable
	}
	derived, ok := privateKey.Public().(ed25519.PublicKey)
	if !ok || !bytes.Equal(publicKey, derived) {
		return ErrStorageUnavailable
	}
	return nil
}

func publicIdentityBundleFingerprint(bundle PublicIdentityBundle) string {
	canonical := bundle
	canonical.BundleFingerprint = ""
	canonical.Capabilities = append([]string{}, bundle.Capabilities...)
	sort.Strings(canonical.Capabilities)
	raw, _ := json.Marshal(canonical)
	return sha256String(string(raw))
}

func publicIdentityBundleFromIdentity(identity DeviceIdentity) PublicIdentityBundle {
	bundle := PublicIdentityBundle{
		SchemaVersion:        SchemaVersion,
		BundleVersion:        IdentityBundleVersion,
		DeviceID:             identity.DeviceID,
		DisplayName:          identity.DisplayName,
		AppID:                identity.AppID,
		Namespace:            identity.Namespace,
		PublicKey:            identity.PublicKey,
		PublicKeyFingerprint: identity.PublicKeyFingerprint,
		CreatedAt:            identity.CreatedAt,
		UpdatedAt:            identity.UpdatedAt,
		Capabilities:         append([]string{}, identity.Capabilities...),
		MetadataVersion:      identity.MetadataVersion,
	}
	bundle.BundleFingerprint = publicIdentityBundleFingerprint(bundle)
	return bundle
}

func proofReceiptFingerprint(receipt ProofReceipt) string {
	canonical := receipt
	canonical.ReceiptFingerprint = ""
	raw, _ := json.Marshal(canonical)
	return sha256String(string(raw))
}

func evaluateProof(now time.Time, localDeviceID string, dev TrustedDevice, link ConnectionStatus) ProofEvaluation {
	evaluation := ProofEvaluation{
		DeviceID:    dev.DeviceID,
		TrustStatus: dev.TrustStatus,
		State:       ProofStateUnverified,
		Reachable:   link.Reachable,
		EvaluatedAt: now,
		Reason:      "no signed proof is recorded",
	}
	if dev.TrustStatus != TrustTrusted {
		evaluation.State = ProofStateRejected
		evaluation.Reason = "device trust does not permit proof acceptance"
		return evaluation
	}
	if link.ProofReceipt == nil {
		return evaluation
	}
	receipt := *link.ProofReceipt
	evaluation.Receipt = &receipt
	if receipt.SchemaVersion != SchemaVersion || !validSessionID(receipt.SessionID) || receipt.LocalDeviceID != localDeviceID || receipt.PeerDeviceID != dev.DeviceID || receipt.PeerPublicKeyFingerprint != dev.PublicKeyFingerprint || receipt.VerifiedAt.IsZero() || receipt.ExpiresAt.IsZero() || !receipt.ExpiresAt.After(receipt.VerifiedAt) || receipt.ChallengeFingerprint == "" || receipt.SignatureFingerprint == "" || receipt.ReceiptFingerprint == "" || receipt.ReceiptFingerprint != proofReceiptFingerprint(receipt) {
		evaluation.State = ProofStateRejected
		evaluation.Reason = "stored signed proof is invalid"
		return evaluation
	}
	if now.After(receipt.ExpiresAt) {
		evaluation.State = ProofStateExpired
		evaluation.Reason = "signed proof has expired"
		return evaluation
	}
	evaluation.State = ProofStateVerified
	evaluation.Satisfied = true
	evaluation.Reason = "signed device proof is verified"
	return evaluation
}

func sha256String(s string) string {
	sum := sha256.Sum256([]byte(s))
	return hex.EncodeToString(sum[:])
}

func handshakePayload(appID, namespace, challengerDeviceID, responderDeviceID, challenge string) []byte {
	parts := []string{
		"aegis-devicelink-v1",
		appID,
		namespace,
		challengerDeviceID,
		responderDeviceID,
		challenge,
	}
	return []byte(strings.Join(parts, "\n"))
}

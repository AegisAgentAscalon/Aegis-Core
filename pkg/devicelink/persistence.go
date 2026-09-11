package devicelink

import (
	"context"
	"crypto/ed25519"
	"errors"
	"time"
)

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
		ProofState:   ProofStateVerified,
		ProofReceipt: &receipt,
		Message:      "signed proof verified",
	})
	links.UpdatedAt = now
	return s.store.writeLinks(links)
}

func (s *Service) clearDeviceLinkStatusLocked(deviceID string, updatedAt time.Time) error {
	links, err := s.store.readLinks()
	if err != nil {
		return err
	}
	links, changed := withoutDeviceLinkStatus(links, deviceID, updatedAt)
	if !changed {
		return nil
	}
	return s.store.writeLinks(links)
}

func withoutDeviceLinkStatus(links linkStatusFile, deviceID string, updatedAt time.Time) (linkStatusFile, bool) {
	filtered := make([]ConnectionStatus, 0, len(links.Links))
	changed := false
	for _, link := range links.Links {
		if link.DeviceID == deviceID {
			changed = true
			continue
		}
		filtered = append(filtered, link)
	}
	if changed {
		links.Links = filtered
		links.UpdatedAt = updatedAt.UTC()
	}
	return links, changed
}

func latestProofTime(links linkStatusFile, deviceID string) time.Time {
	var latest time.Time
	for _, link := range links.Links {
		if link.DeviceID == deviceID && link.ProofReceipt != nil && link.ProofReceipt.VerifiedAt.After(latest) {
			latest = link.ProofReceipt.VerifiedAt
		}
	}
	return latest
}

func nextTrustTransitionTime(now time.Time, boundaries ...time.Time) time.Time {
	latest := now.UTC()
	for _, boundary := range boundaries {
		if boundary.After(latest) {
			latest = boundary.UTC()
		}
	}
	return latest.Add(time.Nanosecond)
}

func cloneTrustedDevices(in []TrustedDevice) []TrustedDevice {
	out := make([]TrustedDevice, len(in))
	for i, dev := range in {
		out[i] = dev
		out[i].Capabilities = append([]string{}, dev.Capabilities...)
		if dev.RevokedAt != nil {
			revokedAt := *dev.RevokedAt
			out[i].RevokedAt = &revokedAt
		}
	}
	return out
}

func cloneRegistryFile(reg registryFile) registryFile {
	reg.Devices = cloneTrustedDevices(reg.Devices)
	return reg
}

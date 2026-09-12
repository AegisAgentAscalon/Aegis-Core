package devicelink

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"strings"
)

func (s *Service) StartHandshake(ctx context.Context, peer DiscoveredPeer) (HandshakeStartResult, error) {
	now, err := s.lockAtTime(ctx)
	if err != nil {
		return HandshakeStartResult{}, err
	}
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
	expires := now.Add(defaultLinkTTL)
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
	now, err := s.lockAtTime(ctx)
	if err != nil {
		return LinkSession{}, err
	}
	defer s.mu.Unlock()
	h, err := s.store.readHandshake(req.SessionID)
	if err != nil {
		return LinkSession{}, err
	}
	if h.Consumed {
		return LinkSession{}, ErrChallengeReplay
	}
	if !now.Before(h.ExpiresAt) {
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
	if now.Before(trusted.TrustedAt) {
		now = trusted.TrustedAt
	}
	receipt := ProofReceipt{
		SchemaVersion:            schemaVersion,
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
	if err := s.upsertProofStatusLocked(req.PeerDeviceID, receipt, now); err != nil {
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

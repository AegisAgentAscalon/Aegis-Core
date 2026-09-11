package devicelink

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"strings"
)

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
	if !s.clock.Now().UTC().Before(h.ExpiresAt) {
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

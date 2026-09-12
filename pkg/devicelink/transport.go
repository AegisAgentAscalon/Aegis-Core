package devicelink

import "context"

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
	now, err := s.lockAtTime(linkCtx)
	if err != nil {
		return LinkTestResult{}, err
	}
	peer, err := s.peerForDeviceLocked(deviceID, now)
	if err != nil {
		s.mu.Unlock()
		return LinkTestResult{}, err
	}
	transport := s.transport
	s.mu.Unlock()
	if transport == nil {
		return LinkTestResult{}, ErrTransportUnavailable
	}
	start, err := s.operationTime(linkCtx)
	if err != nil {
		return LinkTestResult{}, err
	}
	conn, err := transport.Open(linkCtx, peer)
	if err != nil {
		return LinkTestResult{}, transportPublicError(linkCtx, err)
	}
	defer conn.Close()
	sentAt, err := s.operationTime(linkCtx)
	if err != nil {
		return LinkTestResult{}, err
	}
	if err := conn.Send(linkCtx, Message{Kind: "ping", ToDeviceID: deviceID, CreatedAt: sentAt}); err != nil {
		return LinkTestResult{}, transportPublicError(linkCtx, err)
	}
	msg, err := conn.Receive(linkCtx)
	if err != nil {
		return LinkTestResult{}, transportPublicError(linkCtx, err)
	}
	if msg.Kind != "pong" || (msg.FromDeviceID != "" && msg.FromDeviceID != deviceID) {
		return LinkTestResult{}, ErrTransportUnavailable
	}
	completedAt, err := s.operationTime(linkCtx)
	if err != nil {
		return LinkTestResult{}, err
	}
	latency := completedAt.Sub(start).Milliseconds()
	// Network latency excludes contention while recording the result. The
	// persisted observation must still be fresh when this transaction acquires
	// the owner mutex.
	recordedAt, err := s.lockAtTime(linkCtx)
	if err != nil {
		return LinkTestResult{}, err
	}
	defer s.mu.Unlock()
	// The provider may have reentered or another call may have changed trust
	// during transport. Revalidate the authoritative registry before writing.
	trusted, found, err := s.findTrustedDeviceLocked(deviceID)
	if err != nil {
		return LinkTestResult{}, err
	}
	if !found || trusted.TrustStatus != TrustTrusted {
		return LinkTestResult{}, trustError(trusted.TrustStatus)
	}
	if trusted.PublicKeyFingerprint != peer.Presence.PublicKeyFingerprint {
		return LinkTestResult{}, ErrFingerprintMismatch
	}
	if err := s.upsertReachabilityStatusLocked(deviceID, true, "reachable", recordedAt); err != nil {
		return LinkTestResult{}, err
	}
	return LinkTestResult{DeviceID: deviceID, OK: true, Status: "ok", LatencyMillis: latency, Message: "link reachable"}, nil
}

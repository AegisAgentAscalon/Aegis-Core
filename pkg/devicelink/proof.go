package devicelink

import "context"

// EvaluateProof evaluates only durable signed-handshake evidence. Reachability,
// registry import, app membership, passphrases, and payload policy cannot make
// this result satisfied.
func (s *Service) EvaluateProof(ctx context.Context, deviceID string) (ProofEvaluation, error) {
	now, err := s.lockAtTime(ctx)
	if err != nil {
		return ProofEvaluation{}, err
	}
	defer s.mu.Unlock()
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
	now, err := s.lockAtTime(ctx)
	if err != nil {
		return ConnectionStatus{}, err
	}
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
			link.Stale = isStale(now, link.LastSeen)
			if link.ProofState == "" {
				link.ProofState = ProofStateUnverified
			}
			if link.ProofReceipt != nil {
				current, err := s.store.readIdentity()
				if err != nil {
					return ConnectionStatus{}, err
				}
				link.ProofState = evaluateProof(now, current.DeviceID, dev, link).State
			}
			if link.Stale {
				link.Message = "device is stale"
			}
			return link, nil
		}
	}
	return ConnectionStatus{DeviceID: deviceID, TrustStatus: dev.TrustStatus, LastSeen: dev.LastSeen, Stale: isStale(now, dev.LastSeen), ProofState: ProofStateUnverified, Message: "no active link"}, nil
}

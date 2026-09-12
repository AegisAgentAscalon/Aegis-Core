package devicelink

import (
	"encoding/json"
	"strings"
	"time"
)

func proofReceiptFingerprint(receipt ProofReceipt) string {
	canonical := receipt
	canonical.ReceiptFingerprint = ""
	raw, err := json.Marshal(canonical)
	if err != nil {
		return ""
	}
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
	if receipt.SchemaVersion != schemaVersion || !validSessionID(receipt.SessionID) || receipt.LocalDeviceID != localDeviceID || receipt.PeerDeviceID != dev.DeviceID || receipt.PeerPublicKeyFingerprint != dev.PublicKeyFingerprint || receipt.VerifiedAt.IsZero() || receipt.VerifiedAt.Before(dev.TrustedAt) || receipt.ExpiresAt.IsZero() || !receipt.ExpiresAt.After(receipt.VerifiedAt) || receipt.ChallengeFingerprint == "" || receipt.SignatureFingerprint == "" || receipt.ReceiptFingerprint == "" || receipt.ReceiptFingerprint != proofReceiptFingerprint(receipt) {
		evaluation.State = ProofStateRejected
		evaluation.Reason = "stored signed proof is invalid"
		return evaluation
	}
	if !now.Before(receipt.ExpiresAt) {
		evaluation.State = ProofStateExpired
		evaluation.Reason = "signed proof has expired"
		return evaluation
	}
	evaluation.State = ProofStateVerified
	evaluation.Satisfied = true
	evaluation.Reason = "signed device proof is verified"
	return evaluation
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

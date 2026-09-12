package devicelink

import (
	"context"
	"time"
)

type ProofState string

const (
	ProofStateUnverified ProofState = "unverified"
	ProofStateVerified   ProofState = "verified"
	ProofStateExpired    ProofState = "expired"
	ProofStateRejected   ProofState = "rejected"
)

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

type Transport interface {
	Open(ctx context.Context, peer DiscoveredPeer) (Connection, error)
}

type Connection interface {
	Send(ctx context.Context, msg Message) error
	Receive(ctx context.Context) (Message, error)
	Close() error
}

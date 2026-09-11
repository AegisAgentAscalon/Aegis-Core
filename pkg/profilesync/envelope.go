package profilesync

import (
	"time"

	"github.com/AegisAgentAscalon/aegis-core/pkg/profilemesh"
)

func snapshotEnvelope(namespace, deviceID string, snapshot profilemesh.SignedProfileSnapshot, now time.Time) SyncEnvelope {
	return SyncEnvelope{SchemaVersion: EnvelopeSchemaVersion, Kind: EnvelopeKindSnapshot, ProfileNamespace: namespace, SourceDeviceID: deviceID, MessageID: "snapshot-" + snapshot.Metadata.SnapshotID, CreatedAt: now, Snapshot: &snapshot}
}

func proposalEnvelope(namespace, deviceID string, proposal profilemesh.ProfileChangeProposal, now time.Time) SyncEnvelope {
	return SyncEnvelope{SchemaVersion: EnvelopeSchemaVersion, Kind: EnvelopeKindProposal, ProfileNamespace: namespace, SourceDeviceID: deviceID, MessageID: "proposal-" + proposal.ProposalID, CreatedAt: now, Proposal: &proposal}
}

func validateEnvelopeHeader(envelope SyncEnvelope, namespace string) error {
	return validateEnvelopeHeaderAt(envelope, namespace, time.Now().UTC())
}

func validateEnvelopeHeaderAt(envelope SyncEnvelope, namespace string, now time.Time) error {
	if envelope.SchemaVersion != EnvelopeSchemaVersion || !validSyncName(envelope.ProfileNamespace) || envelope.ProfileNamespace != namespace || !validSyncID(envelope.SourceDeviceID) || !validSyncID(envelope.MessageID) || envelope.CreatedAt.IsZero() {
		return ErrInvalidSyncEnvelope
	}
	if now.IsZero() {
		now = time.Now().UTC()
	}
	if envelope.CreatedAt.After(now.Add(defaultClockSkew)) {
		return ErrInvalidSyncEnvelope
	}
	switch envelope.Kind {
	case EnvelopeKindSnapshot:
		if envelope.Snapshot == nil {
			return ErrInvalidSyncEnvelope
		}
	case EnvelopeKindProposal:
		if envelope.Proposal == nil {
			return ErrInvalidSyncEnvelope
		}
	default:
		return ErrInvalidSyncEnvelope
	}
	return nil
}

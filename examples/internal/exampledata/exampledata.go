// Package exampledata contains synthetic example inputs and output checks.
// Its internal location prevents library packages from depending on example setup.
package exampledata

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/AegisAgentAscalon/aegis-core/pkg/profilemesh"
)

func Snapshot(namespace, profileID, snapshotID, parentID, sourceDeviceID string, now time.Time) profilemesh.SignedProfileSnapshot {
	return profilemesh.SignedProfileSnapshot{
		Metadata: profilemesh.ProfileSnapshotMetadata{
			SchemaVersion:       1,
			ProfileNamespace:    namespace,
			ProfileID:           profileID,
			SnapshotID:          snapshotID,
			SnapshotFingerprint: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
			ParentSnapshotID:    parentID,
			SourceDeviceID:      sourceDeviceID,
			HostingMode:         profilemesh.HostingSingleProfileDevice,
			CreatedAt:           now.Add(-time.Minute),
			UpdatedAt:           now,
			ExpiresAt:           now.Add(time.Hour),
			MetadataVersion:     1,
		},
		Signature: profilemesh.SnapshotSignatureSummary{
			SignerDeviceID:       sourceDeviceID,
			SignerKeyFingerprint: "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
			SignatureFingerprint: "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc",
			Algorithm:            "generic-ed25519-summary",
			SignedAt:             now,
		},
	}
}

func WriteJSON(path string, value any) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	file, err := os.OpenFile(path, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}
	encodeErr := json.NewEncoder(file).Encode(value)
	closeErr := file.Close()
	if encodeErr != nil {
		return encodeErr
	}
	return closeErr
}

func OutputSafe(value any, extraForbidden string, payloadMarkers ...string) bool {
	raw, err := json.Marshal(value)
	if err != nil {
		return false
	}
	text := strings.ToLower(string(raw))
	for _, forbidden := range append([]string{
		`:\`,
		"/users/",
		"/home/",
		"appdata",
		"raw payload",
	}, payloadMarkers...) {
		if strings.Contains(text, forbidden) {
			return false
		}
	}
	if strings.TrimSpace(extraForbidden) != "" && strings.Contains(text, strings.ToLower(extraForbidden)) {
		return false
	}
	return true
}

package profilemesh

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"testing"
	"time"
)

func TestSnapshotImportRejectsUnencodableFingerprintInput(t *testing.T) {
	for _, version := range []struct {
		name   string
		schema int
	}{{"legacy", legacyProfileMeshSnapshotSchemaVersion}, {"current", ProfileMeshSnapshotSchemaVersion}} {
		t.Run(version.name, func(t *testing.T) {
			svc, snapshot := w08Service(t)
			before := w08Bytes(t, svc)
			snapshot.SchemaVersion = version.schema
			snapshot.Profile.DisplayName = "unbound replacement"
			// Go accepts this fixed zone but its JSON encoder rejects +24:00.
			// The outer CreatedAt is not copied into persisted profile state.
			snapshot.CreatedAt = time.Date(2026, 9, 12, 12, 0, 0, 0, time.FixedZone("invalid", 24*60*60))
			if _, err := json.Marshal(snapshot); err == nil {
				t.Fatal("fixture did not exercise a JSON encoding error")
			}
			snapshot.SnapshotFingerprint = "e3b0c44298fc1c14" // SHA-256 of an empty encoding.
			if version.schema == legacyProfileMeshSnapshotSchemaVersion {
				snapshot.SnapshotFingerprint = legacyProfileMeshSnapshotFingerprint(snapshot)
			}
			if err := svc.ImportProfileMeshSnapshot(context.Background(), snapshot); !errors.Is(err, ErrInvalidProfileSnapshot) {
				t.Fatalf("unencodable snapshot import = %v", err)
			}
			w08Unchanged(t, svc, before)
		})
	}
}

func TestSnapshotExportRejectsUnencodableLegacyTime(t *testing.T) {
	now := time.Date(2026, 9, 12, 12, 0, 0, 0, time.UTC)
	svc := newTestService(t, "legacy", WithClock(&testClock{now: now}))
	w14WriteLegacy(t, svc, w14LegacyState(now))
	path := svc.store.profilePath()
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	raw = bytes.Replace(raw, []byte(`12:00:00Z`), []byte(`12:00:00+24:00`), 1)
	if err := os.WriteFile(path, raw, 0600); err != nil {
		t.Fatal(err)
	}
	before := w08Bytes(t, svc)
	if _, err := svc.ExportProfileMeshSnapshot(context.Background()); !errors.Is(err, ErrStorageUnavailable) {
		t.Fatalf("unencodable legacy export = %v", err)
	}
	w08Unchanged(t, svc, before)
}

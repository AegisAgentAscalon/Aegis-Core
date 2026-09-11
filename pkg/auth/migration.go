package auth

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"

	"github.com/AegisAgentAscalon/aegis-core/pkg/secretstore"
)

type migrationRecord struct {
	key           secretstore.Key
	value         []byte
	expected      secretstore.Revision
	needsWrite    bool
	cleanupLegacy bool
}

type migrationWrite struct {
	key      secretstore.Key
	revision secretstore.Revision
}

func (s *store) migrateLegacySecrets(ctx context.Context) error {
	tokenPlan, err := s.planLegacyToken(ctx)
	if err != nil {
		return err
	}
	sessionsPlan, err := s.planLegacySessions(ctx)
	if err != nil {
		return err
	}

	plans := []migrationRecord{tokenPlan, sessionsPlan}
	writes := make([]migrationWrite, 0, len(plans))
	for _, plan := range plans {
		if !plan.needsWrite {
			continue
		}
		revision, err := s.versioned.CompareAndSwap(ctx, plan.key, plan.expected, plan.value)
		if err != nil {
			s.rollbackMigrationWrites(ctx, writes)
			return ErrStorageUnavailable
		}
		writes = append(writes, migrationWrite{key: plan.key, revision: revision})
		readBack, readRevision, err := s.versioned.GetWithRevision(ctx, plan.key)
		if err != nil || readRevision != revision || !bytes.Equal(readBack, plan.value) {
			s.rollbackMigrationWrites(ctx, writes)
			return ErrStorageUnavailable
		}
	}

	if tokenPlan.cleanupLegacy {
		if err := removeLegacyFile(s.tokenPath()); err != nil {
			return err
		}
	}
	if sessionsPlan.cleanupLegacy {
		if err := removeLegacySessions(s.sessionsDir()); err != nil {
			return err
		}
	}
	return nil
}

func (s *store) planLegacyToken(ctx context.Context) (migrationRecord, error) {
	plan := migrationRecord{key: s.tokenKey}
	protectedRecord, revision, err := s.versioned.GetWithRevision(ctx, s.tokenKey)
	switch {
	case err == nil:
		if _, decodeErr := decodeProtectedToken(protectedRecord); decodeErr != nil {
			return migrationRecord{}, ErrProtectedStorageCorrupt
		}
		plan.cleanupLegacy = true
		return plan, nil
	case !errors.Is(err, secretstore.ErrNotFound):
		return migrationRecord{}, ErrStorageUnavailable
	}

	legacyRecord, err := os.ReadFile(s.tokenPath())
	if errors.Is(err, os.ErrNotExist) {
		return plan, nil
	}
	if err != nil {
		return migrationRecord{}, ErrStorageUnavailable
	}
	if _, err := decodeProtectedToken(legacyRecord); err != nil {
		return migrationRecord{}, ErrStorageUnavailable
	}
	plan.value = append([]byte(nil), legacyRecord...)
	plan.expected = revision
	plan.needsWrite = true
	plan.cleanupLegacy = true
	return plan, nil
}

func (s *store) planLegacySessions(ctx context.Context) (migrationRecord, error) {
	plan := migrationRecord{key: s.sessionsKey}
	protectedRecord, revision, err := s.versioned.GetWithRevision(ctx, s.sessionsKey)
	switch {
	case err == nil:
		if _, decodeErr := decodeProtectedSessions(protectedRecord); decodeErr != nil {
			return migrationRecord{}, ErrProtectedStorageCorrupt
		}
		plan.cleanupLegacy = true
		return plan, nil
	case !errors.Is(err, secretstore.ErrNotFound):
		return migrationRecord{}, ErrStorageUnavailable
	}

	sessions, exists, err := readLegacySessions(s.sessionsDir())
	if err != nil {
		return migrationRecord{}, err
	}
	if !exists {
		return plan, nil
	}
	plan.cleanupLegacy = true
	if len(sessions) == 0 {
		return plan, nil
	}
	record, err := encodeProtectedSessions(sessions)
	if err != nil {
		return migrationRecord{}, err
	}
	plan.value = record
	plan.expected = revision
	plan.needsWrite = true
	return plan, nil
}

func (s *store) rollbackMigrationWrites(ctx context.Context, writes []migrationWrite) {
	for i := len(writes) - 1; i >= 0; i-- {
		_, _ = s.versioned.CompareAndDelete(ctx, writes[i].key, writes[i].revision)
	}
}

func readLegacySessions(dir string) ([]pendingSession, bool, error) {
	files, err := os.ReadDir(dir)
	if errors.Is(err, os.ErrNotExist) {
		return nil, false, nil
	}
	if err != nil || len(files) > maxPendingSessionFiles {
		return nil, true, ErrStorageUnavailable
	}
	sessions := make([]pendingSession, 0, len(files))
	seenIDs := make(map[string]bool, len(files))
	seenStates := make(map[string]bool, len(files))
	for _, file := range files {
		if file.IsDir() {
			return nil, true, ErrStorageUnavailable
		}
		b, err := os.ReadFile(filepath.Join(dir, file.Name()))
		if err != nil {
			return nil, true, ErrStorageUnavailable
		}
		var sess pendingSession
		if err := json.Unmarshal(b, &sess); err != nil || validatePendingSession(sess) != nil {
			return nil, true, ErrStorageUnavailable
		}
		if file.Name() != sess.SessionID+".json" || seenIDs[sess.SessionID] || seenStates[sess.State] {
			return nil, true, ErrStorageUnavailable
		}
		seenIDs[sess.SessionID] = true
		seenStates[sess.State] = true
		sessions = append(sessions, sess)
	}
	return sessions, true, nil
}

func removeLegacyFile(path string) error {
	if err := os.Remove(path); err != nil && !errors.Is(err, os.ErrNotExist) {
		return ErrStorageUnavailable
	}
	return nil
}

func removeLegacySessions(dir string) error {
	if err := os.RemoveAll(dir); err != nil {
		return ErrStorageUnavailable
	}
	return nil
}

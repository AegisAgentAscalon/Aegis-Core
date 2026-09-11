package auth

import (
	"context"
	"encoding/json"
	"errors"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/AegisAgentAscalon/aegis-core/pkg/secretstore"
)

const maxPendingSessionFiles = 5

const protectedSessionsVersion = 1

const maxProtectedSessionCASAttempts = 32

type protectedPendingSessions struct {
	Version  int              `json:"version"`
	Sessions []pendingSession `json:"sessions"`
}

func (s *store) writeSession(sess pendingSession) error {
	if s.isStrict() {
		if err := validatePendingSession(sess); err != nil {
			return ErrStorageUnavailable
		}
		return s.mutateProtectedSessions(func(sessions []pendingSession) ([]pendingSession, error) {
			return appendPendingSession(sessions, sess, time.Now().UTC())
		})
	}
	if err := ensurePrivateDir(s.sessionsDir()); err != nil {
		return ErrStorageUnavailable
	}
	b, err := json.MarshalIndent(sess, "", "  ")
	if err != nil {
		return ErrStorageUnavailable
	}
	return writeFileAtomic(s.sessionPath(sess.SessionID), b, 0o600)
}

// Keep the existing bounded record format. Forgotten states cannot be claimed:
// consumeSessionByState rejects unknown states before any token exchange.
func appendPendingSession(sessions []pendingSession, sess pendingSession, now time.Time) ([]pendingSession, error) {
	kept := sessions[:0]
	for _, existing := range sessions {
		if !now.After(existing.ExpiresAt) {
			kept = append(kept, existing)
		}
	}
	for i := range kept {
		if kept[i].SessionID == sess.SessionID {
			if kept[i].Consumed && !sess.Consumed {
				return nil, ErrSessionConsumed
			}
			kept[i] = sess
			return kept, nil
		}
	}
	if len(kept) >= maxPendingSessionFiles {
		consumed := -1
		for i := range kept {
			if kept[i].Consumed && (consumed < 0 || kept[i].ExpiresAt.Before(kept[consumed].ExpiresAt)) {
				consumed = i
			}
		}
		if consumed < 0 {
			return nil, ErrStorageUnavailable
		}
		kept = append(kept[:consumed], kept[consumed+1:]...)
	}
	return append(kept, sess), nil
}

func (s *store) readSession(sessionID string) (pendingSession, error) {
	if s.isStrict() {
		sessions, err := s.readProtectedSessions()
		if err != nil {
			return pendingSession{}, err
		}
		for _, sess := range sessions {
			if sess.SessionID == sessionID {
				return sess, nil
			}
		}
		return pendingSession{}, secretstore.ErrNotFound
	}
	b, err := os.ReadFile(s.sessionPath(sessionID))
	if err != nil {
		return pendingSession{}, err
	}
	var sess pendingSession
	if err := json.Unmarshal(b, &sess); err != nil {
		return pendingSession{}, ErrInvalidProviderResponse
	}
	return sess, nil
}

func (s *store) findSessionByState(state string) (pendingSession, error) {
	state = strings.TrimSpace(state)
	if state == "" {
		return pendingSession{}, errors.New("state is required")
	}
	if s.isStrict() {
		sessions, err := s.readProtectedSessions()
		if errors.Is(err, secretstore.ErrNotFound) {
			return pendingSession{}, ErrSessionNotFound
		}
		if err != nil {
			return pendingSession{}, err
		}
		for _, sess := range sessions {
			if sess.State == state {
				return sess, nil
			}
		}
		return pendingSession{}, ErrSessionNotFound
	}
	files, err := os.ReadDir(s.sessionsDir())
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return pendingSession{}, ErrSessionNotFound
		}
		return pendingSession{}, ErrStorageUnavailable
	}
	sawInvalid := false
	sessionFiles := 0
	for _, file := range files {
		if file.IsDir() {
			continue
		}
		sessionFiles++
		if sessionFiles > maxPendingSessionFiles {
			return pendingSession{}, ErrStorageUnavailable
		}
		b, err := os.ReadFile(filepath.Join(s.sessionsDir(), file.Name()))
		if err != nil {
			sawInvalid = true
			continue
		}
		var sess pendingSession
		if err := json.Unmarshal(b, &sess); err != nil {
			sawInvalid = true
			continue
		}
		if sess.State == state {
			return sess, nil
		}
	}
	if sawInvalid {
		return pendingSession{}, ErrInvalidProviderResponse
	}
	return pendingSession{}, ErrSessionNotFound
}

func (s *store) consumeSessionByState(state string, now time.Time) (pendingSession, error) {
	state = strings.TrimSpace(state)
	if state == "" {
		return pendingSession{}, errors.New("state is required")
	}
	if !s.isStrict() {
		sess, err := s.findSessionByState(state)
		if err != nil {
			return pendingSession{}, err
		}
		if sess.Consumed {
			return pendingSession{}, ErrSessionConsumed
		}
		if now.After(sess.ExpiresAt) {
			return pendingSession{}, ErrSessionExpired
		}
		sess.Consumed = true
		if err := s.writeSession(sess); err != nil {
			return pendingSession{}, err
		}
		return sess, nil
	}

	var claimed pendingSession
	err := s.mutateProtectedSessions(func(sessions []pendingSession) ([]pendingSession, error) {
		for i := range sessions {
			if sessions[i].State != state {
				continue
			}
			if sessions[i].Consumed {
				return nil, ErrSessionConsumed
			}
			if now.After(sessions[i].ExpiresAt) {
				return nil, ErrSessionExpired
			}
			claimed = sessions[i]
			sessions[i].Consumed = true
			return sessions, nil
		}
		return nil, ErrSessionNotFound
	})
	if err != nil {
		return pendingSession{}, err
	}
	return claimed, nil
}

func (s *store) clearSessions() error {
	if s.isStrict() {
		return s.deleteProtected(s.sessionsKey)
	}
	if err := os.RemoveAll(s.sessionsDir()); err != nil && !errors.Is(err, os.ErrNotExist) {
		return ErrStorageUnavailable
	}
	return nil
}

func (s *store) readProtectedSessions() ([]pendingSession, error) {
	b, err := s.getProtected(s.sessionsKey)
	if err != nil {
		return nil, err
	}
	return decodeProtectedSessions(b)
}

func (s *store) mutateProtectedSessions(mutate func([]pendingSession) ([]pendingSession, error)) error {
	for attempt := 0; attempt < maxProtectedSessionCASAttempts; attempt++ {
		b, revision, err := s.versioned.GetWithRevision(context.Background(), s.sessionsKey)
		var sessions []pendingSession
		switch {
		case err == nil:
			sessions, err = decodeProtectedSessions(b)
			if err != nil {
				return err
			}
		case errors.Is(err, secretstore.ErrNotFound):
			sessions = nil
		default:
			return ErrStorageUnavailable
		}

		updated, err := mutate(append([]pendingSession(nil), sessions...))
		if err != nil {
			return err
		}
		record, err := encodeProtectedSessions(updated)
		if err != nil {
			return err
		}
		if _, err := s.versioned.CompareAndSwap(context.Background(), s.sessionsKey, revision, record); err == nil {
			return nil
		} else if !errors.Is(err, secretstore.ErrConflict) {
			return ErrStorageUnavailable
		}
	}
	return ErrStorageUnavailable
}

func decodeProtectedSessions(b []byte) ([]pendingSession, error) {
	var record protectedPendingSessions
	if err := json.Unmarshal(b, &record); err != nil || record.Version != protectedSessionsVersion {
		return nil, ErrProtectedStorageCorrupt
	}
	if len(record.Sessions) == 0 || len(record.Sessions) > maxPendingSessionFiles {
		return nil, ErrProtectedStorageCorrupt
	}
	seenIDs := make(map[string]bool, len(record.Sessions))
	seenStates := make(map[string]bool, len(record.Sessions))
	for _, sess := range record.Sessions {
		if err := validatePendingSession(sess); err != nil || seenIDs[sess.SessionID] || seenStates[sess.State] {
			return nil, ErrProtectedStorageCorrupt
		}
		seenIDs[sess.SessionID] = true
		seenStates[sess.State] = true
	}
	return append([]pendingSession(nil), record.Sessions...), nil
}

func encodeProtectedSessions(sessions []pendingSession) ([]byte, error) {
	record := protectedPendingSessions{Version: protectedSessionsVersion, Sessions: append([]pendingSession(nil), sessions...)}
	b, err := json.Marshal(record)
	if err != nil {
		return nil, ErrStorageUnavailable
	}
	if _, err := decodeProtectedSessions(b); err != nil {
		return nil, ErrStorageUnavailable
	}
	return b, nil
}

func validatePendingSession(sess pendingSession) error {
	redirect, err := url.Parse(sess.RedirectURI)
	switch {
	case !validSessionID(sess.SessionID):
		return errors.New("invalid session id")
	case strings.TrimSpace(sess.State) == "":
		return errors.New("missing state")
	case strings.TrimSpace(sess.Verifier) == "":
		return errors.New("missing verifier")
	case err != nil || redirect.Scheme != "http" || redirect.Host == "" || !isLoopbackHost(redirect.Hostname()):
		return errors.New("invalid redirect uri")
	case sess.CreatedAt.IsZero() || sess.ExpiresAt.IsZero() || !sess.ExpiresAt.After(sess.CreatedAt):
		return errors.New("invalid session lifetime")
	default:
		return nil
	}
}

func validSessionID(sessionID string) bool {
	sessionID = strings.TrimSpace(sessionID)
	if sessionID == "" || len(sessionID) > 128 {
		return false
	}
	for i := 0; i < len(sessionID); i++ {
		c := sessionID[i]
		if (c < 'a' || c > 'z') && (c < 'A' || c > 'Z') && (c < '0' || c > '9') && c != '-' && c != '_' {
			return false
		}
	}
	return true
}

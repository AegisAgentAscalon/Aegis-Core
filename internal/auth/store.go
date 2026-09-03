package auth

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
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

type store struct {
	dir         string
	protected   secretstore.Store
	versioned   secretstore.VersionedStore
	tokenKey    secretstore.Key
	sessionsKey secretstore.Key
}

type protectedPendingSessions struct {
	Version  int              `json:"version"`
	Sessions []pendingSession `json:"sessions"`
}

func newStore(cfg AppConfig, protected secretstore.Store) (*store, error) {
	var versioned secretstore.VersionedStore
	if protected != nil {
		var ok bool
		versioned, ok = protected.(secretstore.VersionedStore)
		if !ok || isNilSecretStore(versioned) {
			return nil, ErrStorageUnavailable
		}
	}
	base := strings.TrimSpace(cfg.TokenStore.BaseDir)
	if base == "" {
		userCfg, err := os.UserConfigDir()
		if err != nil {
			return nil, ErrStorageUnavailable
		}
		base = filepath.Join(userCfg, "aegis-core", "auth")
	}
	dir := namespacedStoreDir(base, cfg.AppID, cfg.TokenStore.Namespace)
	if err := ensurePrivateDir(dir); err != nil {
		return nil, ErrStorageUnavailable
	}
	st := &store{
		dir:         dir,
		protected:   protected,
		versioned:   versioned,
		tokenKey:    protectedKey(cfg, "oauth-token"),
		sessionsKey: protectedKey(cfg, "pending-sessions"),
	}
	if st.isStrict() {
		if err := st.migrateLegacySecrets(context.Background()); err != nil {
			return nil, err
		}
	}
	return st, nil
}

func protectedKey(cfg AppConfig, record string) secretstore.Key {
	return secretstore.Key("auth/v1/" + cfg.AppID + "/" + cfg.TokenStore.Namespace + "/" + record)
}

func (s *store) isStrict() bool { return s.protected != nil }

func (s *store) tokenPath() string   { return filepath.Join(s.dir, "google_token.json") }
func (s *store) profilePath() string { return filepath.Join(s.dir, "google_profile.json") }
func (s *store) errorPath() string   { return filepath.Join(s.dir, "last_error.txt") }
func (s *store) sessionsDir() string { return filepath.Join(s.dir, "pending_sessions") }
func (s *store) sessionPath(sessionID string) string {
	return filepath.Join(s.sessionsDir(), safePathPart(sessionID)+".json")
}

func (s *store) readToken() (token, error) {
	if s.isStrict() {
		b, err := s.getProtected(s.tokenKey)
		if err != nil {
			return token{}, err
		}
		return decodeProtectedToken(b)
	}
	b, err := os.ReadFile(s.tokenPath())
	if err != nil {
		return token{}, err
	}
	var t token
	if err := json.Unmarshal(b, &t); err != nil {
		return token{}, ErrInvalidProviderResponse
	}
	if strings.TrimSpace(t.AccessToken) == "" {
		return token{}, ErrNotSignedIn
	}
	return t, nil
}

func (s *store) writeToken(t token) error {
	b, err := json.MarshalIndent(t, "", "  ")
	if err != nil {
		return ErrStorageUnavailable
	}
	if s.isStrict() {
		if _, err := decodeProtectedToken(b); err != nil {
			return ErrStorageUnavailable
		}
		return s.putProtected(s.tokenKey, b)
	}
	return writeFileAtomic(s.tokenPath(), b, 0o600)
}

func (s *store) deleteToken() error {
	if s.isStrict() {
		return s.deleteProtected(s.tokenKey)
	}
	if err := os.Remove(s.tokenPath()); err != nil && !errors.Is(err, os.ErrNotExist) {
		return ErrStorageUnavailable
	}
	return nil
}

func (s *store) readProfile() (profileFile, error) {
	b, err := os.ReadFile(s.profilePath())
	if err != nil {
		return profileFile{}, err
	}
	var p profileFile
	if err := json.Unmarshal(b, &p); err != nil {
		return profileFile{}, ErrInvalidProviderResponse
	}
	return p, nil
}

func (s *store) writeProfile(p profileFile) error {
	b, err := json.MarshalIndent(p, "", "  ")
	if err != nil {
		return ErrStorageUnavailable
	}
	return writeFileAtomic(s.profilePath(), b, 0o600)
}

func (s *store) clear() error {
	var errs []string
	if err := s.deleteToken(); err != nil {
		errs = append(errs, "token cleanup failed")
	}
	for _, path := range []string{s.profilePath(), s.errorPath()} {
		if err := os.Remove(path); err != nil && !errors.Is(err, os.ErrNotExist) {
			errs = append(errs, "file cleanup failed")
		}
	}
	if err := s.clearSessions(); err != nil {
		errs = append(errs, "session cleanup failed")
	}
	if len(errs) > 0 {
		return fmt.Errorf("%w: %s", ErrSignOutIncomplete, strings.Join(errs, "; "))
	}
	return nil
}

func (s *store) writeLastError(err error) {
	if err == nil {
		_ = os.Remove(s.errorPath())
		return
	}
	_ = writeFileAtomic(s.errorPath(), []byte(safeAuthError(err)), 0o600)
}

func (s *store) readLastError() string {
	b, err := os.ReadFile(s.errorPath())
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(b))
}

func (s *store) status(cfg AppConfig) (AuthStatus, error) {
	st := AuthStatus{
		AppID:               cfg.AppID,
		DisplayName:         cfg.DisplayName,
		ClientIDPresent:     cfg.OAuth.ClientID != "",
		ClientIDShapeValid:  cfg.OAuth.ClientID != "" && strings.HasSuffix(cfg.OAuth.ClientID, ".apps.googleusercontent.com"),
		ClientIDFingerprint: Fingerprint(cfg.OAuth.ClientID),
		UseClientSecret:     cfg.OAuth.UseClientSecret,
		Scopes:              append([]string{}, cfg.OAuth.Scopes...),
		TokenNamespace:      cfg.TokenStore.Namespace,
		LastError:           s.readLastError(),
	}
	if _, err := os.Stat(s.profilePath()); err == nil {
		st.ProfilePresent = true
	}
	if p, err := s.readProfile(); err == nil {
		st.Profile = ProfileSummary{Email: p.Email, DisplayName: p.DisplayName, Subject: p.Subject, PictureURL: p.PictureURL}
	} else if st.ProfilePresent {
		st.NeedsReconnect = true
		if st.LastError == "" {
			st.LastError = "stored auth data is invalid; sign in again"
		}
	}
	if s.isStrict() {
		t, err := s.readToken()
		switch {
		case err == nil:
			st.TokenPresent = true
			st.SignedIn = true
			st.AccessTokenExpired = time.Until(t.Expiry) <= 90*time.Second
			st.NeedsReconnect = st.AccessTokenExpired
		case errors.Is(err, secretstore.ErrNotFound):
		default:
			return AuthStatus{}, err
		}
	} else {
		if _, err := os.Stat(s.tokenPath()); err == nil {
			st.TokenPresent = true
		}
		if t, err := s.readToken(); err == nil {
			st.SignedIn = true
			st.AccessTokenExpired = time.Until(t.Expiry) <= 90*time.Second
			st.NeedsReconnect = st.AccessTokenExpired
		} else if st.TokenPresent {
			st.NeedsReconnect = true
			if st.LastError == "" {
				st.LastError = "stored auth data is invalid; sign in again"
			}
		}
	}
	st.Configured = st.ClientIDPresent && st.ClientIDShapeValid && len(st.Scopes) > 0
	if st.SignedIn && !st.ProfilePresent {
		st.NeedsReconnect = true
	}
	return st, nil
}

func (s *store) writeSession(sess pendingSession) error {
	if s.isStrict() {
		if err := validatePendingSession(sess); err != nil {
			return ErrStorageUnavailable
		}
		return s.mutateProtectedSessions(func(sessions []pendingSession) ([]pendingSession, error) {
			for i := range sessions {
				if sessions[i].SessionID == sess.SessionID {
					sessions[i] = sess
					return sessions, nil
				}
			}
			if len(sessions) >= maxPendingSessionFiles {
				return nil, ErrStorageUnavailable
			}
			return append(sessions, sess), nil
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

func safeAuthError(err error) string {
	if err == nil {
		return ""
	}
	var pathErr *os.PathError
	switch {
	case errors.As(err, &pathErr):
		return "auth storage operation failed"
	case errors.Is(err, ErrNotConfigured),
		errors.Is(err, ErrNotSignedIn),
		errors.Is(err, ErrProfileNotFound),
		errors.Is(err, ErrSessionNotFound),
		errors.Is(err, ErrSessionExpired),
		errors.Is(err, ErrSessionConsumed),
		errors.Is(err, ErrStateMismatch),
		errors.Is(err, ErrTokenExchangeFailed),
		errors.Is(err, ErrProviderUnavailable),
		errors.Is(err, ErrInvalidProviderResponse),
		errors.Is(err, ErrStorageUnavailable),
		errors.Is(err, ErrProtectedStorageCorrupt),
		errors.Is(err, ErrAuthCanceled),
		errors.Is(err, ErrSignOutIncomplete),
		errors.Is(err, errProfileFetchFailed):
		return unwrapAuthSentinel(err).Error()
	}
	lower := strings.ToLower(err.Error())
	switch {
	case strings.Contains(lower, "token exchange timed out"):
		return "token exchange timed out"
	case strings.Contains(lower, "profile fetch timed out"):
		return "profile fetch timed out"
	case strings.Contains(lower, "state is required"):
		return "state is required"
	case strings.Contains(lower, "authorization code is required"):
		return "authorization code is required"
	default:
		return "auth operation failed"
	}
}

func unwrapAuthSentinel(err error) error {
	for _, sentinel := range []error{
		ErrNotConfigured,
		ErrNotSignedIn,
		ErrProfileNotFound,
		ErrSessionNotFound,
		ErrSessionExpired,
		ErrSessionConsumed,
		ErrStateMismatch,
		ErrTokenExchangeFailed,
		ErrProviderUnavailable,
		ErrInvalidProviderResponse,
		ErrStorageUnavailable,
		ErrProtectedStorageCorrupt,
		ErrAuthCanceled,
		ErrSignOutIncomplete,
		errProfileFetchFailed,
	} {
		if errors.Is(err, sentinel) {
			return sentinel
		}
	}
	return errors.New("auth operation failed")
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

func (s *store) getProtected(key secretstore.Key) ([]byte, error) {
	b, err := s.protected.Get(context.Background(), key)
	if err == nil {
		return b, nil
	}
	if errors.Is(err, secretstore.ErrNotFound) {
		return nil, secretstore.ErrNotFound
	}
	return nil, ErrStorageUnavailable
}

func (s *store) putProtected(key secretstore.Key, value []byte) error {
	if err := s.protected.Put(context.Background(), key, value); err != nil {
		return ErrStorageUnavailable
	}
	return nil
}

func (s *store) deleteProtected(key secretstore.Key) error {
	err := s.protected.Delete(context.Background(), key)
	if err == nil || errors.Is(err, secretstore.ErrNotFound) {
		return nil
	}
	return ErrStorageUnavailable
}

func decodeProtectedToken(b []byte) (token, error) {
	var t token
	if err := json.Unmarshal(b, &t); err != nil || strings.TrimSpace(t.AccessToken) == "" || t.Expiry.IsZero() {
		return token{}, ErrProtectedStorageCorrupt
	}
	return t, nil
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

func writeFileAtomic(path string, data []byte, perm os.FileMode) error {
	dir := filepath.Dir(path)
	if err := ensurePrivateDir(dir); err != nil {
		return ErrStorageUnavailable
	}
	tmp, err := os.CreateTemp(dir, ".tmp-*")
	if err != nil {
		return ErrStorageUnavailable
	}
	tmpName := tmp.Name()
	cleanup := true
	defer func() {
		if cleanup {
			_ = os.Remove(tmpName)
		}
	}()
	if _, err := tmp.Write(data); err != nil {
		_ = tmp.Close()
		return ErrStorageUnavailable
	}
	if err := tmp.Close(); err != nil {
		return ErrStorageUnavailable
	}
	if err := os.Chmod(tmpName, perm); err != nil {
		return ErrStorageUnavailable
	}
	if err := os.Rename(tmpName, path); err != nil {
		return ErrStorageUnavailable
	}
	cleanup = false
	return nil
}

func ensurePrivateDir(dir string) error {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	info, err := os.Lstat(dir)
	if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return ErrStorageUnavailable
	}
	return os.Chmod(dir, 0o700)
}

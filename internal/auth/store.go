package auth

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"
)

const maxPendingSessionFiles = 5

type store struct {
	dir string
}

func newStore(cfg AppConfig) (*store, error) {
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
	return &store{dir: dir}, nil
}

func (s *store) tokenPath() string   { return filepath.Join(s.dir, "google_token.json") }
func (s *store) profilePath() string { return filepath.Join(s.dir, "google_profile.json") }
func (s *store) errorPath() string   { return filepath.Join(s.dir, "last_error.txt") }
func (s *store) sessionsDir() string { return filepath.Join(s.dir, "pending_sessions") }
func (s *store) sessionPath(sessionID string) string {
	return filepath.Join(s.sessionsDir(), safePathPart(sessionID)+".json")
}

func (s *store) readToken() (token, error) {
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
	return writeFileAtomic(s.tokenPath(), b, 0o600)
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
	for _, path := range []string{s.tokenPath(), s.profilePath(), s.errorPath()} {
		if err := os.Remove(path); err != nil && !errors.Is(err, os.ErrNotExist) {
			errs = append(errs, "file cleanup failed")
		}
	}
	if err := os.RemoveAll(s.sessionsDir()); err != nil && !errors.Is(err, os.ErrNotExist) {
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

func (s *store) status(cfg AppConfig) AuthStatus {
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
	if _, err := os.Stat(s.tokenPath()); err == nil {
		st.TokenPresent = true
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
	st.Configured = st.ClientIDPresent && st.ClientIDShapeValid && len(st.Scopes) > 0
	if st.SignedIn && !st.ProfilePresent {
		st.NeedsReconnect = true
	}
	return st
}

func (s *store) writeSession(sess pendingSession) error {
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

func (s *store) consumeSession(sess pendingSession) error {
	sess.Consumed = true
	return s.writeSession(sess)
}

func (s *store) clearSessions() error {
	if err := os.RemoveAll(s.sessionsDir()); err != nil && !errors.Is(err, os.ErrNotExist) {
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

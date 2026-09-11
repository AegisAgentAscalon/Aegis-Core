package auth

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/AegisAgentAscalon/aegis-core/pkg/secretstore"
)

type store struct {
	dir         string
	protected   secretstore.Store
	versioned   secretstore.VersionedStore
	tokenKey    secretstore.Key
	sessionsKey secretstore.Key
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

func (s *store) tokenPath() string { return filepath.Join(s.dir, "google_token.json") }

func (s *store) profilePath() string { return filepath.Join(s.dir, "google_profile.json") }

func (s *store) errorPath() string { return filepath.Join(s.dir, "last_error.txt") }

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

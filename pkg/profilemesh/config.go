package profilemesh

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"regexp"
	"strings"
	"time"
)

var (
	safeNamePattern    = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9._-]{0,127}$`)
	safeIDPattern      = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9._:-]{0,127}$`)
	fingerprintPattern = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9:_-]{3,127}$`)
)

func (realClock) Now() time.Time { return time.Now().UTC() }

func normalizeConfig(cfg AppConfig) AppConfig {
	cfg.AppID = strings.TrimSpace(cfg.AppID)
	cfg.DisplayName = strings.TrimSpace(cfg.DisplayName)
	cfg.DataDir = strings.TrimSpace(cfg.DataDir)
	cfg.Namespace = strings.TrimSpace(cfg.Namespace)
	return cfg
}

func validateConfig(cfg AppConfig) error {
	cfg = normalizeConfig(cfg)
	switch {
	case cfg.AppID == "":
		return errors.New("app id is required")
	case !validSafeName(cfg.AppID):
		return ErrInvalidNamespace
	case cfg.DisplayName == "":
		return errors.New("display name is required")
	case cfg.DataDir == "":
		return errors.New("data dir is required")
	case cfg.Namespace == "":
		return errors.New("namespace is required")
	case !validSafeName(cfg.Namespace):
		return ErrInvalidNamespace
	}
	return nil
}

func defaultHostingConfig(now time.Time) ProfileHostingConfig {
	return ProfileHostingConfig{HostingMode: HostingSingleProfileDevice, LocalCacheEnabled: true, OfflineBranchModePlanned: true, UpdatedAt: now.UTC()}
}

func validSafeName(s string) bool {
	s = strings.TrimSpace(s)
	if !safeNamePattern.MatchString(s) {
		return false
	}
	if strings.Contains(s, "..") || strings.ContainsAny(s, `/\`) {
		return false
	}
	upper := strings.ToUpper(s)
	if i := strings.IndexByte(upper, '.'); i >= 0 {
		upper = upper[:i]
	}
	return !reservedDeviceName(upper)
}

func validID(s string) bool {
	s = strings.TrimSpace(s)
	return safeIDPattern.MatchString(s) && !strings.Contains(s, "..") && !strings.ContainsAny(s, `/\`)
}

func validFingerprint(s string) bool {
	return fingerprintPattern.MatchString(strings.TrimSpace(s)) && !strings.Contains(strings.ToLower(s), "secret")
}

func randomID(prefix string, n int) (string, error) {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return prefix + base64.RawURLEncoding.EncodeToString(b), nil
}

func contextError(ctx context.Context) error {
	if ctx != nil && ctx.Err() != nil {
		return ErrContextCanceled
	}
	return nil
}

func reservedDeviceName(s string) bool {
	switch strings.ToUpper(strings.TrimSpace(s)) {
	case "CON", "PRN", "AUX", "NUL", "COM1", "COM2", "COM3", "COM4", "COM5", "COM6", "COM7", "COM8", "COM9", "LPT1", "LPT2", "LPT3", "LPT4", "LPT5", "LPT6", "LPT7", "LPT8", "LPT9":
		return true
	default:
		return false
	}
}

package devicelink

import (
	"context"
	"errors"
	"regexp"
	"strings"
	"time"
)

type AppConfig struct {
	AppID       string
	DisplayName string
	DataDir     string
	Namespace   string
}

type Option func(*options)

type options struct {
	discovery DiscoveryProvider
	transport Transport
	clock     Clock
}

type Clock interface {
	Now() time.Time
}

type realClock struct{}

func (realClock) Now() time.Time { return time.Now().UTC() }

var safeNamePattern = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9._-]{0,127}$`)

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
	reserved := map[string]bool{
		"CON": true, "PRN": true, "AUX": true, "NUL": true,
		"COM1": true, "COM2": true, "COM3": true, "COM4": true, "COM5": true, "COM6": true, "COM7": true, "COM8": true, "COM9": true,
		"LPT1": true, "LPT2": true, "LPT3": true, "LPT4": true, "LPT5": true, "LPT6": true, "LPT7": true, "LPT8": true, "LPT9": true,
	}
	return !reserved[upper]
}

func validSessionID(id string) bool {
	id = strings.TrimSpace(id)
	if id == "" || strings.ContainsAny(id, `/\.`) {
		return false
	}
	if !strings.HasPrefix(id, "hs_") {
		return false
	}
	return safeNamePattern.MatchString(id)
}

func normalizeContext(ctx context.Context) context.Context {
	if ctx == nil {
		return context.Background()
	}
	return ctx
}

func contextError(ctx context.Context) error {
	if ctx != nil && ctx.Err() != nil {
		return ErrContextCanceled
	}
	return nil
}

func isStale(now, lastSeen time.Time) bool {
	return !lastSeen.IsZero() && (lastSeen.After(now.Add(defaultFutureSkew)) || now.Sub(lastSeen) > defaultStaleAfter)
}

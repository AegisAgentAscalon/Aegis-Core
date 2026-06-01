// Package setupstate contains private setup overview aggregation helpers.
package setupstate

import (
	"context"
	"errors"
	"strings"
)

var (
	ErrInvalidConfig = errors.New("invalid setup overview configuration")
)

type Capability string

const (
	CapabilityAuth            Capability = "auth"
	CapabilityUpdates         Capability = "updates"
	CapabilityDeviceLink      Capability = "device_link"
	CapabilityProfileMesh     Capability = "profile_mesh"
	CapabilityProfileSync     Capability = "profile_sync"
	CapabilityRelay           Capability = "relay"
	CapabilitySecurityPosture Capability = "security_posture"
)

type CapabilityState string

const (
	StateDisabled CapabilityState = "disabled"
	StateReady    CapabilityState = "ready"
	StateWarning  CapabilityState = "warning"
	StateBlocked  CapabilityState = "blocked"
	StateUnknown  CapabilityState = "unknown"
)

type AppSetupConfig struct {
	AppID               string
	DisplayName         string
	EnabledCapabilities []Capability
}

type CapabilityStatus struct {
	Capability Capability      `json:"capability"`
	Enabled    bool            `json:"enabled"`
	Ready      bool            `json:"ready"`
	State      CapabilityState `json:"state"`
	Summary    string          `json:"summary,omitempty"`
}

type SetupIssue struct {
	Capability Capability `json:"capability,omitempty"`
	Code       string     `json:"code"`
	Message    string     `json:"message"`
	Blocking   bool       `json:"blocking"`
}

type SetupOverview struct {
	AppID          string             `json:"app_id"`
	DisplayName    string             `json:"display_name"`
	Capabilities   []CapabilityStatus `json:"capabilities"`
	BlockingIssues []SetupIssue       `json:"blocking_issues"`
	Warnings       []SetupIssue       `json:"warnings"`
	Ready          bool               `json:"ready"`
}

type StatusProvider interface {
	SetupStatus(ctx context.Context) (CapabilityStatus, error)
}

type StatusProviderFunc func(ctx context.Context) (CapabilityStatus, error)

func (f StatusProviderFunc) SetupStatus(ctx context.Context) (CapabilityStatus, error) {
	return f(ctx)
}

func BuildOverview(ctx context.Context, cfg AppSetupConfig, providers map[Capability]StatusProvider) (SetupOverview, error) {
	cfg.AppID = strings.TrimSpace(cfg.AppID)
	cfg.DisplayName = strings.TrimSpace(cfg.DisplayName)
	if cfg.AppID == "" || cfg.DisplayName == "" {
		return SetupOverview{}, ErrInvalidConfig
	}
	overview := SetupOverview{AppID: cfg.AppID, DisplayName: cfg.DisplayName, Ready: true}
	enabled := normalizeCapabilities(cfg.EnabledCapabilities)
	for _, capability := range enabled {
		provider := providers[capability]
		if provider == nil {
			status := CapabilityStatus{Capability: capability, Enabled: true, Ready: false, State: StateBlocked, Summary: "setup status provider is not configured"}
			overview.Capabilities = append(overview.Capabilities, status)
			overview.BlockingIssues = append(overview.BlockingIssues, SetupIssue{Capability: capability, Code: "provider_missing", Message: "setup status provider is not configured", Blocking: true})
			overview.Ready = false
			continue
		}
		status, err := provider.SetupStatus(ctx)
		if err != nil {
			status = CapabilityStatus{Capability: capability, Enabled: true, Ready: false, State: StateBlocked, Summary: "setup status is unavailable"}
			overview.BlockingIssues = append(overview.BlockingIssues, SetupIssue{Capability: capability, Code: "provider_error", Message: "setup status is unavailable", Blocking: true})
			overview.Ready = false
		} else {
			status.Capability = capability
			status.Enabled = true
			if status.State == "" {
				if status.Ready {
					status.State = StateReady
				} else {
					status.State = StateBlocked
				}
			}
			if status.State == StateWarning {
				overview.Warnings = append(overview.Warnings, SetupIssue{Capability: capability, Code: "capability_warning", Message: safeSummary(status.Summary, "capability has a warning"), Blocking: false})
			} else if status.State == StateBlocked || !status.Ready {
				overview.BlockingIssues = append(overview.BlockingIssues, SetupIssue{Capability: capability, Code: "capability_not_ready", Message: safeSummary(status.Summary, "capability is not ready"), Blocking: true})
				overview.Ready = false
			}
		}
		overview.Capabilities = append(overview.Capabilities, status)
	}
	return overview, nil
}

func normalizeCapabilities(in []Capability) []Capability {
	seen := map[Capability]bool{}
	var out []Capability
	for _, cap := range in {
		switch cap {
		case CapabilityAuth, CapabilityUpdates, CapabilityDeviceLink, CapabilityProfileMesh, CapabilityProfileSync, CapabilityRelay, CapabilitySecurityPosture:
			if !seen[cap] {
				out = append(out, cap)
				seen[cap] = true
			}
		}
	}
	return out
}

func safeSummary(value, fallback string) string {
	value = strings.TrimSpace(value)
	if value == "" {
		return fallback
	}
	if strings.Contains(value, `:\`) || strings.Contains(value, "/") || strings.Contains(strings.ToLower(value), "secret") || strings.Contains(strings.ToLower(value), "token") {
		return fallback
	}
	return value
}

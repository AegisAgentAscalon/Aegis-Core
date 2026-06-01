// Package setupstate exposes safe setup overview aggregation contracts.
package setupstate

import (
	"context"

	internal "github.com/AegisAgentAscalon/aegis-core/internal/setupstate"
)

var ErrInvalidConfig = internal.ErrInvalidConfig

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
	internalProviders := map[internal.Capability]internal.StatusProvider{}
	for capability, provider := range providers {
		if provider == nil {
			continue
		}
		capCopy := toInternalCapability(capability)
		providerCopy := provider
		internalProviders[capCopy] = internal.StatusProviderFunc(func(ctx context.Context) (internal.CapabilityStatus, error) {
			status, err := providerCopy.SetupStatus(ctx)
			if err != nil {
				return internal.CapabilityStatus{}, err
			}
			return toInternalStatus(status), nil
		})
	}
	overview, err := internal.BuildOverview(ctx, internal.AppSetupConfig{
		AppID:               cfg.AppID,
		DisplayName:         cfg.DisplayName,
		EnabledCapabilities: toInternalCapabilities(cfg.EnabledCapabilities),
	}, internalProviders)
	if err != nil {
		return SetupOverview{}, err
	}
	return fromInternalOverview(overview), nil
}

func toInternalCapability(capability Capability) internal.Capability {
	return internal.Capability(capability)
}

func toInternalCapabilities(in []Capability) []internal.Capability {
	out := make([]internal.Capability, 0, len(in))
	for _, capability := range in {
		out = append(out, toInternalCapability(capability))
	}
	return out
}

func toInternalState(state CapabilityState) internal.CapabilityState {
	return internal.CapabilityState(state)
}

func fromInternalState(state internal.CapabilityState) CapabilityState {
	return CapabilityState(state)
}

func toInternalStatus(status CapabilityStatus) internal.CapabilityStatus {
	return internal.CapabilityStatus{
		Capability: toInternalCapability(status.Capability),
		Enabled:    status.Enabled,
		Ready:      status.Ready,
		State:      toInternalState(status.State),
		Summary:    status.Summary,
	}
}

func fromInternalStatus(status internal.CapabilityStatus) CapabilityStatus {
	return CapabilityStatus{
		Capability: Capability(status.Capability),
		Enabled:    status.Enabled,
		Ready:      status.Ready,
		State:      fromInternalState(status.State),
		Summary:    status.Summary,
	}
}

func fromInternalIssue(issue internal.SetupIssue) SetupIssue {
	return SetupIssue{Capability: Capability(issue.Capability), Code: issue.Code, Message: issue.Message, Blocking: issue.Blocking}
}

func fromInternalOverview(overview internal.SetupOverview) SetupOverview {
	out := SetupOverview{AppID: overview.AppID, DisplayName: overview.DisplayName, Ready: overview.Ready}
	for _, status := range overview.Capabilities {
		out.Capabilities = append(out.Capabilities, fromInternalStatus(status))
	}
	for _, issue := range overview.BlockingIssues {
		out.BlockingIssues = append(out.BlockingIssues, fromInternalIssue(issue))
	}
	for _, issue := range overview.Warnings {
		out.Warnings = append(out.Warnings, fromInternalIssue(issue))
	}
	return out
}

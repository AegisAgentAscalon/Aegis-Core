// Package setupstate exposes safe setup overview aggregation contracts.
package setupstate

import (
	"context"

	"errors"
)

var ErrInvalidConfig = errors.New("invalid setup overview configuration")

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

package devicelink

import (
	"context"
	"time"
)

type ResourceType string

const (
	ResourceService   ResourceType = "service"
	ResourceData      ResourceType = "kb"
	ResourceConnector ResourceType = "connector"
	ResourceRuntime   ResourceType = "runtime"
	ResourceTool      ResourceType = "tool"
	ResourceOther     ResourceType = "other"
)

type ResourceAvailability string

const (
	ResourceAvailable   ResourceAvailability = "available"
	ResourceUnavailable ResourceAvailability = "unavailable"
	ResourceUnknown     ResourceAvailability = "unknown"
)

type EndpointHint struct {
	Kind    string `json:"kind"`
	Address string `json:"address"`
}

type ResourceSummary struct {
	Type  ResourceType `json:"type"`
	Count int          `json:"count"`
}

type PresenceRecord struct {
	SchemaVersion        int               `json:"schema_version"`
	DeviceID             string            `json:"device_id"`
	DisplayName          string            `json:"display_name"`
	EndpointHints        []EndpointHint    `json:"endpoint_hints"`
	Capabilities         []string          `json:"capabilities"`
	ResourcesSummary     []ResourceSummary `json:"resources_summary"`
	LastSeen             time.Time         `json:"last_seen"`
	PublicKeyFingerprint string            `json:"public_key_fingerprint"`
}

type DiscoveredPeer struct {
	Presence    PresenceRecord `json:"presence"`
	TrustStatus TrustStatus    `json:"trust_status"`
	Stale       bool           `json:"stale"`
}

type ResourceDescriptor struct {
	ResourceID    string               `json:"resource_id"`
	Type          ResourceType         `json:"type"`
	DisplayName   string               `json:"display_name"`
	OwnerDeviceID string               `json:"owner_device_id"`
	Availability  ResourceAvailability `json:"availability"`
	Tags          []string             `json:"tags"`
	Metadata      map[string]string    `json:"metadata"`
	LastUpdated   time.Time            `json:"last_updated"`
}

type RemoteResourceDescriptor struct {
	ResourceDescriptor
	DeviceDisplayName    string      `json:"device_display_name,omitempty"`
	DeviceTrustStatus    TrustStatus `json:"device_trust_status"`
	PublicKeyFingerprint string      `json:"public_key_fingerprint"`
}

type ResourceAdvertisementRequest struct {
	Resources []ResourceDescriptor
}

type DiscoveryProvider interface {
	Publish(ctx context.Context, record PresenceRecord) error
	Discover(ctx context.Context) ([]PresenceRecord, error)
}

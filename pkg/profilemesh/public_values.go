package profilemesh

import (
	"maps"
	"sort"
	"strings"
)

// Public results retain the former facade's owned, non-nil slice values.
// Apply these copies after canonical fingerprinting, which has its own shape.
func cloneProfileDevice(device ProfileDeviceRecord) ProfileDeviceRecord {
	device.Capabilities = append([]string{}, device.Capabilities...)
	if device.RemovedAt != nil {
		removedAt := *device.RemovedAt
		device.RemovedAt = &removedAt
	}
	return device
}

func cloneProfileDevices(in []ProfileDeviceRecord) []ProfileDeviceRecord {
	out := make([]ProfileDeviceRecord, len(in))
	for i, device := range in {
		out[i] = cloneProfileDevice(device)
	}
	return out
}

func cloneProfileResource(resource ProfileResourceRecord) ProfileResourceRecord {
	resource.AllowedHostDeviceIDs = append([]string{}, resource.AllowedHostDeviceIDs...)
	resource.Tags = append([]string{}, resource.Tags...)
	resource.Metadata = maps.Clone(resource.Metadata)
	return resource
}

func cloneProfileResources(in []ProfileResourceRecord) []ProfileResourceRecord {
	out := make([]ProfileResourceRecord, len(in))
	for i, resource := range in {
		out[i] = cloneProfileResource(resource)
	}
	return out
}

func publicProfileMeshSnapshot(snapshot ProfileMeshSnapshot) ProfileMeshSnapshot {
	snapshot.Devices = cloneProfileDevices(snapshot.Devices)
	snapshot.Resources = cloneProfileResources(snapshot.Resources)
	snapshot.RelayHints = append([]ProfileRelayHint{}, snapshot.RelayHints...)
	for i := range snapshot.RelayHints {
		snapshot.RelayHints[i].Capabilities = append([]string{}, snapshot.RelayHints[i].Capabilities...)
		snapshot.RelayHints[i].Metadata = maps.Clone(snapshot.RelayHints[i].Metadata)
	}
	snapshot.EndpointHints = append([]ProfileEndpointHint{}, snapshot.EndpointHints...)
	for i := range snapshot.EndpointHints {
		snapshot.EndpointHints[i].Capabilities = append([]string{}, snapshot.EndpointHints[i].Capabilities...)
		snapshot.EndpointHints[i].Metadata = maps.Clone(snapshot.EndpointHints[i].Metadata)
	}
	return snapshot
}

func compactStrings(in []string) []string {
	seen := map[string]bool{}
	var out []string
	for _, item := range in {
		item = strings.TrimSpace(item)
		if item == "" || strings.Contains(strings.ToLower(item), "secret") || seen[item] {
			continue
		}
		seen[item] = true
		out = append(out, item)
	}
	sort.Strings(out)
	return out
}

// Host IDs are authorization data: sorting and deduplication must not redact,
// trim or drop entries. Validation rejects invalid references before storage.

func uniqueHostIDs(in []string) []string {
	seen := make(map[string]bool, len(in))
	var out []string
	for _, id := range in {
		if !seen[id] {
			seen[id] = true
			out = append(out, id)
		}
	}
	sort.Strings(out)
	return out
}

func cloneMetadata(in map[string]string) map[string]string {
	out := map[string]string{}
	for k, v := range in {
		k = strings.TrimSpace(k)
		v = strings.TrimSpace(v)
		lower := strings.ToLower(k + " " + v)
		if k == "" || strings.Contains(lower, "secret") || strings.Contains(lower, "token") || strings.Contains(lower, "private") {
			continue
		}
		out[k] = v
	}
	return out
}

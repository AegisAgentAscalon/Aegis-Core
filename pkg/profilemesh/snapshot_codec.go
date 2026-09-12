package profilemesh

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"sort"
	"strings"
)

// Schema 1 and schema 2 retain distinct canonical fingerprint encodings.
func snapshotFingerprint(snapshot ProfileMeshSnapshot) string {
	canonical := normalizeProfileMeshSnapshot(snapshot)
	canonical.SnapshotFingerprint = ""
	sort.Slice(canonical.Devices, func(i, j int) bool {
		return canonical.Devices[i].DeviceID < canonical.Devices[j].DeviceID
	})
	sort.Slice(canonical.Resources, func(i, j int) bool {
		return canonical.Resources[i].ResourceID < canonical.Resources[j].ResourceID
	})
	sort.Slice(canonical.RelayHints, func(i, j int) bool {
		return canonicalJSON(canonical.RelayHints[i]) < canonicalJSON(canonical.RelayHints[j])
	})
	sort.Slice(canonical.EndpointHints, func(i, j int) bool {
		return canonicalJSON(canonical.EndpointHints[i]) < canonicalJSON(canonical.EndpointHints[j])
	})
	raw, _ := json.Marshal(canonical)
	sum := sha256.Sum256(raw)
	return hex.EncodeToString(sum[:])[:16]
}

func legacyProfileMeshSnapshotFingerprint(snapshot ProfileMeshSnapshot) string {
	parts := []string{snapshot.AppID, snapshot.Namespace, snapshot.Profile.ProfileID}
	for _, dev := range snapshot.Devices {
		parts = append(parts, "d:"+dev.DeviceID+"="+dev.PublicKeyFingerprint+"="+string(dev.Status))
	}
	for _, resource := range snapshot.Resources {
		parts = append(parts, "r:"+resource.ResourceID+"="+resource.ProfileOwnerID+"="+resource.CurrentHostDeviceID)
	}
	sort.Strings(parts)
	sum := sha256.Sum256([]byte(strings.Join(parts, "|")))
	return hex.EncodeToString(sum[:])[:16]
}

func normalizeProfileMeshSnapshot(snapshot ProfileMeshSnapshot) ProfileMeshSnapshot {
	normalized := snapshot
	normalized.Profile.ProfilePublicFingerprint = normalizeFingerprint(normalized.Profile.ProfilePublicFingerprint)
	normalized.Devices = append([]ProfileDeviceRecord{}, snapshot.Devices...)
	for i := range normalized.Devices {
		normalized.Devices[i].PublicKeyFingerprint = normalizeFingerprint(normalized.Devices[i].PublicKeyFingerprint)
		normalized.Devices[i].Capabilities = compactStrings(normalized.Devices[i].Capabilities)
		normalized.Devices[i].MetadataSource = strings.TrimSpace(normalized.Devices[i].MetadataSource)
	}
	normalized.Resources = append([]ProfileResourceRecord{}, snapshot.Resources...)
	for i := range normalized.Resources {
		normalized.Resources[i].AllowedHostDeviceIDs = uniqueHostIDs(normalized.Resources[i].AllowedHostDeviceIDs)
		normalized.Resources[i].Tags = compactStrings(normalized.Resources[i].Tags)
		normalized.Resources[i].Metadata = cloneMetadata(normalized.Resources[i].Metadata)
	}
	normalized.RelayHints = append([]ProfileRelayHint{}, snapshot.RelayHints...)
	for i := range normalized.RelayHints {
		normalized.RelayHints[i].Capabilities = compactStrings(normalized.RelayHints[i].Capabilities)
		normalized.RelayHints[i].Metadata = cloneMetadata(normalized.RelayHints[i].Metadata)
	}
	normalized.EndpointHints = append([]ProfileEndpointHint{}, snapshot.EndpointHints...)
	for i := range normalized.EndpointHints {
		normalized.EndpointHints[i].Capabilities = compactStrings(normalized.EndpointHints[i].Capabilities)
		normalized.EndpointHints[i].Metadata = cloneMetadata(normalized.EndpointHints[i].Metadata)
	}
	return normalized
}

func normalizeFingerprint(value string) string {
	return strings.ToLower(strings.TrimSpace(value))
}

func canonicalJSON(value any) string {
	raw, _ := json.Marshal(value)
	return string(raw)
}

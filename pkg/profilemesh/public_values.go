package profilemesh

// Public results retain the former facade's owned, non-nil slice values.
// Apply these copies after canonical fingerprinting, which has its own shape.
func cloneProfileDevice(device ProfileDeviceRecord) ProfileDeviceRecord {
	device.Capabilities = append([]string{}, device.Capabilities...)
	return device
}

func cloneProfileDevices(in []ProfileDeviceRecord) []ProfileDeviceRecord {
	out := make([]ProfileDeviceRecord, len(in))
	for i, device := range in {
		out[i] = cloneProfileDevice(device)
	}
	return out
}

func cloneProfileMetadata(in map[string]string) map[string]string {
	if in == nil {
		return nil
	}
	out := make(map[string]string, len(in))
	for key, value := range in {
		out[key] = value
	}
	return out
}

func cloneProfileResource(resource ProfileResourceRecord) ProfileResourceRecord {
	resource.AllowedHostDeviceIDs = append([]string{}, resource.AllowedHostDeviceIDs...)
	resource.Tags = append([]string{}, resource.Tags...)
	resource.Metadata = cloneProfileMetadata(resource.Metadata)
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
		snapshot.RelayHints[i].Metadata = cloneProfileMetadata(snapshot.RelayHints[i].Metadata)
	}
	snapshot.EndpointHints = append([]ProfileEndpointHint{}, snapshot.EndpointHints...)
	for i := range snapshot.EndpointHints {
		snapshot.EndpointHints[i].Capabilities = append([]string{}, snapshot.EndpointHints[i].Capabilities...)
		snapshot.EndpointHints[i].Metadata = cloneProfileMetadata(snapshot.EndpointHints[i].Metadata)
	}
	return snapshot
}

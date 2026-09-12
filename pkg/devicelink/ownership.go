package devicelink

import "context"

// ownedDiscoveryProvider preserves the public facade's conversion boundary:
// providers never retain slices owned by a Service result, and Service never
// retains slices owned by a provider result.
type ownedDiscoveryProvider struct {
	provider DiscoveryProvider
}

func (p ownedDiscoveryProvider) Publish(ctx context.Context, record PresenceRecord) error {
	return p.provider.Publish(ctx, clonePresenceRecord(record))
}

func (p ownedDiscoveryProvider) Discover(ctx context.Context) ([]PresenceRecord, error) {
	records, err := p.provider.Discover(ctx)
	if err != nil {
		return nil, err
	}
	owned := make([]PresenceRecord, len(records))
	for i := range records {
		owned[i] = clonePresenceRecord(records[i])
	}
	return owned, nil
}

type ownedTransport struct {
	transport Transport
}

func (t ownedTransport) Open(ctx context.Context, peer DiscoveredPeer) (Connection, error) {
	conn, err := t.transport.Open(ctx, cloneDiscoveredPeer(peer))
	if err != nil {
		return nil, err
	}
	if conn == nil {
		return nil, ErrTransportUnavailable
	}
	return ownedConnection{connection: conn}, nil
}

type ownedConnection struct {
	connection Connection
}

func (c ownedConnection) Send(ctx context.Context, msg Message) error {
	return c.connection.Send(ctx, cloneMessage(msg))
}

func (c ownedConnection) Receive(ctx context.Context) (Message, error) {
	msg, err := c.connection.Receive(ctx)
	return cloneMessage(msg), err
}

func (c ownedConnection) Close() error {
	return c.connection.Close()
}

func cloneDiscoveredPeer(peer DiscoveredPeer) DiscoveredPeer {
	peer.Presence = clonePresenceRecord(peer.Presence)
	return peer
}

func cloneMessage(msg Message) Message {
	msg.Payload = cloneMap(msg.Payload)
	return msg
}

func cloneDeviceIdentity(identity DeviceIdentity) DeviceIdentity {
	identity.Capabilities = append([]string{}, identity.Capabilities...)
	return identity
}

func cloneTrustedDevice(device TrustedDevice) TrustedDevice {
	return cloneTrustedDevices([]TrustedDevice{device})[0]
}

func cloneMap(in map[string]string) map[string]string {
	if in == nil {
		return nil
	}
	out := map[string]string{}
	for key, value := range in {
		out[key] = value
	}
	return out
}

func cloneResourceDescriptors(in []ResourceDescriptor) []ResourceDescriptor {
	out := make([]ResourceDescriptor, len(in))
	for i, resource := range in {
		out[i] = resource
		out[i].Tags = append([]string{}, resource.Tags...)
		out[i].Metadata = cloneMap(resource.Metadata)
	}
	return out
}

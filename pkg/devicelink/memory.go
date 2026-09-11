package devicelink

import (
	"context"
	"sync"
)

type MessageHandler func(context.Context, Message) (Message, error)

type MemoryDiscoveryProvider struct {
	mu      sync.Mutex
	records map[string]PresenceRecord
	err     error
}

func NewMemoryDiscoveryProvider() *MemoryDiscoveryProvider {
	return &MemoryDiscoveryProvider{records: map[string]PresenceRecord{}}
}

func (p *MemoryDiscoveryProvider) SetError(err error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.err = err
}

func (p *MemoryDiscoveryProvider) Publish(ctx context.Context, record PresenceRecord) error {
	if err := contextError(ctx); err != nil {
		return err
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.err != nil {
		return ErrDiscoveryUnavailable
	}
	p.records[record.DeviceID] = record
	return nil
}

func (p *MemoryDiscoveryProvider) Discover(ctx context.Context) ([]PresenceRecord, error) {
	if err := contextError(ctx); err != nil {
		return nil, err
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.err != nil {
		return nil, ErrDiscoveryUnavailable
	}
	out := make([]PresenceRecord, 0, len(p.records))
	for _, rec := range p.records {
		out = append(out, rec)
	}
	return out, nil
}

type noopDiscoveryProvider struct{}

func (noopDiscoveryProvider) Publish(context.Context, PresenceRecord) error { return nil }
func (noopDiscoveryProvider) Discover(context.Context) ([]PresenceRecord, error) {
	return []PresenceRecord{}, nil
}

type MemoryTransport struct {
	mu       sync.Mutex
	handlers map[string]MessageHandler
	err      error
}

func NewMemoryTransport() *MemoryTransport {
	return &MemoryTransport{handlers: map[string]MessageHandler{}}
}

func (t *MemoryTransport) RegisterHandler(deviceID string, handler MessageHandler) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.handlers[deviceID] = handler
}

func (t *MemoryTransport) SetError(err error) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.err = err
}

func (t *MemoryTransport) Open(ctx context.Context, peer DiscoveredPeer) (Connection, error) {
	if err := contextError(ctx); err != nil {
		return nil, err
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.err != nil {
		return nil, ErrTransportUnavailable
	}
	handler := t.handlers[peer.Presence.DeviceID]
	if handler == nil {
		return nil, ErrTransportUnavailable
	}
	return &memoryConnection{handler: handler}, nil
}

type memoryConnection struct {
	handler MessageHandler
	last    Message
	closed  bool
}

func (c *memoryConnection) Send(ctx context.Context, msg Message) error {
	if c.closed {
		return ErrTransportUnavailable
	}
	if err := contextError(ctx); err != nil {
		return err
	}
	c.last = msg
	return nil
}

func (c *memoryConnection) Receive(ctx context.Context) (Message, error) {
	if c.closed {
		return Message{}, ErrTransportUnavailable
	}
	if err := contextError(ctx); err != nil {
		return Message{}, err
	}
	return c.handler(ctx, c.last)
}

func (c *memoryConnection) Close() error {
	c.closed = true
	return nil
}

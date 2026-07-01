package identitygate

import (
	"context"
	"sync"
)

type MemoryAuditSink struct {
	mu     sync.Mutex
	Events []AuditEvent
}

func (m *MemoryAuditSink) Record(ctx context.Context, event AuditEvent) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	m.Events = append(m.Events, event)
	return nil
}

func (m *MemoryAuditSink) Snapshot() []AuditEvent {
	m.mu.Lock()
	defer m.mu.Unlock()
	return append([]AuditEvent(nil), m.Events...)
}

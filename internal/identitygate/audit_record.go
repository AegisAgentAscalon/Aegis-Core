package identitygate

import "context"

type queuedAuditEvent struct {
	ctx   context.Context
	event AuditEvent
}

// record is for callers outside the state lock.
func (s *Service) record(ctx context.Context, kind, summary string) {
	s.mu.Lock()
	s.recordLocked(ctx, kind, summary)
	s.unlockAndDrainAudit()
}

// recordLocked enqueues in state-transition order, while mu is held.
func (s *Service) recordLocked(ctx context.Context, kind, summary string) {
	if s.audit != nil {
		s.auditQueue = append(s.auditQueue, queuedAuditEvent{ctx, NewAuditEvent(kind, summary, s.clock)})
	}
}

// One caller drains the FIFO outside mu. Concurrent and reentrant operations
// enqueue and return; their callbacks run after the active callback returns.
// Delivery remains best effort: sink errors are ignored, without retries.
func (s *Service) unlockAndDrainAudit() {
	if s.auditDraining || len(s.auditQueue) == 0 {
		s.mu.Unlock()
		return
	}
	s.auditDraining = true
	s.mu.Unlock()
	completed := false
	// A sink panic propagates, but must not permanently disable later delivery.
	defer func() {
		if completed {
			return
		}
		s.mu.Lock()
		s.auditDraining = false
		s.mu.Unlock()
	}()
	for {
		s.mu.Lock()
		if len(s.auditQueue) == 0 {
			// Clear ownership before unlocking so no concurrent event is stranded.
			s.auditDraining = false
			completed = true
			s.mu.Unlock()
			return
		}
		next := s.auditQueue[0]
		s.auditQueue[0] = queuedAuditEvent{}
		s.auditQueue = s.auditQueue[1:]
		s.mu.Unlock()
		_ = s.audit.Record(next.ctx, next.event)
	}
}

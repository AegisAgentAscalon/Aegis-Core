package updates

import (
	"context"
	"errors"

	"github.com/AegisAgentAscalon/aegis-core/internal/filelock"
	"github.com/AegisAgentAscalon/aegis-core/internal/generation"
)

func (s *Service) lockWorkflow(ctx context.Context) error {
	select {
	case s.workflowGate <- struct{}{}:
		if err := contextError(ctx); err != nil {
			s.unlockWorkflow()
			return err
		}
		return nil
	case <-ctx.Done():
		return ErrContextCanceled
	}
}

func (s *Service) unlockWorkflow() { <-s.workflowGate }

// When combined, locks are acquired workflow -> commit -> owner. Apply's
// execution gate is only tried, never waited on, under the commit lock.
type operationGuard struct {
	service  *Service
	guard    *generation.Guard
	gate     *filelock.Lock
	snapshot serviceSnapshot
}

func (o *operationGuard) close() {
	o.service.mu.Unlock()
	if o.gate != nil {
		_ = o.gate.Close()
	}
	_ = o.guard.Close()
}

func (s *Service) lockOperation(ctx context.Context, snapshot serviceSnapshot, blocksApply bool) (*operationGuard, error) {
	guard, err := snapshot.store.generations.Lock(ctx)
	if err != nil {
		return nil, persistenceError(err)
	}
	var gate *filelock.Lock
	if blocksApply {
		gate, err = snapshot.store.tryApply(ctx)
		if err != nil {
			_ = guard.Close()
			return nil, err
		}
	}
	s.mu.Lock()
	op := &operationGuard{service: s, guard: guard, gate: gate, snapshot: snapshot}
	if !s.currentLocked(snapshot) {
		op.close()
		return nil, ErrUpdateStateChanged
	}
	if blocksApply && s.applyInProgress {
		op.close()
		return nil, ErrApplyInProgress
	}
	if snapshot.view != nil {
		if err := snapshot.store.checkExpected(ctx, guard, snapshot.view); err != nil {
			op.close()
			return nil, err
		}
	}
	return op, nil
}

func (s *Service) beginLocked(ctx context.Context, blocksApply bool) (*operationGuard, error) {
	for {
		if err := contextError(ctx); err != nil {
			return nil, err
		}
		s.mu.Lock()
		snapshot := s.snapshotLocked()
		s.mu.Unlock()
		op, err := s.lockOperation(ctx, snapshot, blocksApply)
		if errors.Is(err, ErrUpdateStateChanged) {
			continue
		}
		if err != nil {
			return nil, err
		}
		view, err := snapshot.store.load(ctx, op.guard)
		if err == nil {
			err = contextError(ctx)
		}
		if err != nil {
			op.close()
			return nil, err
		}
		op.snapshot.view = view
		return op, nil
	}
}

func (s *Service) beginOperation(ctx context.Context, blocksApply bool) (serviceSnapshot, error) {
	op, err := s.beginLocked(ctx, blocksApply)
	if err != nil {
		return serviceSnapshot{}, err
	}
	defer op.close()
	return op.snapshot, nil
}

func (s *Service) publishOperation(ctx context.Context, snapshot serviceSnapshot) error {
	op, err := s.lockOperation(ctx, snapshot, true)
	if err != nil {
		return err
	}
	defer op.close()
	return snapshot.store.publish(ctx, op.guard, snapshot.cfg, snapshot.view, false)
}

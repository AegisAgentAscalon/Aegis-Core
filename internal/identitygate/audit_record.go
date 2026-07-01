package identitygate

import "context"

func (s *Service) record(ctx context.Context, kind string, summary string) {
	if s == nil || s.audit == nil {
		return
	}
	_ = s.audit.Record(ctx, NewAuditEvent(kind, summary, s.clock))
}

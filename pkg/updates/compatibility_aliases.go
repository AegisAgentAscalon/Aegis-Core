// Compatibility method aliases for the original Updates API.
package updates

import (
	"context"
)

func (s *Service) State(ctx context.Context) (CurrentState, error) { return s.GetStatus(ctx) }
func (s *Service) Check(ctx context.Context) (CheckResult, error)  { return s.CheckForUpdates(ctx) }
func (s *Service) Download(ctx context.Context, version string) (DownloadResult, error) {
	return s.DownloadUpdate(ctx, version)
}
func (s *Service) Verify(ctx context.Context, version string) (VerifyResult, error) {
	return s.VerifyUpdate(ctx, version)
}
func (s *Service) Stage(ctx context.Context, version string) (StageResult, error) {
	return s.StageUpdate(ctx, version)
}
func (s *Service) Describe(ctx context.Context) (StagedUpdateSummary, error) {
	return s.DescribeStagedUpdate(ctx)
}
func (s *Service) PlanApply(ctx context.Context) (ApplyPlan, error) { return s.BuildApplyPlan(ctx) }
func (s *Service) Apply(ctx context.Context, version string) (ApplyResult, error) {
	return s.applyExpectedVersion(ctx, version)
}

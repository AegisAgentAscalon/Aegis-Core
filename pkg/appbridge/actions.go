package appbridge

import (
	"context"

	"github.com/AegisAgentAscalon/aegis-core/pkg/auth"
	"github.com/AegisAgentAscalon/aegis-core/pkg/updates"
)

func (b *Bridge) StartSignIn(ctx context.Context) (auth.SignInStartResult, error) {
	if !b.cfg.Auth.Enabled {
		return auth.SignInStartResult{}, ErrDisabled
	}
	if b.cfg.Auth.Service == nil {
		return auth.SignInStartResult{}, ErrNotConfigured
	}
	return b.cfg.Auth.Service.StartSignIn(ctx)
}

func (b *Bridge) CompleteSignIn(ctx context.Context, req auth.CompleteSignInRequest) (auth.CompleteSignInResult, error) {
	if !b.cfg.Auth.Enabled {
		return auth.CompleteSignInResult{}, ErrDisabled
	}
	if b.cfg.Auth.Service == nil {
		return auth.CompleteSignInResult{}, ErrNotConfigured
	}
	return b.cfg.Auth.Service.CompleteSignIn(ctx, req)
}

func (b *Bridge) SignOut(ctx context.Context) error {
	if !b.cfg.Auth.Enabled {
		return ErrDisabled
	}
	if b.cfg.Auth.Service == nil {
		return ErrNotConfigured
	}
	return b.cfg.Auth.Service.SignOut(ctx)
}

func (b *Bridge) CheckForUpdates(ctx context.Context) (updates.CheckResult, error) {
	if !b.cfg.Updates.Enabled {
		return updates.CheckResult{}, ErrDisabled
	}
	if b.cfg.Updates.Service == nil {
		return updates.CheckResult{}, ErrNotConfigured
	}
	return b.cfg.Updates.Service.CheckForUpdates(ctx)
}

func (b *Bridge) DownloadUpdate(ctx context.Context, version string) (updates.DownloadResult, error) {
	if !b.cfg.Updates.Enabled {
		return updates.DownloadResult{}, ErrDisabled
	}
	if b.cfg.Updates.Service == nil {
		return updates.DownloadResult{}, ErrNotConfigured
	}
	return b.cfg.Updates.Service.DownloadUpdate(ctx, version)
}

func (b *Bridge) VerifyUpdate(ctx context.Context, version string) (updates.VerifyResult, error) {
	if !b.cfg.Updates.Enabled {
		return updates.VerifyResult{}, ErrDisabled
	}
	if b.cfg.Updates.Service == nil {
		return updates.VerifyResult{}, ErrNotConfigured
	}
	return b.cfg.Updates.Service.VerifyUpdate(ctx, version)
}

func (b *Bridge) StageUpdate(ctx context.Context, version string) (updates.StageResult, error) {
	if !b.cfg.Updates.Enabled {
		return updates.StageResult{}, ErrDisabled
	}
	if b.cfg.Updates.Service == nil {
		return updates.StageResult{}, ErrNotConfigured
	}
	return b.cfg.Updates.Service.StageUpdate(ctx, version)
}

func (b *Bridge) DescribeStagedUpdate(ctx context.Context) (updates.StagedUpdateSummary, error) {
	if !b.cfg.Updates.Enabled {
		return updates.StagedUpdateSummary{}, ErrDisabled
	}
	if b.cfg.Updates.Service == nil {
		return updates.StagedUpdateSummary{}, ErrNotConfigured
	}
	return b.cfg.Updates.Service.DescribeStagedUpdate(ctx)
}

func (b *Bridge) BuildUpdateApplyPlan(ctx context.Context) (updates.ApplyPlan, error) {
	if !b.cfg.Updates.Enabled {
		return updates.ApplyPlan{}, ErrDisabled
	}
	if b.cfg.Updates.Service == nil {
		return updates.ApplyPlan{}, ErrNotConfigured
	}
	return b.cfg.Updates.Service.BuildApplyPlan(ctx)
}

func (b *Bridge) ApplyUpdate(ctx context.Context) (updates.ApplyResult, error) {
	if !b.cfg.Updates.Enabled {
		return updates.ApplyResult{}, ErrDisabled
	}
	if b.cfg.Updates.Service == nil {
		return updates.ApplyResult{}, ErrNotConfigured
	}
	return b.cfg.Updates.Service.ApplyUpdate(ctx)
}

func (b *Bridge) ClearStagedUpdate(ctx context.Context) (updates.ClearResult, error) {
	if !b.cfg.Updates.Enabled {
		return updates.ClearResult{}, ErrDisabled
	}
	if b.cfg.Updates.Service == nil {
		return updates.ClearResult{}, ErrNotConfigured
	}
	return b.cfg.Updates.Service.ClearStagedUpdate(ctx)
}

// Compatibility constructors and app-owned apply callbacks retained for legacy callers.
package updates

import (
	"context"
	"errors"
	"os"
	"strings"
	"time"
)

type ApplyStrategy interface {
	Apply(ctx context.Context, staged StagedUpdate) (ApplyResult, error)
}

type ApplyAdapter interface {
	ApplyUpdate(ctx context.Context, stagedPath string, release Release) (ApplyResult, error)
}

type ManualApplyStrategy struct {
	Message string
}

func (m ManualApplyStrategy) Apply(ctx context.Context, staged StagedUpdate) (ApplyResult, error) {
	if err := contextError(ctx); err != nil {
		return ApplyResult{}, err
	}
	message := strings.TrimSpace(m.Message)
	if message == "" {
		message = "update is staged for app-owned manual apply"
	}
	return ApplyResult{Version: staged.Version, OK: true, Message: message}, nil
}

func NewService(cfg AppConfig, apply ApplyStrategy) (*Service, error) {
	return NewServiceWithOptions(cfg, apply, ServiceOptions{})
}

func NewServiceWithOptions(cfg AppConfig, apply ApplyStrategy, options ServiceOptions) (*Service, error) {
	return newServiceWithOptions(cfg, apply, options, true)
}

func NewServiceWithAdapter(cfg AppConfig, adapter ApplyAdapter) (*Service, error) {
	return NewServiceWithAdapterOptions(cfg, adapter, ServiceOptions{})
}

func NewServiceWithAdapterOptions(cfg AppConfig, adapter ApplyAdapter, options ServiceOptions) (*Service, error) {
	var strategy ApplyStrategy
	if adapter != nil {
		strategy = applyAdapterStrategy{adapter: adapter}
	}
	return NewServiceWithOptions(cfg, strategy, options)
}

type applyAdapterStrategy struct {
	adapter ApplyAdapter
}

func (s applyAdapterStrategy) Apply(ctx context.Context, staged StagedUpdate) (ApplyResult, error) {
	release := Release{
		Source:          staged.Source,
		AppID:           staged.AppID,
		Version:         staged.Version,
		Channel:         staged.Channel,
		Platform:        staged.Platform,
		Architecture:    staged.Architecture,
		RequiredRestart: staged.RequiredRestart,
		ApplyBehavior:   staged.ApplyBehavior,
		ArtifactName:    staged.ArtifactName,
		ArtifactSHA256:  staged.SHA256,
		ArtifactSize:    staged.Size,
	}
	return s.adapter.ApplyUpdate(ctx, staged.ArtifactPath, release)
}

func (s *Service) ApplyUpdate(ctx context.Context) (ApplyResult, error) {
	return s.applyExpectedVersion(ctx, "")
}

func (s *Service) applyExpectedVersion(ctx context.Context, version string) (ApplyResult, error) {
	ctx = normalizeContext(ctx)
	if err := contextError(ctx); err != nil {
		return ApplyResult{}, err
	}
	version = strings.TrimSpace(version)
	if version != "" && !validVersion(version) {
		return ApplyResult{}, ErrNoUpdateAvailable
	}
	s.mu.Lock()
	legacyApplyEnabled := s.legacyApplyEnabled
	s.mu.Unlock()
	if !legacyApplyEnabled {
		return ApplyResult{}, ErrLegacyExecutionDisabled
	}
	s.workflowMu.Lock()
	s.mu.Lock()
	if s.applyInProgress {
		s.mu.Unlock()
		s.workflowMu.Unlock()
		return ApplyResult{}, ErrApplyInProgress
	}
	stagedRecord, err := s.store.readStaged(ctx)
	if err != nil {
		s.mu.Unlock()
		s.workflowMu.Unlock()
		if errors.Is(err, os.ErrNotExist) {
			return ApplyResult{}, ErrStagedUpdateNotFound
		}
		return ApplyResult{}, err
	}
	staged := stagedRecord.StagedUpdate
	if version != "" && staged.Version != version {
		s.mu.Unlock()
		s.workflowMu.Unlock()
		return ApplyResult{}, ErrNoUpdateAvailable
	}
	if err := validateStagedUpdateReadyFor(ctx, s.cfg, s.store, stagedRecord, time.Now().UTC()); err != nil {
		s.mu.Unlock()
		s.workflowMu.Unlock()
		return ApplyResult{}, err
	}
	strategy := s.apply
	s.applyInProgress = true
	s.mu.Unlock()
	s.workflowMu.Unlock()
	defer func() {
		s.mu.Lock()
		s.applyInProgress = false
		s.mu.Unlock()
	}()
	result, err := strategy.Apply(ctx, staged)
	if err != nil {
		if contextError(ctx) != nil {
			return ApplyResult{}, ErrContextCanceled
		}
		return ApplyResult{}, ErrApplyFailed
	}
	result.Version = staged.Version
	if result.Message == "" || unsafeUpdateDetail(result.Message) {
		result.Message = "apply strategy completed"
	}
	return result, nil
}

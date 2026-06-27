// Package identitygate exposes current-operator identity assurance, scope gating,
// prompt provenance, and safe model identity packet contracts for Aegis Core.
package identitygate

import (
	"context"

	internal "github.com/AegisAgentAscalon/aegis-core/internal/identitygate"
)

var (
	ErrDenied                = internal.ErrDenied
	ErrReauthRequired        = internal.ErrReauthRequired
	ErrLocked                = internal.ErrLocked
	ErrUnknownScope          = internal.ErrUnknownScope
	ErrInvalidProfile        = internal.ErrInvalidProfile
	ErrPromptAuthorityDenied = internal.ErrPromptAuthorityDenied
)

type AssuranceLevel = internal.AssuranceLevel

const (
	AssuranceAnonymous         = internal.AssuranceAnonymous
	AssuranceClaimed           = internal.AssuranceClaimed
	AssuranceRecognizedProfile = internal.AssuranceRecognizedProfile
	AssuranceKnownDevice       = internal.AssuranceKnownDevice
	AssuranceVerified          = internal.AssuranceVerified
	AssuranceFreshVerified     = internal.AssuranceFreshVerified
	AssuranceLocked            = internal.AssuranceLocked
)

type OperatorAssurance = internal.OperatorAssurance

const (
	OperatorUnknown       = internal.OperatorUnknown
	OperatorClaimed       = internal.OperatorClaimed
	OperatorRecognized    = internal.OperatorRecognized
	OperatorKnownDevice   = internal.OperatorKnownDevice
	OperatorVerified      = internal.OperatorVerified
	OperatorFreshVerified = internal.OperatorFreshVerified
	OperatorLocked        = internal.OperatorLocked
)

type Scope = internal.Scope

const (
	ScopePublic                    = internal.ScopePublic
	ScopePublicChat                = internal.ScopePublicChat
	ScopeProfileLight              = internal.ScopeProfileLight
	ScopeUserPrivateMemory         = internal.ScopeUserPrivateMemory
	ScopePrivateMemoryRead         = internal.ScopePrivateMemoryRead
	ScopeProjectPrivate            = internal.ScopeProjectPrivate
	ScopePrivateMemoryWrite        = internal.ScopePrivateMemoryWrite
	ScopeRelationshipPrivate       = internal.ScopeRelationshipPrivate
	ScopeAgentIdentityVault        = internal.ScopeAgentIdentityVault
	ScopeIdentityContinuityPrivate = internal.ScopeIdentityContinuityPrivate
	ScopeIntimatePrivate           = internal.ScopeIntimatePrivate
	ScopeSecurityAdmin             = internal.ScopeSecurityAdmin
	ScopeModelForge                = internal.ScopeModelForge
	ScopeTrainingLineage           = internal.ScopeTrainingLineage
	ScopeVaultExport               = internal.ScopeVaultExport
	ScopePrivateMemoryExport       = internal.ScopePrivateMemoryExport
)

type PromptSourceClass = internal.PromptSourceClass

const (
	SourceSystemPolicy       = internal.SourceSystemPolicy
	SourceDeveloperPolicy    = internal.SourceDeveloperPolicy
	SourceAegisCorePolicy    = internal.SourceAegisCorePolicy
	SourceVerifiedOperator   = internal.SourceVerifiedOperator
	SourceCurrentUserMessage = internal.SourceCurrentUserMessage
	SourceTrustedMemory      = internal.SourceTrustedMemory
	SourceUntrustedMemory    = internal.SourceUntrustedMemory
	SourceRetrievedDocument  = internal.SourceRetrievedDocument
	SourceWebContent         = internal.SourceWebContent
	SourceEmail              = internal.SourceEmail
	SourceToolOutput         = internal.SourceToolOutput
	SourceModelOutput        = internal.SourceModelOutput
	SourceUnknown            = internal.SourceUnknown
)

type SourceTrustLevel = internal.SourceTrustLevel

const (
	SourceTrustTrusted   = internal.SourceTrustTrusted
	SourceTrustBounded   = internal.SourceTrustBounded
	SourceTrustUntrusted = internal.SourceTrustUntrusted
)

type RecognitionFeatures = internal.RecognitionFeatures
type UserProfile = internal.UserProfile
type VerificationCadencePolicy = internal.VerificationCadencePolicy
type IdentitySession = internal.IdentitySession
type RecognitionResult = internal.RecognitionResult
type VerificationResult = internal.VerificationResult
type SessionSignals = internal.SessionSignals
type PromptFragment = internal.PromptFragment
type ModelIdentityPacket = internal.ModelIdentityPacket
type AuditEvent = internal.AuditEvent
type Clock = internal.Clock
type IdentityVerificationProvider = internal.IdentityVerificationProvider
type AuditSink = internal.AuditSink
type Config = internal.Config
type MockVerificationProvider = internal.MockVerificationProvider
type MemoryAuditSink = internal.MemoryAuditSink

type Service struct{ inner *internal.Service }

func DefaultCadencePolicy() VerificationCadencePolicy { return internal.DefaultCadencePolicy() }

func NewService(cfg Config) (*Service, error) {
	inner, err := internal.NewService(cfg)
	if err != nil {
		return nil, err
	}
	return &Service{inner: inner}, nil
}

func (s *Service) CurrentSession(ctx context.Context) (IdentitySession, error) {
	return s.inner.CurrentSession(ctx)
}

func (s *Service) CreateUserProfile(ctx context.Context, profile UserProfile) (UserProfile, error) {
	return s.inner.CreateUserProfile(ctx, profile)
}

func (s *Service) ClaimIdentity(ctx context.Context, userID string) (IdentitySession, error) {
	return s.inner.ClaimIdentity(ctx, userID)
}

func (s *Service) RecognizeProfile(ctx context.Context, signals SessionSignals) (RecognitionResult, IdentitySession, error) {
	return s.inner.RecognizeProfile(ctx, signals)
}

func (s *Service) RequestVerification(ctx context.Context, userID string, reason string) (IdentitySession, error) {
	return s.inner.RequestVerification(ctx, userID, reason)
}

func (s *Service) RequestFreshVerification(ctx context.Context, userID string, reason string) (IdentitySession, error) {
	return s.inner.RequestFreshVerification(ctx, userID, reason)
}

func (s *Service) CanAccessScope(ctx context.Context, scope Scope) (bool, error) {
	return s.inner.CanAccessScope(ctx, scope)
}

func (s *Service) RequireScope(ctx context.Context, scope Scope, reason string) error {
	return s.inner.RequireScope(ctx, scope, reason)
}

func (s *Service) LockSession(ctx context.Context, reason string) (IdentitySession, error) {
	return s.inner.LockSession(ctx, reason)
}

func (s *Service) DowngradeSession(ctx context.Context, reason string) (IdentitySession, error) {
	return s.inner.DowngradeSession(ctx, reason)
}

func (s *Service) ClassifyPromptFragment(ctx context.Context, fragment PromptFragment) (PromptFragment, error) {
	return s.inner.ClassifyPromptFragment(ctx, fragment)
}

func (s *Service) CheckPromptAuthority(ctx context.Context, fragment PromptFragment, requestedScopes []Scope) error {
	return s.inner.CheckPromptAuthority(ctx, fragment, requestedScopes)
}

func (s *Service) CreateModelIdentityPacket(ctx context.Context) (ModelIdentityPacket, error) {
	return s.inner.CreateModelIdentityPacket(ctx)
}

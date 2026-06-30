package identitygate

const (
	EventSessionCreated          = "identity.session.created"
	EventIdentityClaimed         = "identity.claimed"
	EventProfileRecognized       = "identity.recognized"
	EventVerificationRequested   = "identity.verification.requested"
	EventVerificationSucceeded   = "identity.verification.succeeded"
	EventVerificationFailed      = "identity.verification.failed"
	EventScopeAllowed            = "identity.scope.allowed"
	EventScopeDenied             = "identity.scope.denied"
	EventSessionLocked           = "identity.session.locked"
	EventSessionDowngraded       = "identity.session.downgraded"
	EventPromptAuthorityDenied   = "identity.prompt_authority.denied"
	EventModelPacketCreated      = "identity.model_packet.created"
	EventOutputPolicyEvaluated   = "identity.output_policy.evaluated"
	EventSocialPolicyEvaluated   = "identity.social_policy.evaluated"
	EventEmergencyPolicyEvaluated = "identity.emergency_policy.evaluated"
)

func NewAuditEvent(kind string, summary string, clock Clock) AuditEvent {
	if clock == nil {
		clock = realClock{}
	}
	return AuditEvent{Kind: safe(kind), Summary: safe(summary), CreatedAt: clock.Now().UTC()}
}

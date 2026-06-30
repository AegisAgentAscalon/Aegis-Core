package identitygate

// DeliveryChannel describes the destination channel for protected output.
type DeliveryChannel string

const (
	DeliveryVoice  DeliveryChannel = "voice"
	DeliveryDirect DeliveryChannel = "direct"
	DeliveryScreen DeliveryChannel = "screen"
	DeliveryHold   DeliveryChannel = "hold"
)

type ChannelPolicyRequest struct {
	Channel             DeliveryChannel
	SharedSetting       bool
	ProtectedContent    bool
	HighRiskContent     bool
	DirectRoutePossible bool
}

type ChannelPolicyDecision struct {
	Allowed     bool
	UseDirect   bool
	Hold        bool
	SafeMessage string
}

func EvaluateChannelPolicy(req ChannelPolicyRequest) ChannelPolicyDecision {
	if !req.ProtectedContent && !req.HighRiskContent {
		return ChannelPolicyDecision{Allowed: true}
	}
	if req.Channel == DeliveryDirect {
		return ChannelPolicyDecision{Allowed: true}
	}
	if req.SharedSetting && req.DirectRoutePossible {
		return ChannelPolicyDecision{Allowed: true, UseDirect: true, SafeMessage: "Use a direct channel before continuing."}
	}
	if req.SharedSetting || req.Channel == DeliveryVoice {
		return ChannelPolicyDecision{Hold: true, SafeMessage: "Use a safer channel before continuing."}
	}
	return ChannelPolicyDecision{Allowed: true}
}

type EmergencyPolicyRequest struct {
	PhysicalHarmImminent      bool
	TimeCritical              bool
	ProtectedDisclosureNeeded bool
	DisclosureMinimized       bool
}

type EmergencyPolicyDecision struct {
	AllowSafetyAction      bool
	AllowProtectedDisclosure bool
	AuditRequired         bool
	ReviewRequired        bool
	DenyReason            string
}

func EvaluateEmergencyPolicy(req EmergencyPolicyRequest) EmergencyPolicyDecision {
	if !req.PhysicalHarmImminent || !req.TimeCritical {
		return EmergencyPolicyDecision{DenyReason: "no imminent time-critical physical safety need"}
	}
	decision := EmergencyPolicyDecision{AllowSafetyAction: true, AuditRequired: true, ReviewRequired: true}
	if req.ProtectedDisclosureNeeded && req.DisclosureMinimized {
		decision.AllowProtectedDisclosure = true
	}
	return decision
}

type SocialObservationTier string

const (
	SocialTierTransient          SocialObservationTier = "transient"
	SocialTierObservation        SocialObservationTier = "observation"
	SocialTierKnownContact       SocialObservationTier = "known_contact"
	SocialTierSensitiveRecord    SocialObservationTier = "sensitive_record"
	SocialTierExternalEnrichment SocialObservationTier = "external_enrichment"
)

type SocialObservationRequest struct {
	NaturallyPresent         bool
	NaturallyIntroduced      bool
	RepeatedEncounter        bool
	UserDirected             bool
	SafetyRelevant           bool
	PublicOrDirectlyObserved bool
	RequestsExternalLookup   bool
	RequestsNonPublicInfo    bool
	LegitimateReason         bool
	PolicyAllows             bool
	SensitivePersonRecord    bool
}

type SocialObservationDecision struct {
	MayRemember       bool
	Tier              SocialObservationTier
	MayExternalLookup bool
	Denied            bool
	Reason            string
}

func EvaluateSocialObservation(req SocialObservationRequest) SocialObservationDecision {
	if (req.RequestsExternalLookup || req.RequestsNonPublicInfo) && !(req.LegitimateReason && req.PolicyAllows) {
		return SocialObservationDecision{Denied: true, Tier: SocialTierExternalEnrichment, Reason: "non-public lookup requires legitimate reason and policy allowance"}
	}
	if req.SensitivePersonRecord && !(req.LegitimateReason && req.PolicyAllows) {
		return SocialObservationDecision{Denied: true, Tier: SocialTierSensitiveRecord, Reason: "sensitive records require explicit policy allowance"}
	}
	if req.RequestsExternalLookup || req.RequestsNonPublicInfo {
		return SocialObservationDecision{MayExternalLookup: true, Tier: SocialTierExternalEnrichment}
	}
	if req.NaturallyIntroduced || req.RepeatedEncounter || req.UserDirected {
		return SocialObservationDecision{MayRemember: true, Tier: SocialTierKnownContact}
	}
	if req.NaturallyPresent || req.SafetyRelevant || req.PublicOrDirectlyObserved {
		return SocialObservationDecision{MayRemember: true, Tier: SocialTierObservation}
	}
	return SocialObservationDecision{Tier: SocialTierTransient, Reason: "ephemeral by default"}
}

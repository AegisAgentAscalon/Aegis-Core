package identitygate

import "testing"

func TestChannelPolicyDefersProtectedVoiceInSharedSetting(t *testing.T) {
	decision := EvaluateChannelPolicy(ChannelPolicyRequest{Channel: DeliveryVoice, SharedSetting: true, ProtectedContent: true})
	if !decision.Hold || decision.Allowed {
		t.Fatalf("expected hold, got %+v", decision)
	}
}

func TestChannelPolicyRoutesToDirectWhenPossible(t *testing.T) {
	decision := EvaluateChannelPolicy(ChannelPolicyRequest{Channel: DeliveryVoice, SharedSetting: true, ProtectedContent: true, DirectRoutePossible: true})
	if !decision.Allowed || !decision.UseDirect {
		t.Fatalf("expected direct route, got %+v", decision)
	}
}

func TestEmergencyPolicyDoesNotBecomeGeneralBypass(t *testing.T) {
	decision := EvaluateEmergencyPolicy(EmergencyPolicyRequest{PhysicalHarmImminent: true, TimeCritical: true, ProtectedDisclosureNeeded: true})
	if !decision.AllowSafetyAction {
		t.Fatalf("expected safety action, got %+v", decision)
	}
	if decision.AllowProtectedDisclosure {
		t.Fatalf("protected disclosure allowed without minimization: %+v", decision)
	}
}

func TestSocialObservationAllowsNaturalContactButDeniesSnooping(t *testing.T) {
	remember := EvaluateSocialObservation(SocialObservationRequest{NaturallyIntroduced: true})
	if !remember.MayRemember || remember.Tier != SocialTierKnownContact {
		t.Fatalf("expected known-contact memory, got %+v", remember)
	}
	snoop := EvaluateSocialObservation(SocialObservationRequest{RequestsNonPublicInfo: true})
	if !snoop.Denied {
		t.Fatalf("expected non-public lookup denial, got %+v", snoop)
	}
}

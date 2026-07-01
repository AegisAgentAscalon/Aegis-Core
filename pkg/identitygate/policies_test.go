package identitygate

import "testing"

func TestPublicPolicyHelpers(t *testing.T) {
	channel := EvaluateChannelPolicy(ChannelPolicyRequest{Channel: DeliveryVoice, SharedSetting: true, ProtectedContent: true, DirectRoutePossible: true})
	if !channel.Allowed || !channel.UseDirect {
		t.Fatalf("expected direct channel routing, got %+v", channel)
	}
	emergency := EvaluateEmergencyPolicy(EmergencyPolicyRequest{PhysicalHarmImminent: true, TimeCritical: true, ProtectedDisclosureNeeded: true, DisclosureMinimized: true})
	if !emergency.AllowSafetyAction || !emergency.AllowProtectedDisclosure {
		t.Fatalf("expected minimal emergency disclosure, got %+v", emergency)
	}
	social := EvaluateSocialObservation(SocialObservationRequest{RequestsExternalLookup: true})
	if !social.Denied {
		t.Fatalf("expected external lookup denial, got %+v", social)
	}
}

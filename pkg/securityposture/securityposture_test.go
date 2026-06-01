package securityposture

import (
	"encoding/json"
	"reflect"
	"strings"
	"testing"
)

func TestContractConstantsAreStable(t *testing.T) {
	cases := map[string]string{
		"SeverityHigh":                 string(SeverityHigh),
		"PostureReviewRequired":        string(PostureReviewRequired),
		"BoundaryProviderTransport":    string(BoundaryProviderTransport),
		"BoundaryRelayTransport":       string(BoundaryRelayTransport),
		"RiskUnsafeIfTrusted":          string(RiskUnsafeIfTrusted),
		"RiskRequiresCallerPolicy":     string(RiskRequiresCallerPolicy),
		"RedactionApplied":             string(RedactionApplied),
		"RedactionRequired":            string(RedactionRequired),
		"BoundaryExplicitlyOutOfScope": string(BoundaryExplicitlyOutOfScope),
	}

	for name, got := range cases {
		if got == "" {
			t.Fatalf("%s must remain non-empty", name)
		}
		if strings.ContainsAny(got, " \t\n\r") {
			t.Fatalf("%s must remain wire-safe, got %q", name, got)
		}
	}
}

func TestIssueAndSummaryAreReadOnlyDTOs(t *testing.T) {
	if reflect.TypeOf(Issue{}).NumMethod() != 0 {
		t.Fatal("Issue must remain a DTO without command methods")
	}
	if reflect.TypeOf(Summary{}).NumMethod() != 0 {
		t.Fatal("Summary must remain a DTO without command methods")
	}

	summary := Summary{
		Capability: "updates",
		Posture:    PostureReviewRequired,
		Boundary:   BoundaryProviderTransport,
		Risk:       RiskUnsafeIfTrusted,
		Redaction:  RedactionApplied,
		Issues: []Issue{
			{
				Code:           "provider_transport_not_authority",
				Severity:       SeverityMedium,
				Posture:        PostureReviewRequired,
				Boundary:       BoundaryProviderTransport,
				Risk:           RiskUnsafeIfTrusted,
				Redaction:      RedactionApplied,
				Summary:        "provider output is classified before trust decisions",
				ReviewRequired: true,
			},
		},
	}

	body, err := json.Marshal(summary)
	if err != nil {
		t.Fatalf("marshal summary: %v", err)
	}

	text := string(body)
	for _, want := range []string{
		`"capability":"updates"`,
		`"posture":"review_required"`,
		`"boundary":"provider_transport"`,
		`"risk":"unsafe_if_trusted"`,
		`"redaction":"applied"`,
		`"review_required":true`,
	} {
		if !strings.Contains(text, want) {
			t.Fatalf("summary JSON missing %s in %s", want, text)
		}
	}
}

func TestContractsDoNotServiceSecurityProductActions(t *testing.T) {
	typeNames := []string{
		reflect.TypeOf(Severity("")).Name(),
		reflect.TypeOf(Posture("")).Name(),
		reflect.TypeOf(TrustBoundary("")).Name(),
		reflect.TypeOf(CapabilityRisk("")).Name(),
		reflect.TypeOf(RedactionStatus("")).Name(),
		reflect.TypeOf(Issue{}).Name(),
		reflect.TypeOf(Summary{}).Name(),
	}

	forbidden := []string{
		"Scan",
		"Remediate",
		"Quarantine",
		"Monitor",
		"Protect",
		"Execute",
		"Apply",
		"Merge",
		"Retry",
	}

	for _, name := range typeNames {
		for _, term := range forbidden {
			if strings.Contains(name, term) {
				t.Fatalf("contract type %s must not service action term %s", name, term)
			}
		}
	}
}

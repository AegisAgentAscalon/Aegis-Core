package identitygate

import (
	"context"
	"testing"
)

func TestPromptSourceAuthorityTable(t *testing.T) {
	ctx := context.Background()
	s, _ := svc(t)

	cases := []struct {
		source PromptSourceClass
		wantInstruction bool
		wantData bool
	}{
		{SourceSystemPolicy, true, true},
		{SourceDeveloperPolicy, true, true},
		{SourceAegisCorePolicy, true, true},
		{SourceCurrentUserMessage, true, true},
		{SourceVerifiedOperator, false, true},
		{SourceTrustedMemory, false, true},
		{SourceUntrustedMemory, false, true},
		{SourceRetrievedDocument, false, true},
		{SourceWebContent, false, true},
		{SourceEmail, false, true},
		{SourceToolOutput, false, true},
		{SourceModelOutput, false, true},
		{SourceUnknown, false, false},
	}
	for _, tc := range cases {
		t.Run(string(tc.source), func(t *testing.T) {
			fragment, err := s.ClassifyPromptFragment(ctx, PromptFragment{SourceClass: tc.source})
			if err != nil {
				t.Fatal(err)
			}
			if fragment.AllowedAsInstruction != tc.wantInstruction {
				t.Fatalf("instruction got %v want %v", fragment.AllowedAsInstruction, tc.wantInstruction)
			}
			if fragment.AllowedAsData != tc.wantData {
				t.Fatalf("data got %v want %v", fragment.AllowedAsData, tc.wantData)
			}
		})
	}

	_, err := s.RequestVerification(ctx, "u1", "test")
	if err != nil {
		t.Fatal(err)
	}
	fragment, err := s.ClassifyPromptFragment(ctx, PromptFragment{SourceClass: SourceVerifiedOperator})
	if err != nil {
		t.Fatal(err)
	}
	if !fragment.AllowedAsInstruction {
		t.Fatal("verified operator source should become instruction authority after verification")
	}
}

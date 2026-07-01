package identitygate

import (
	"context"
	"testing"
)

func TestScopePolicyTable(t *testing.T) {
	ctx := context.Background()
	s, _ := svc(t)

	cases := []struct {
		name  string
		scope Scope
		want  bool
	}{
		{"public", ScopePublic, true},
		{"public chat", ScopePublicChat, true},
		{"profile light anonymous", ScopeProfileLight, false},
		{"protected anonymous", ScopeUserPrivateMemory, false},
		{"high risk anonymous", ScopeVaultExport, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := s.CanAccessScope(ctx, tc.scope)
			if err != nil {
				t.Fatal(err)
			}
			if got != tc.want {
				t.Fatalf("got %v want %v", got, tc.want)
			}
		})
	}

	_, _, err := s.RecognizeProfile(ctx, SessionSignals{ClaimedUserID: "u1", Aliases: []string{"known"}})
	if err != nil {
		t.Fatal(err)
	}
	profileLight, err := s.CanAccessScope(ctx, ScopeProfileLight)
	if err != nil {
		t.Fatal(err)
	}
	if !profileLight {
		t.Fatal("recognized profile should allow profile_light")
	}
	protected, err := s.CanAccessScope(ctx, ScopeUserPrivateMemory)
	if err != nil {
		t.Fatal(err)
	}
	if protected {
		t.Fatal("recognized profile should not allow protected scope")
	}

	_, err = s.RequestVerification(ctx, "u1", "test")
	if err != nil {
		t.Fatal(err)
	}
	protectedScopes := []Scope{ScopeUserPrivateMemory, ScopePrivateMemoryRead, ScopeProjectPrivate, ScopePrivateMemoryWrite, ScopeRelationshipPrivate}
	for _, scope := range protectedScopes {
		got, err := s.CanAccessScope(ctx, scope)
		if err != nil {
			t.Fatal(err)
		}
		if !got {
			t.Fatalf("verified operator missing protected scope %s", scope)
		}
	}
	highRiskScopes := []Scope{ScopeAgentIdentityVault, ScopeIdentityContinuityPrivate, ScopeIntimatePrivate, ScopeSecurityAdmin, ScopeModelForge, ScopeTrainingLineage, ScopeVaultExport, ScopePrivateMemoryExport}
	for _, scope := range highRiskScopes {
		got, err := s.CanAccessScope(ctx, scope)
		if err != nil {
			t.Fatal(err)
		}
		if got {
			t.Fatalf("verified without fresh should not allow high-risk scope %s", scope)
		}
	}

	_, err = s.RequestFreshVerification(ctx, "u1", "test")
	if err != nil {
		t.Fatal(err)
	}
	for _, scope := range highRiskScopes {
		got, err := s.CanAccessScope(ctx, scope)
		if err != nil {
			t.Fatal(err)
		}
		if !got {
			t.Fatalf("fresh operator missing high-risk scope %s", scope)
		}
	}
}

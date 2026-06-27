package main

import (
	"context"
	"fmt"

	"github.com/AegisAgentAscalon/aegis-core/pkg/identitygate"
)

func main() {
	ctx := context.Background()
	svc, _ := identitygate.NewService(identitygate.Config{})
	_, _ = svc.CreateUserProfile(ctx, identitygate.UserProfile{
		UserID:      "demo",
		DisplayName: "Demo",
		RecognitionFeatures: identitygate.RecognitionFeatures{
			Aliases: []string{"demo"},
		},
	})
	_, session, _ := svc.RecognizeProfile(ctx, identitygate.SessionSignals{
		ClaimedUserID: "demo",
		Aliases:       []string{"demo"},
	})
	fmt.Println(session.AssuranceLevel)
	allowed, _ := svc.CanAccessScope(ctx, identitygate.ScopeUserPrivateMemory)
	fmt.Println("private before verification:", allowed)
	_, _ = svc.RequestVerification(ctx, "demo", "")
	allowed, _ = svc.CanAccessScope(ctx, identitygate.ScopeUserPrivateMemory)
	fmt.Println("private after verification:", allowed)
}

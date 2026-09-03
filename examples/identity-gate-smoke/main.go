package main

import (
	"context"
	"fmt"

	"github.com/AegisAgentAscalon/aegis-core/pkg/identitygate"
)

func main() {
	ctx := context.Background()
	svc, err := identitygate.NewService(identitygate.Config{
		ReceiptProvider: identitygate.MockVerificationProvider{Allow: true},
	})
	if err != nil {
		panic(err)
	}
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
	receipt, _, err := svc.RequestVerificationReceipt(ctx, "demo", "smoke example")
	if err != nil {
		panic(err)
	}
	fmt.Println("verification provider:", receipt.Provider)
	allowed, _ = svc.CanAccessScope(ctx, identitygate.ScopeUserPrivateMemory)
	fmt.Println("private after verification:", allowed)
}

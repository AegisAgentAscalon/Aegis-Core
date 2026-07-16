package identitygate_test

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"reflect"
	"strings"
	"testing"
	"time"

	identitygate "github.com/AegisAgentAscalon/aegis-core/pkg/identitygate"
)

type externalReceiptProvider struct{}

var _ identitygate.VerificationReceiptProvider = externalReceiptProvider{}

func (externalReceiptProvider) ProviderName() string { return "external-conformance-provider" }

func (p externalReceiptProvider) Verify(ctx context.Context, request identitygate.VerificationRequest) (identitygate.VerificationReceipt, error) {
	if err := ctx.Err(); err != nil {
		return identitygate.VerificationReceipt{}, err
	}
	now := time.Now().UTC()
	return identitygate.VerificationReceipt{
		ReceiptID:     randomExternalID(),
		AttemptID:     request.AttemptID,
		AssertionID:   request.AssertionID,
		SessionID:     request.SessionID,
		SubjectUserID: request.SubjectUserID,
		Provider:      p.ProviderName(),
		Verified:      true,
		Fresh:         request.FreshRequired,
		VerifiedAt:    now,
		ExpiresAt:     now.Add(5 * time.Minute),
	}, nil
}

func randomExternalID() string {
	value := make([]byte, 18)
	if _, err := rand.Read(value); err != nil {
		panic(err)
	}
	return "external_receipt_" + base64.RawURLEncoding.EncodeToString(value)
}

func TestExternalReceiptProviderConformance(t *testing.T) {
	svc, err := identitygate.NewService(identitygate.Config{ReceiptProvider: externalReceiptProvider{}})
	if err != nil {
		t.Fatal(err)
	}
	receipt, session, err := svc.RequestFreshVerificationReceipt(context.Background(), "external-user", "conformance")
	if err != nil {
		t.Fatal(err)
	}
	if !receipt.Verified || !receipt.Fresh || session.AssuranceLevel != identitygate.AssuranceFreshVerified {
		t.Fatalf("external provider receipt was not accepted: receipt=%+v session=%+v", receipt, session)
	}
	if receipt.SessionID != session.SessionID || receipt.SubjectUserID != session.VerifiedOperatorUserID {
		t.Fatalf("external receipt bindings were lost: receipt=%+v session=%+v", receipt, session)
	}
}

func TestVerificationContractsContainNoForbiddenMaterialFields(t *testing.T) {
	contracts := []reflect.Type{
		reflect.TypeOf(identitygate.VerificationRequest{}),
		reflect.TypeOf(identitygate.VerificationReceipt{}),
	}
	forbidden := []string{"biometric", "template", "credential", "payload", "sample", "secret", "token"}
	for _, contract := range contracts {
		for i := 0; i < contract.NumField(); i++ {
			field := contract.Field(i)
			name := strings.ToLower(field.Name)
			for _, term := range forbidden {
				if strings.Contains(name, term) {
					t.Fatalf("%s.%s exposes forbidden material category %q", contract.Name(), field.Name, term)
				}
			}
			if strings.Contains(name, "assertion") && field.Name != "AssertionID" {
				t.Fatalf("%s.%s exposes an assertion rather than an assertion identifier", contract.Name(), field.Name)
			}
		}
	}
}

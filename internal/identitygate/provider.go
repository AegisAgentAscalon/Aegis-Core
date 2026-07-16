package identitygate

import (
	"context"
	"errors"
	"reflect"
)

type legacyVerificationProviderAdapter struct {
	provider IdentityVerificationProvider
	name     string
}

func (a legacyVerificationProviderAdapter) ProviderName() string { return a.name }

func (a legacyVerificationProviderAdapter) Verify(ctx context.Context, request VerificationRequest) (VerificationReceipt, error) {
	if !a.provider.CanVerify(ctx, request.SubjectUserID) {
		return VerificationReceipt{}, ErrReauthRequired
	}

	var (
		result VerificationResult
		err    error
	)
	if request.FreshRequired {
		result, err = a.provider.RequestFreshVerification(ctx, request.SubjectUserID, request.Reason)
	} else {
		result, err = a.provider.RequestVerification(ctx, request.SubjectUserID, request.Reason)
	}
	if err != nil {
		return VerificationReceipt{}, err
	}
	receiptID, err := newOpaqueID("receipt")
	if err != nil {
		return VerificationReceipt{}, err
	}
	return VerificationReceipt{
		ReceiptID:     receiptID,
		AttemptID:     request.AttemptID,
		AssertionID:   request.AssertionID,
		SessionID:     request.SessionID,
		SubjectUserID: result.UserID,
		Provider:      result.Provider,
		Verified:      result.Verified,
		Fresh:         result.Fresh,
		VerifiedAt:    result.VerifiedAt,
		ExpiresAt:     result.ExpiresAt,
	}, nil
}

func configuredReceiptProvider(cfg Config) (VerificationReceiptProvider, string, error) {
	receiptConfigured := !nilInterface(cfg.ReceiptProvider)
	legacyConfigured := !nilInterface(cfg.VerificationProvider)
	if receiptConfigured && legacyConfigured {
		return nil, "", ErrInvalidVerificationConfig
	}

	var provider VerificationReceiptProvider
	if receiptConfigured {
		provider = cfg.ReceiptProvider
	} else if legacyConfigured {
		name := cfg.VerificationProvider.ProviderName()
		provider = legacyVerificationProviderAdapter{provider: cfg.VerificationProvider, name: name}
	} else {
		return nil, "", ErrVerificationProviderRequired
	}

	name := provider.ProviderName()
	if !validProviderName(name) {
		return nil, "", errors.Join(ErrInvalidVerificationConfig, errors.New("provider name is empty or unsafe"))
	}
	return provider, name, nil
}

func nilInterface(value any) bool {
	if value == nil {
		return true
	}
	reflected := reflect.ValueOf(value)
	switch reflected.Kind() {
	case reflect.Chan, reflect.Func, reflect.Interface, reflect.Map, reflect.Pointer, reflect.Slice:
		return reflected.IsNil()
	default:
		return false
	}
}

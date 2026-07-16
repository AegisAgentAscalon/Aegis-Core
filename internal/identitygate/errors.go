package identitygate

import "errors"

var (
	ErrDenied                       = errors.New("identitygate: denied")
	ErrReauthRequired               = errors.New("identitygate: reauth required")
	ErrLocked                       = errors.New("identitygate: session locked")
	ErrUnknownScope                 = errors.New("identitygate: unknown scope")
	ErrInvalidProfile               = errors.New("identitygate: invalid profile")
	ErrPromptAuthorityDenied        = errors.New("identitygate: prompt source lacks authority")
	ErrVerificationProviderRequired = errors.New("identitygate: verification provider required")
	ErrInvalidVerificationConfig    = errors.New("identitygate: invalid verification configuration")
	ErrInvalidVerificationReceipt   = errors.New("identitygate: invalid verification receipt")
	ErrVerificationReceiptUsed      = errors.New("identitygate: verification receipt already used")
)

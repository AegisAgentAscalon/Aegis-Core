package identitygate

import "time"

func DefaultCadencePolicy() VerificationCadencePolicy {
	return VerificationCadencePolicy{
		VerifiedWindow:    30 * time.Minute,
		FreshWindow:       5 * time.Minute,
		IdleTimeout:       15 * time.Minute,
		MaxVerifiedWindow: time.Hour,
		MaxFreshWindow:    10 * time.Minute,
	}
}

func resolve(p VerificationCadencePolicy) VerificationCadencePolicy {
	d := DefaultCadencePolicy()
	if p.VerifiedWindow > 0 {
		d.VerifiedWindow = p.VerifiedWindow
	}
	if p.FreshWindow > 0 {
		d.FreshWindow = p.FreshWindow
	}
	if p.IdleTimeout > 0 {
		d.IdleTimeout = p.IdleTimeout
	}
	if p.MaxVerifiedWindow > 0 {
		d.MaxVerifiedWindow = p.MaxVerifiedWindow
	}
	if p.MaxFreshWindow > 0 {
		d.MaxFreshWindow = p.MaxFreshWindow
	}
	if d.VerifiedWindow > d.MaxVerifiedWindow {
		d.VerifiedWindow = d.MaxVerifiedWindow
	}
	if d.FreshWindow > d.MaxFreshWindow {
		d.FreshWindow = d.MaxFreshWindow
	}
	d.PublicChatRequiresAuth = p.PublicChatRequiresAuth
	d.ProfileLightRequiresAuth = p.ProfileLightRequiresAuth
	d.SlidingVerifiedWindow = p.SlidingVerifiedWindow
	d.SlidingFreshWindow = p.SlidingFreshWindow
	d.BurnFreshAfterSensitiveUse = p.BurnFreshAfterSensitiveUse
	return d
}

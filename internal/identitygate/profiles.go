package identitygate

import (
	"context"
	"maps"
	"slices"
	"strings"
)

func (s *Service) CreateUserProfile(ctx context.Context, profile UserProfile) (UserProfile, error) {
	if err := ctx.Err(); err != nil {
		return UserProfile{}, err
	}
	if profile.UserID == "" || secretish(profile.DisplayName) || secretish(strings.Join(profile.RecognitionFeatures.Aliases, " ")) {
		return UserProfile{}, ErrInvalidProfile
	}
	s.mu.Lock()
	defer s.unlockAndDrainAudit()
	s.profiles[profile.UserID] = cloneProfile(profile)
	return cloneProfile(profile), nil
}

func cloneProfile(profile UserProfile) UserProfile {
	profile.RecognitionFeatures.Aliases = slices.Clone(profile.RecognitionFeatures.Aliases)
	profile.RecognitionFeatures.Topics = slices.Clone(profile.RecognitionFeatures.Topics)
	profile.RecognitionFeatures.SafeMetadata = maps.Clone(profile.RecognitionFeatures.SafeMetadata)
	return profile
}

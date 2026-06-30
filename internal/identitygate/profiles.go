package identitygate

import (
	"context"
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
	defer s.mu.Unlock()
	s.profiles[profile.UserID] = profile
	return profile, nil
}

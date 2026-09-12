package auth

import "testing"

// newTestAuthService constructs a valid fixture; constructor rejection tests call the API directly.
func newTestAuthService(t *testing.T, cfg AppConfig) *Service {
	t.Helper()
	svc, err := NewService(cfg)
	if err != nil {
		t.Fatal(err)
	}
	return svc
}

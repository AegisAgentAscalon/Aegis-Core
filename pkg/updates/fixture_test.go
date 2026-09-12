package updates

import "testing"

// newTestUpdateService constructs a valid fixture; constructor rejection tests call the API directly.
func newTestUpdateService(t *testing.T, cfg AppConfig) *Service {
	t.Helper()
	svc, err := NewService(cfg, nil)
	if err != nil {
		t.Fatal(err)
	}
	return svc
}

package relay

import (
	"crypto/subtle"
	"net/http"
	"strings"
)

// HTTPRelayAuthorizer is a narrow access-control seam for self-hosted relay
// endpoints. Authorization permits relay API access only; it is not device
// trust, profile truth, or sync authority.
type HTTPRelayAuthorizer interface {
	AuthorizeRelayRequest(r *http.Request) bool
}

// BearerRelayAuthorizer checks a static bearer credential for self-hosted
// deployments. Callers own credential provisioning and rotation.
type BearerRelayAuthorizer struct {
	Bearer string
}

func (a BearerRelayAuthorizer) AuthorizeRelayRequest(r *http.Request) bool {
	expected := strings.TrimSpace(a.Bearer)
	if expected == "" {
		return false
	}
	got := strings.TrimSpace(r.Header.Get("Authorization"))
	if !strings.HasPrefix(got, "Bearer ") {
		return false
	}
	token := strings.TrimSpace(strings.TrimPrefix(got, "Bearer "))
	return subtle.ConstantTimeCompare([]byte(token), []byte(expected)) == 1
}

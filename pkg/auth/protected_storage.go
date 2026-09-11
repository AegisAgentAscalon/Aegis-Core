package auth

import (
	"context"
	"encoding/json"
	"errors"
	"strings"

	"github.com/AegisAgentAscalon/aegis-core/pkg/secretstore"
)

func (s *store) getProtected(key secretstore.Key) ([]byte, error) {
	b, err := s.protected.Get(context.Background(), key)
	if err == nil {
		return b, nil
	}
	if errors.Is(err, secretstore.ErrNotFound) {
		return nil, secretstore.ErrNotFound
	}
	return nil, ErrStorageUnavailable
}

func (s *store) putProtected(key secretstore.Key, value []byte) error {
	if err := s.protected.Put(context.Background(), key, value); err != nil {
		return ErrStorageUnavailable
	}
	return nil
}

func (s *store) deleteProtected(key secretstore.Key) error {
	err := s.protected.Delete(context.Background(), key)
	if err == nil || errors.Is(err, secretstore.ErrNotFound) {
		return nil
	}
	return ErrStorageUnavailable
}

func decodeProtectedToken(b []byte) (token, error) {
	var t token
	if err := json.Unmarshal(b, &t); err != nil || strings.TrimSpace(t.AccessToken) == "" || t.Expiry.IsZero() {
		return token{}, ErrProtectedStorageCorrupt
	}
	return t, nil
}

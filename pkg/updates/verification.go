// Downloaded artifact verification and metadata.
package updates

import (
	"context"
	"errors"
	"os"
	"strings"
	"time"
)

func (s *Service) VerifyUpdate(ctx context.Context, version string) (VerifyResult, error) {
	ctx = normalizeContext(ctx)
	if err := contextError(ctx); err != nil {
		return VerifyResult{}, err
	}
	s.workflowMu.Lock()
	defer s.workflowMu.Unlock()
	snapshot, err := s.operationSnapshot()
	if err != nil {
		return VerifyResult{}, err
	}
	return s.verifyUpdateSnapshot(snapshot, version)
}

func (s *Service) verifyUpdateSnapshot(snapshot serviceSnapshot, version string) (VerifyResult, error) {
	downloaded, err := snapshot.store.readDownloaded(context.Background())
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return VerifyResult{}, ErrVerificationFailed
		}
		return VerifyResult{}, err
	}
	if version != "" && downloaded.Manifest.Version != strings.TrimSpace(version) {
		return VerifyResult{}, ErrVerificationFailed
	}
	if err := validateDownloadedUpdateFor(snapshot.cfg, snapshot.store, downloaded); err != nil {
		return VerifyResult{}, err
	}
	got, err := fileSHA256(downloaded.ArtifactPath)
	if err != nil || !strings.EqualFold(got, downloaded.Artifact.SHA256) {
		return VerifyResult{}, ErrVerificationFailed
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.applyInProgress {
		return VerifyResult{}, ErrApplyInProgress
	}
	if !s.currentLocked(snapshot) {
		return VerifyResult{}, ErrUpdateStateChanged
	}
	verified := verifiedUpdate{SchemaVersion: schemaVersion, Downloaded: downloaded, VerifiedAt: time.Now().UTC()}
	if err := snapshot.store.writeVerified(context.Background(), verified); err != nil {
		return VerifyResult{}, err
	}
	return VerifyResult{Version: downloaded.Manifest.Version, ArtifactName: downloaded.Artifact.Filename, OK: true, Message: "update verified"}, nil
}

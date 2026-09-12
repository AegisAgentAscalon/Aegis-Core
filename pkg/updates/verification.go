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
	snapshot, err := s.beginOperation(ctx, true)
	if err != nil {
		return VerifyResult{}, err
	}
	result, err := verifyUpdateSnapshot(ctx, snapshot, version)
	if err != nil {
		return VerifyResult{}, err
	}
	if err := s.publishOperation(ctx, snapshot); err != nil {
		return VerifyResult{}, err
	}
	return result, nil
}

func verifyUpdateSnapshot(ctx context.Context, snapshot serviceSnapshot, version string) (VerifyResult, error) {
	if err := candidateAdmission(ctx, snapshot); err != nil {
		return VerifyResult{}, err
	}
	downloaded, err := snapshot.view.downloaded.read()
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
	if err := contextError(ctx); err != nil {
		return VerifyResult{}, err
	}
	snapshot.view.verified = stored(verifiedUpdate{SchemaVersion: schemaVersion, Downloaded: downloaded, VerifiedAt: time.Now().UTC()})
	return VerifyResult{Version: downloaded.Manifest.Version, ArtifactName: downloaded.Artifact.Filename, OK: true, Message: "update verified"}, nil
}

func candidateAdmission(ctx context.Context, snapshot serviceSnapshot) error {
	if snapshot.view.candidateFault {
		return ErrStorageUnavailable
	}
	if snapshot.view.token == "" {
		invalid, err := snapshot.store.candidateProblem(ctx, snapshot.view)
		if err != nil {
			return err
		}
		if invalid {
			return ErrStorageUnavailable
		}
	}
	return nil
}

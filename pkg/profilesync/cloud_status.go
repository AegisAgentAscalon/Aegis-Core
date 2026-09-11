package profilesync

import (
	"context"
	"errors"
)

func cloudIssue(code string, err error, blocking bool) CloudSyncIssue {
	return sanitizeCloudIssue(CloudSyncIssue{Code: code, Message: sanitizeCloudError(err).Error(), Blocking: blocking})
}

func sanitizeCloudProviderStatus(status CloudSyncProviderStatus) CloudSyncProviderStatus {
	out := CloudSyncProviderStatus{
		Available:        status.Available,
		ProviderID:       safeID(status.ProviderID),
		ProfileNamespace: safeID(status.ProfileNamespace),
		Summary:          safeSummary(status.Summary, "profile sync cloud provider status"),
	}
	if status.ManifestCount > 0 {
		out.ManifestCount = status.ManifestCount
	}
	if status.ObjectCount > 0 {
		out.ObjectCount = status.ObjectCount
	}
	for _, issue := range status.Issues {
		out.Issues = append(out.Issues, sanitizeCloudIssue(issue))
	}
	if !out.Available && len(out.Issues) == 0 {
		out.Issues = append(out.Issues, cloudIssue("cloud_provider_unavailable", ErrCloudProviderUnavailable, false))
	}
	return out
}

func sanitizeCloudIssue(issue CloudSyncIssue) CloudSyncIssue {
	code := safeID(issue.Code)
	if code == "" {
		code = "cloud_sync_issue"
	}
	return CloudSyncIssue{Code: code, Message: safeSummary(issue.Message, ErrCloudProviderUnavailable.Error()), Blocking: issue.Blocking}
}

func sanitizeCloudError(err error) error {
	if err == nil {
		return nil
	}
	if errors.Is(err, context.Canceled) {
		return ErrTransportUnavailable
	}
	if errors.Is(err, context.DeadlineExceeded) {
		return ErrTransportUnavailable
	}
	switch {
	case errors.Is(err, ErrCloudObjectNotFound):
		return ErrCloudObjectNotFound
	case errors.Is(err, ErrInvalidCloudManifest):
		return ErrInvalidCloudManifest
	case errors.Is(err, ErrInvalidCloudObject):
		return ErrInvalidCloudObject
	case errors.Is(err, ErrCloudHashMismatch):
		return ErrCloudHashMismatch
	case errors.Is(err, ErrCloudObjectTooLarge):
		return ErrCloudObjectTooLarge
	case errors.Is(err, ErrCloudStoreCorrupt):
		return ErrCloudStoreCorrupt
	case errors.Is(err, ErrCloudObjectConflict):
		return ErrCloudObjectConflict
	default:
		return ErrCloudProviderUnavailable
	}
}

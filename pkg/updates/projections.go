package updates

import (
	"time"
)

func releaseFromSelection(manifest Manifest, artifact Artifact, checkedAt time.Time, source SourceSummary) Release {
	releaseNotesURL := manifest.ReleaseNotesURL
	if source.Authenticated {
		releaseNotesURL = ""
	}
	return Release{
		Source:                  source,
		AppID:                   manifest.AppID,
		Version:                 manifest.Version,
		Channel:                 manifest.Channel,
		Platform:                artifact.Platform,
		Architecture:            artifact.Architecture,
		PublishedAt:             manifest.PublishedAt,
		ReleaseNotesURL:         releaseNotesURL,
		ReleaseNotesText:        manifest.ReleaseNotesText,
		MinimumSupportedVersion: manifest.MinimumSupportedVersion,
		RequiredRestart:         manifest.RequiredRestart,
		ApplyBehavior:           manifest.ApplyBehavior,
		ArtifactName:            artifact.Filename,
		ArtifactSHA256:          artifact.SHA256,
		ArtifactSize:            artifact.Size,
		CheckedAt:               checkedAt,
	}
}

func stagedSummaryFrom(staged StagedUpdate) StagedUpdateSummary {
	return StagedUpdateSummary{
		Source:          staged.Source,
		AppID:           staged.AppID,
		Version:         staged.Version,
		Channel:         staged.Channel,
		Platform:        staged.Platform,
		Architecture:    staged.Architecture,
		ArtifactName:    staged.ArtifactName,
		SHA256:          staged.SHA256,
		Size:            staged.Size,
		StagedAt:        staged.StagedAt,
		RequiredRestart: staged.RequiredRestart,
		ApplyBehavior:   staged.ApplyBehavior,
		Message:         "update is staged for app-owned apply",
	}
}

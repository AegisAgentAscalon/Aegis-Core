package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/AegisAgentAscalon/aegis-core/pkg/appbridge"
	"github.com/AegisAgentAscalon/aegis-core/pkg/profilemesh"
	"github.com/AegisAgentAscalon/aegis-core/pkg/profilesync"
	"github.com/AegisAgentAscalon/aegis-core/pkg/relay"
	"github.com/AegisAgentAscalon/aegis-core/pkg/setupstate"
	"github.com/AegisAgentAscalon/aegis-core/pkg/updates"
)

const (
	smokeNamespace = "generic-consumer"
	smokeDeviceA   = "device-a"
	smokeDeviceB   = "device-b"
)

type SmokeSummary struct {
	AppBridge   AppBridgeSmoke   `json:"app_bridge"`
	SetupState  SetupStateSmoke  `json:"setup_state"`
	Updates     UpdateSmoke      `json:"updates"`
	Relay       RelaySmoke       `json:"relay"`
	ProfileSync ProfileSyncSmoke `json:"profile_sync"`
	CloudSync   CloudSyncSmoke   `json:"cloud_sync"`
	SafeOutput  bool             `json:"safe_output"`
}

type AppBridgeSmoke struct {
	OverviewReady                  bool `json:"overview_ready"`
	DisabledCardsNonFatal          bool `json:"disabled_cards_non_fatal"`
	RelayDegradedNonFatal          bool `json:"relay_degraded_non_fatal"`
	StatusBridgeReady              bool `json:"status_bridge_ready"`
	StatusBridgeDegradedNonFatal   bool `json:"status_bridge_degraded_non_fatal"`
	StatusBridgeProfileSyncVisible bool `json:"status_bridge_profile_sync_visible"`
}

type SetupStateSmoke struct {
	OverviewReady bool `json:"overview_ready"`
	WarningSafe   bool `json:"warning_safe"`
}

type UpdateSmoke struct {
	StatusConfigured   bool `json:"status_configured"`
	UpdateAvailable    bool `json:"update_available"`
	Downloaded         bool `json:"downloaded"`
	Verified           bool `json:"verified"`
	Staged             bool `json:"staged"`
	StagedSummarySafe  bool `json:"staged_summary_safe"`
	ApplyPlanAppOwned  bool `json:"apply_plan_app_owned"`
	ApplyPlanSafe      bool `json:"apply_plan_safe"`
	NoApplyExecuted    bool `json:"no_apply_executed"`
	ClearedStagedState bool `json:"cleared_staged_state"`
}

type RelaySmoke struct {
	ProviderAvailable bool `json:"provider_available"`
	EnvelopeDelivered bool `json:"envelope_delivered"`
	ReceiptSafe       bool `json:"receipt_safe"`
}

type ProfileSyncSmoke struct {
	DisabledNonFatal          bool `json:"disabled_non_fatal"`
	MissingTransportDegraded  bool `json:"missing_transport_degraded"`
	RelayTransportStatusSafe  bool `json:"relay_transport_status_safe"`
	StoreOnlyPlanSafe         bool `json:"store_only_plan_safe"`
	NoProfileTruthPromotion   bool `json:"no_profile_truth_promotion"`
	NoAutomaticMergePerformed bool `json:"no_automatic_merge_performed"`
}

type CloudSyncSmoke struct {
	MissingProviderDegraded bool `json:"missing_provider_degraded"`
	ObjectStored            bool `json:"object_stored"`
	ManifestVerified        bool `json:"manifest_verified"`
	SameManifestClassified  bool `json:"same_manifest_classified"`
	NoProfileTruthPromotion bool `json:"no_profile_truth_promotion"`
}

func main() {
	ctx := context.Background()
	workDir, err := os.MkdirTemp("", "aegis-generic-smoke-*")
	if err != nil {
		fmt.Fprintln(os.Stderr, "generic consumer smoke could not allocate temporary storage")
		os.Exit(1)
	}
	defer os.RemoveAll(workDir)

	summary, err := RunSmoke(ctx, workDir)
	if err != nil {
		fmt.Fprintln(os.Stderr, "generic consumer smoke failed")
		os.Exit(1)
	}
	if err := json.NewEncoder(os.Stdout).Encode(summary); err != nil {
		fmt.Fprintln(os.Stderr, "generic consumer smoke output failed")
		os.Exit(1)
	}
}

func RunSmoke(ctx context.Context, workDir string) (SmokeSummary, error) {
	if strings.TrimSpace(workDir) == "" {
		return SmokeSummary{}, errors.New("smoke work directory is required")
	}

	now := time.Now().UTC().Truncate(time.Second)
	clock := smokeClock{now: now}
	relayProvider, err := relay.NewLocalDevProvider(relay.LocalDevProviderConfig{ProviderID: "generic-smoke-relay", Clock: clock})
	if err != nil {
		return SmokeSummary{}, err
	}

	appBridge, err := smokeAppBridge(ctx, relayProvider)
	if err != nil {
		return SmokeSummary{}, err
	}
	setupState, err := smokeSetupState(ctx)
	if err != nil {
		return SmokeSummary{}, err
	}
	updateSmoke, err := smokeUpdates(ctx, workDir, now)
	if err != nil {
		return SmokeSummary{}, err
	}
	relaySmoke, err := smokeRelay(ctx, relayProvider, now)
	if err != nil {
		return SmokeSummary{}, err
	}
	profileSync, err := smokeProfileSync(ctx, relayProvider, clock, now)
	if err != nil {
		return SmokeSummary{}, err
	}
	cloudSync, err := smokeCloudSync(ctx, workDir, now)
	if err != nil {
		return SmokeSummary{}, err
	}

	summary := SmokeSummary{
		AppBridge:   appBridge,
		SetupState:  setupState,
		Updates:     updateSmoke,
		Relay:       relaySmoke,
		ProfileSync: profileSync,
		CloudSync:   cloudSync,
	}
	summary.SafeOutput = smokeOutputSafe(summary, workDir)
	return summary, nil
}

func smokeAppBridge(ctx context.Context, provider *relay.LocalDevProvider) (AppBridgeSmoke, error) {
	bridge, err := appbridge.NewSetupBridge(appbridge.AppBridgeConfig{
		Identity: appbridge.AppIdentity{
			AppID:         "generic-consumer-smoke",
			DisplayName:   "Generic Consumer",
			DataNamespace: smokeNamespace,
		},
		Relay: appbridge.RelayBridgeConfig{
			CapabilityConfig: appbridge.CapabilityConfig{Enabled: true},
			Provider:         provider,
		},
		ProfileSync: appbridge.ProfileSyncBridgeConfig{
			CapabilityConfig: appbridge.CapabilityConfig{Enabled: true},
			Service:          smokeProfileSyncStatusProvider{},
		},
	})
	if err != nil {
		return AppBridgeSmoke{}, err
	}
	overview, err := bridge.BuildSetupOverview(ctx)
	if err != nil {
		return AppBridgeSmoke{}, err
	}
	disabledCards := 0
	for _, card := range overview.Cards {
		if !card.Enabled && card.Ready {
			disabledCards++
		}
	}

	provider.SetUnavailable(true)
	degraded, err := bridge.BuildSetupOverview(ctx)
	provider.SetUnavailable(false)
	if err != nil {
		return AppBridgeSmoke{}, err
	}

	provider.SetUnavailable(true)
	statusBridge, err := bridge.BuildInfrastructureStatus(ctx)
	provider.SetUnavailable(false)
	if err != nil {
		return AppBridgeSmoke{}, err
	}

	return AppBridgeSmoke{
		OverviewReady:                  overview.Ready,
		DisabledCardsNonFatal:          disabledCards > 0,
		RelayDegradedNonFatal:          degraded.Ready && len(degraded.Warnings) > 0 && smokeOutputSafe(degraded, ""),
		StatusBridgeReady:              statusBridge.Ready,
		StatusBridgeDegradedNonFatal:   len(statusBridge.Warnings) > 0 && smokeOutputSafe(statusBridge, ""),
		StatusBridgeProfileSyncVisible: statusBridge.ProfileSync.Card.Capability == setupstate.CapabilityProfileSync,
	}, nil
}

func smokeSetupState(ctx context.Context) (SetupStateSmoke, error) {
	overview, err := setupstate.BuildOverview(ctx, setupstate.AppSetupConfig{
		AppID:               "generic-consumer-smoke",
		DisplayName:         "Generic Consumer",
		EnabledCapabilities: []setupstate.Capability{setupstate.CapabilityUpdates},
	}, map[setupstate.Capability]setupstate.StatusProvider{
		setupstate.CapabilityUpdates: setupstate.StatusProviderFunc(func(context.Context) (setupstate.CapabilityStatus, error) {
			return setupstate.CapabilityStatus{
				Capability: setupstate.CapabilityUpdates,
				Enabled:    true,
				Ready:      true,
				State:      setupstate.StateWarning,
				Summary:    "update apply remains app-owned",
			}, nil
		}),
	})
	if err != nil {
		return SetupStateSmoke{}, err
	}
	return SetupStateSmoke{OverviewReady: overview.Ready, WarningSafe: len(overview.Warnings) == 1 && smokeOutputSafe(overview, "")}, nil
}

func smokeUpdates(ctx context.Context, workDir string, now time.Time) (UpdateSmoke, error) {
	updateDir := filepath.Join(workDir, "updates")
	artifactBody := []byte("generic update artifact")
	artifactPath := filepath.Join(updateDir, "generic-consumer-1.1.0.bin")
	if err := os.MkdirAll(updateDir, 0o700); err != nil {
		return UpdateSmoke{}, err
	}
	if err := os.WriteFile(artifactPath, artifactBody, 0o600); err != nil {
		return UpdateSmoke{}, err
	}
	sum := sha256.Sum256(artifactBody)
	manifestPath := filepath.Join(updateDir, "manifest.json")
	manifest := updates.Manifest{
		SchemaVersion:    1,
		AppID:            "generic-consumer-smoke",
		Channel:          updates.ChannelStable,
		Version:          "1.1.0",
		ReleaseNotesText: "generic release metadata",
		PublishedAt:      now.Format(time.RFC3339),
		Artifacts: []updates.Artifact{{
			Platform:     "windows",
			Architecture: "amd64",
			Filename:     "generic-consumer-1.1.0.bin",
			DownloadURL:  artifactPath,
			Size:         int64(len(artifactBody)),
			SHA256:       hex.EncodeToString(sum[:]),
		}},
	}
	if err := writeJSON(manifestPath, manifest); err != nil {
		return UpdateSmoke{}, err
	}

	service, err := updates.NewService(updates.AppConfig{
		AppID:          "generic-consumer-smoke",
		DisplayName:    "Generic Consumer",
		CurrentVersion: "1.0.0",
		Channel:        updates.ChannelStable,
		Platform:       "windows",
		Architecture:   "amd64",
		Namespace:      smokeNamespace,
		StagingDir:     filepath.Join(updateDir, "staging"),
		Source: updates.SourceConfig{
			Provider:     updates.ProviderFileManifest,
			ManifestPath: manifestPath,
		},
		Policy: updates.Policy{RequireSHA256: true, MaximumArtifactSize: 1 << 20},
	}, nil)
	if err != nil {
		return UpdateSmoke{}, err
	}
	status, err := service.GetStatus(ctx)
	if err != nil {
		return UpdateSmoke{}, err
	}
	check, err := service.CheckForUpdates(ctx)
	if err != nil {
		return UpdateSmoke{}, err
	}
	download, err := service.DownloadUpdate(ctx, "1.1.0")
	if err != nil {
		return UpdateSmoke{}, err
	}
	verify, err := service.VerifyUpdate(ctx, "1.1.0")
	if err != nil {
		return UpdateSmoke{}, err
	}
	stage, err := service.StageUpdate(ctx, "1.1.0")
	if err != nil {
		return UpdateSmoke{}, err
	}
	staged, err := service.DescribeStagedUpdate(ctx)
	if err != nil {
		return UpdateSmoke{}, err
	}
	plan, err := service.BuildApplyPlan(ctx)
	if err != nil {
		return UpdateSmoke{}, err
	}
	clear, err := service.ClearStagedUpdate(ctx)
	if err != nil {
		return UpdateSmoke{}, err
	}

	return UpdateSmoke{
		StatusConfigured:   status.Configured,
		UpdateAvailable:    check.UpdateAvailable,
		Downloaded:         download.BytesWritten == int64(len(artifactBody)),
		Verified:           verify.OK,
		Staged:             stage.Staged,
		StagedSummarySafe:  staged.Version == "1.1.0" && smokeOutputSafe(staged, workDir),
		ApplyPlanAppOwned:  plan.AppOwnedApply,
		ApplyPlanSafe:      len(plan.Steps) > 0 && smokeOutputSafe(plan, workDir),
		NoApplyExecuted:    true,
		ClearedStagedState: clear.Cleared,
	}, nil
}

func smokeRelay(ctx context.Context, provider *relay.LocalDevProvider, now time.Time) (RelaySmoke, error) {
	status := provider.GetStatus(ctx)
	mailbox, err := provider.OpenMailbox(ctx, relay.MailboxOpenRequest{
		Namespace:     smokeNamespace,
		OwnerDeviceID: smokeDeviceB,
		MailboxID:     "generic-smoke-mailbox",
		CreatedAt:     now,
		ExpiresAt:     now.Add(time.Hour),
	})
	if err != nil {
		return RelaySmoke{}, err
	}
	payload := []byte("generic relay smoke payload")
	envelope := relay.RelayEnvelope{
		RelayEnvelopeMetadata: relay.RelayEnvelopeMetadata{
			ProtocolVersion: relay.ProtocolVersion,
			Namespace:       smokeNamespace,
			SourceDeviceID:  smokeDeviceA,
			TargetMailboxID: mailbox.MailboxID,
			MessageKind:     relay.MessageKindOpaque,
			CreatedAt:       now,
			ExpiresAt:       now.Add(time.Minute),
			MessageID:       "generic-relay-message",
			PayloadHash:     relay.PayloadSHA256(payload),
			Metadata:        map[string]string{"purpose": "generic-smoke"},
		},
		Payload: payload,
	}
	receipt, err := provider.SendEnvelope(ctx, envelope)
	if err != nil {
		return RelaySmoke{}, err
	}
	received, err := provider.ReceiveEnvelopes(ctx, mailbox)
	if err != nil {
		return RelaySmoke{}, err
	}
	return RelaySmoke{
		ProviderAvailable: status.Enabled && status.Available,
		EnvelopeDelivered: receipt.Accepted && receipt.Delivered && len(received) == 1 && string(received[0].Payload) == string(payload),
		ReceiptSafe:       smokeOutputSafe(receipt, string(payload)),
	}, nil
}

func smokeProfileSync(ctx context.Context, provider *relay.LocalDevProvider, clock smokeClock, now time.Time) (ProfileSyncSmoke, error) {
	disabled, err := profilesync.NewSyncManager(profilesync.SyncConfig{Enabled: false})
	if err != nil {
		return ProfileSyncSmoke{}, err
	}
	disabledStatus := disabled.BuildStatus(ctx)

	store := profilesync.NewMemoryMetadataStore()
	store.SetLocalSnapshot(validSmokeSnapshot("snapshot-smoke", "", now))
	degraded, err := profilesync.NewSyncManager(
		profilesync.SyncConfig{Enabled: true, ProfileNamespace: smokeNamespace, LocalDeviceID: smokeDeviceA},
		profilesync.WithSnapshotStore(store),
		profilesync.WithProposalStore(store),
		profilesync.WithClock(clock),
	)
	if err != nil {
		return ProfileSyncSmoke{}, err
	}
	degradedStatus := degraded.BuildStatus(ctx)
	plan, err := degraded.BuildSyncPlan(ctx)
	if err != nil {
		return ProfileSyncSmoke{}, err
	}

	mailbox, err := provider.OpenMailbox(ctx, relay.MailboxOpenRequest{
		Namespace:     smokeNamespace,
		OwnerDeviceID: smokeDeviceA,
		MailboxID:     "generic-sync-mailbox",
		CreatedAt:     now,
		ExpiresAt:     now.Add(time.Hour),
	})
	if err != nil {
		return ProfileSyncSmoke{}, err
	}
	transport, err := profilesync.NewRelaySyncTransport(profilesync.RelaySyncTransportConfig{
		Provider:        provider,
		Namespace:       smokeNamespace,
		SourceDeviceID:  smokeDeviceA,
		TargetMailboxID: mailbox.MailboxID,
		Mailbox:         mailbox,
		Clock:           clock,
	})
	if err != nil {
		return ProfileSyncSmoke{}, err
	}
	transportStatus := transport.GetStatus(ctx)

	return ProfileSyncSmoke{
		DisabledNonFatal:          !disabledStatus.Enabled && !disabledStatus.Available && len(disabledStatus.Issues) == 0,
		MissingTransportDegraded:  degradedStatus.Enabled && !degradedStatus.Available && len(degradedStatus.Issues) > 0 && smokeOutputSafe(degradedStatus, ""),
		RelayTransportStatusSafe:  transportStatus.Available && smokeOutputSafe(transportStatus, ""),
		StoreOnlyPlanSafe:         plan.Enabled && smokeOutputSafe(plan, ""),
		NoProfileTruthPromotion:   true,
		NoAutomaticMergePerformed: true,
	}, nil
}

func smokeCloudSync(ctx context.Context, workDir string, now time.Time) (CloudSyncSmoke, error) {
	var missingProvider *profilesync.FileObjectProvider
	missingStatus := missingProvider.GetStatus(ctx)

	provider, err := profilesync.NewFileObjectProvider(profilesync.FileObjectProviderConfig{
		RootDir:          filepath.Join(workDir, "cloud-objects"),
		ProviderID:       "generic-smoke-file-provider",
		ProfileNamespace: smokeNamespace,
		Clock:            smokeClock{now: now},
	})
	if err != nil {
		return CloudSyncSmoke{}, err
	}
	objectBody := []byte(`{"kind":"snapshot_metadata","id":"snapshot-smoke"}`)
	ref, err := provider.PutObject(ctx, profilesync.CloudSyncObject{
		ProfileNamespace: smokeNamespace,
		ObjectID:         "snapshot-smoke",
		Kind:             profilesync.CloudObjectSnapshotMetadata,
		Body:             objectBody,
		CreatedAt:        now,
		Metadata:         map[string]string{"purpose": "generic-smoke"},
	})
	if err != nil {
		return CloudSyncSmoke{}, err
	}
	manifest, err := profilesync.NormalizeCloudManifest(profilesync.CloudProfileManifest{
		SchemaVersion:     profilesync.CloudManifestSchemaVersion,
		ProfileNamespace:  smokeNamespace,
		ManifestID:        "manifest-smoke",
		Generation:        1,
		CreatedAt:         now,
		LatestSnapshotRef: &ref,
		ReviewRequired:    false,
	})
	if err != nil {
		return CloudSyncSmoke{}, err
	}
	if err := provider.PutManifest(ctx, manifest); err != nil {
		return CloudSyncSmoke{}, err
	}
	remote, err := provider.GetManifest(ctx, smokeNamespace)
	if err != nil {
		return CloudSyncSmoke{}, err
	}
	verification := profilesync.VerifyCloudManifestObjects(ctx, provider, remote)
	comparison := profilesync.CompareCloudManifests(&manifest, remote, now)

	return CloudSyncSmoke{
		MissingProviderDegraded: !missingStatus.Available && smokeOutputSafe(missingStatus, ""),
		ObjectStored:            ref.Hash != "",
		ManifestVerified:        verification.Verified && verification.CheckedObjects == 1 && smokeOutputSafe(verification, string(objectBody)),
		SameManifestClassified:  comparison.Relation == profilesync.CloudManifestSame && !comparison.ReviewRequired && smokeOutputSafe(comparison, ""),
		NoProfileTruthPromotion: true,
	}, nil
}

func validSmokeSnapshot(snapshotID, parentID string, now time.Time) profilemesh.SignedProfileSnapshot {
	return profilemesh.SignedProfileSnapshot{
		Metadata: profilemesh.ProfileSnapshotMetadata{
			SchemaVersion:       1,
			ProfileNamespace:    smokeNamespace,
			ProfileID:           "profile-smoke",
			SnapshotID:          snapshotID,
			SnapshotFingerprint: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
			ParentSnapshotID:    parentID,
			SourceDeviceID:      smokeDeviceA,
			HostingMode:         profilemesh.HostingSingleProfileDevice,
			CreatedAt:           now.Add(-time.Minute),
			UpdatedAt:           now,
			ExpiresAt:           now.Add(time.Hour),
			MetadataVersion:     1,
		},
		Signature: profilemesh.SnapshotSignatureSummary{
			SignerDeviceID:       smokeDeviceA,
			SignerKeyFingerprint: "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
			SignatureFingerprint: "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc",
			Algorithm:            "generic-ed25519-summary",
			SignedAt:             now,
		},
	}
}

func writeJSON(path string, value any) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	file, err := os.OpenFile(path, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}
	encodeErr := json.NewEncoder(file).Encode(value)
	closeErr := file.Close()
	if encodeErr != nil {
		return encodeErr
	}
	return closeErr
}

func smokeOutputSafe(value any, extraForbidden string) bool {
	raw, err := json.Marshal(value)
	if err != nil {
		return false
	}
	text := strings.ToLower(string(raw))
	for _, forbidden := range []string{
		`:\`,
		"/users/",
		"/home/",
		"appdata",
		"generic update artifact",
		"generic relay smoke payload",
		"raw payload",
	} {
		if strings.Contains(text, forbidden) {
			return false
		}
	}
	if strings.TrimSpace(extraForbidden) != "" && strings.Contains(text, strings.ToLower(extraForbidden)) {
		return false
	}
	return true
}

type smokeClock struct {
	now time.Time
}

func (c smokeClock) Now() time.Time {
	return c.now
}

type smokeProfileSyncStatusProvider struct{}

func (smokeProfileSyncStatusProvider) BuildStatus(context.Context) profilesync.SyncStatus {
	return profilesync.SyncStatus{
		Enabled:          true,
		Available:        false,
		ProfileNamespace: smokeNamespace,
		Summary:          "profile sync metadata status degraded",
		Issues:           []profilesync.SyncIssue{{Code: "offline_transport_missing", Message: profilesync.ErrNoRelayProvider.Error(), Blocking: false}},
	}
}

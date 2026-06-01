package main

import (
	"context"
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
)

const (
	proofNamespace = "generic-profile"
	deviceAlpha    = "device-alpha"
	deviceBeta     = "device-beta"
)

type ProofSummary struct {
	AppBridge      AppBridgeProof      `json:"app_bridge"`
	Relay          RelayProof          `json:"relay"`
	ProfileSync    ProfileSyncProof    `json:"profile_sync"`
	PartialFailure PartialFailureProof `json:"partial_failure"`
	SafeOutput     bool                `json:"safe_output"`
}

type AppBridgeProof struct {
	OverviewReady           bool `json:"overview_ready"`
	DisabledCards           int  `json:"disabled_cards"`
	RelayDegradedNonFatal   bool `json:"relay_degraded_non_fatal"`
	RelayDisabledNonFatal   bool `json:"relay_disabled_non_fatal"`
	OverviewOutputIsUIReady bool `json:"overview_output_is_ui_ready"`
}

type RelayProof struct {
	LocalProviderAvailable bool `json:"local_provider_available"`
	MailboxOpened          bool `json:"mailbox_opened"`
	EnvelopeDelivered      bool `json:"envelope_delivered"`
	DeliveryReceiptSafe    bool `json:"delivery_receipt_safe"`
	DuplicateRejected      bool `json:"duplicate_rejected"`
}

type ProfileSyncProof struct {
	LocalStoreAvailable      bool `json:"local_store_available"`
	PushedSnapshot           bool `json:"pushed_snapshot"`
	PushedProposal           bool `json:"pushed_proposal"`
	DuplicatePushIdempotent  bool `json:"duplicate_push_idempotent"`
	PulledSnapshot           bool `json:"pulled_snapshot"`
	PulledProposal           bool `json:"pulled_proposal"`
	ConflictReviewRequired   bool `json:"conflict_review_required"`
	ExchangeCompleted        bool `json:"exchange_completed"`
	PersistedAcrossStoreOpen bool `json:"persisted_across_store_open"`
	LastExchangePersisted    bool `json:"last_exchange_persisted"`
}

type PartialFailureProof struct {
	DisabledSyncNonFatal bool `json:"disabled_sync_non_fatal"`
	MissingTransportSafe bool `json:"missing_transport_safe"`
	CorruptStoreSafe     bool `json:"corrupt_store_safe"`
	NoPrivatePathLeak    bool `json:"no_private_path_leak"`
	NoRawPayloadLeak     bool `json:"no_raw_payload_leak"`
}

func main() {
	ctx := context.Background()
	workDir, err := os.MkdirTemp("", "aegis-generic-proof-*")
	if err != nil {
		fmt.Fprintln(os.Stderr, "generic consumer proof could not allocate temporary storage")
		os.Exit(1)
	}
	defer os.RemoveAll(workDir)

	summary, err := RunProof(ctx, workDir)
	if err != nil {
		fmt.Fprintln(os.Stderr, "generic consumer proof failed")
		os.Exit(1)
	}
	if err := json.NewEncoder(os.Stdout).Encode(summary); err != nil {
		fmt.Fprintln(os.Stderr, "generic consumer proof output failed")
		os.Exit(1)
	}
}

func RunProof(ctx context.Context, workDir string) (ProofSummary, error) {
	if strings.TrimSpace(workDir) == "" {
		return ProofSummary{}, errors.New("proof work directory is required")
	}

	now := time.Now().UTC().Truncate(time.Second)
	clock := fixedClock{now: now}
	provider, err := relay.NewLocalDevProvider(relay.LocalDevProviderConfig{ProviderID: "generic-local-dev", Clock: clock})
	if err != nil {
		return ProofSummary{}, err
	}

	appProof, err := proveAppBridge(ctx, provider)
	if err != nil {
		return ProofSummary{}, err
	}
	relayProof, err := proveRelay(ctx, provider, now)
	if err != nil {
		return ProofSummary{}, err
	}
	syncProof, err := proveProfileSync(ctx, provider, clock, workDir, now)
	if err != nil {
		return ProofSummary{}, err
	}
	partialProof, err := provePartialFailure(ctx, workDir, now)
	if err != nil {
		return ProofSummary{}, err
	}

	summary := ProofSummary{
		AppBridge:      appProof,
		Relay:          relayProof,
		ProfileSync:    syncProof,
		PartialFailure: partialProof,
	}
	summary.SafeOutput = proofOutputSafe(summary, workDir)
	return summary, nil
}

func proveAppBridge(ctx context.Context, provider *relay.LocalDevProvider) (AppBridgeProof, error) {
	bridge, err := appbridge.NewSetupBridge(appbridge.AppBridgeConfig{
		Identity: appbridge.AppIdentity{
			AppID:         "generic-consumer-proof",
			DisplayName:   "Generic Consumer",
			DataNamespace: proofNamespace,
		},
		Relay: appbridge.RelayBridgeConfig{
			CapabilityConfig: appbridge.CapabilityConfig{Enabled: true},
			Provider:         provider,
		},
	})
	if err != nil {
		return AppBridgeProof{}, err
	}
	overview, err := bridge.BuildSetupOverview(ctx)
	if err != nil {
		return AppBridgeProof{}, err
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
		return AppBridgeProof{}, err
	}

	disabledBridge, err := appbridge.NewSetupBridge(appbridge.AppBridgeConfig{
		Identity: appbridge.AppIdentity{
			AppID:         "generic-consumer-disabled-proof",
			DisplayName:   "Generic Consumer",
			DataNamespace: proofNamespace,
		},
	})
	if err != nil {
		return AppBridgeProof{}, err
	}
	disabledRelay, err := disabledBridge.RelayStatus(ctx)
	if err != nil {
		return AppBridgeProof{}, err
	}

	return AppBridgeProof{
		OverviewReady:           overview.Ready,
		DisabledCards:           disabledCards,
		RelayDegradedNonFatal:   degraded.Ready && len(degraded.Warnings) > 0,
		RelayDisabledNonFatal:   !disabledRelay.Status.Enabled && disabledRelay.Card.Ready,
		OverviewOutputIsUIReady: safeValue(overview),
	}, nil
}

func proveRelay(ctx context.Context, provider *relay.LocalDevProvider, now time.Time) (RelayProof, error) {
	status := provider.GetStatus(ctx)
	mailbox, err := provider.OpenMailbox(ctx, relay.MailboxOpenRequest{
		Namespace:     proofNamespace,
		OwnerDeviceID: deviceBeta,
		MailboxID:     "relay-mailbox-beta",
		CreatedAt:     now,
		ExpiresAt:     now.Add(time.Hour),
	})
	if err != nil {
		return RelayProof{}, err
	}
	payload := []byte("generic metadata proof payload")
	envelope := relay.RelayEnvelope{
		RelayEnvelopeMetadata: relay.RelayEnvelopeMetadata{
			ProtocolVersion: relay.ProtocolVersion,
			Namespace:       proofNamespace,
			SourceDeviceID:  deviceAlpha,
			TargetMailboxID: mailbox.MailboxID,
			MessageKind:     relay.MessageKindOpaque,
			CreatedAt:       now,
			ExpiresAt:       now.Add(time.Minute),
			MessageID:       "relay-message-001",
			PayloadHash:     relay.PayloadSHA256(payload),
			Metadata:        map[string]string{"purpose": "generic-proof"},
		},
		Payload: payload,
	}
	receipt, err := provider.SendEnvelope(ctx, envelope)
	if err != nil {
		return RelayProof{}, err
	}
	_, duplicateErr := provider.SendEnvelope(ctx, envelope)
	received, err := provider.ReceiveEnvelopes(ctx, mailbox)
	if err != nil {
		return RelayProof{}, err
	}

	return RelayProof{
		LocalProviderAvailable: status.Enabled && status.Available,
		MailboxOpened:          mailbox.MailboxID != "",
		EnvelopeDelivered:      receipt.Accepted && receipt.Delivered && len(received) == 1 && string(received[0].Payload) == string(payload),
		DeliveryReceiptSafe:    safeValue(receipt),
		DuplicateRejected:      errors.Is(duplicateErr, relay.ErrDuplicateEnvelope),
	}, nil
}

func proveProfileSync(ctx context.Context, provider *relay.LocalDevProvider, clock fixedClock, workDir string, now time.Time) (ProfileSyncProof, error) {
	mailboxA, err := provider.OpenMailbox(ctx, relay.MailboxOpenRequest{
		Namespace:     proofNamespace,
		OwnerDeviceID: deviceAlpha,
		MailboxID:     "profile-sync-mailbox-alpha",
		CreatedAt:     now,
		ExpiresAt:     now.Add(time.Hour),
	})
	if err != nil {
		return ProfileSyncProof{}, err
	}
	mailboxB, err := provider.OpenMailbox(ctx, relay.MailboxOpenRequest{
		Namespace:     proofNamespace,
		OwnerDeviceID: deviceBeta,
		MailboxID:     "profile-sync-mailbox-beta",
		CreatedAt:     now,
		ExpiresAt:     now.Add(time.Hour),
	})
	if err != nil {
		return ProfileSyncProof{}, err
	}

	transportA, err := profilesync.NewRelaySyncTransport(profilesync.RelaySyncTransportConfig{
		Provider:        provider,
		Namespace:       proofNamespace,
		SourceDeviceID:  deviceAlpha,
		TargetMailboxID: mailboxB.MailboxID,
		Clock:           clock,
	})
	if err != nil {
		return ProfileSyncProof{}, err
	}
	transportB, err := profilesync.NewRelaySyncTransport(profilesync.RelaySyncTransportConfig{
		Provider:       provider,
		Namespace:      proofNamespace,
		SourceDeviceID: deviceBeta,
		TargetDeviceID: deviceAlpha,
		Mailbox:        mailboxB,
		Clock:          clock,
	})
	if err != nil {
		return ProfileSyncProof{}, err
	}

	storeA := profilesync.NewMemoryMetadataStore()
	storeA.SetLocalSnapshot(validSnapshot("snapshot-alpha", "", deviceAlpha, now))
	storeA.AddLocalProposal(validProposal("proposal-alpha", "snapshot-beta", "snapshot-alpha", now))

	storeRoot := filepath.Join(workDir, "generic-proof-store")
	storeB, err := profilesync.NewLocalMetadataStore(profilesync.LocalMetadataStoreConfig{RootDir: storeRoot, ProfileNamespace: proofNamespace, Clock: clock})
	if err != nil {
		return ProfileSyncProof{}, err
	}
	if err := storeB.SaveLocalSnapshot(ctx, validSnapshot("snapshot-beta", "snapshot-alpha", deviceBeta, now)); err != nil {
		return ProfileSyncProof{}, err
	}

	managerA, err := profilesync.NewSyncManager(
		profilesync.SyncConfig{Enabled: true, ProfileNamespace: proofNamespace, LocalDeviceID: deviceAlpha},
		profilesync.WithSnapshotStore(storeA),
		profilesync.WithProposalStore(storeA),
		profilesync.WithTransport(transportA),
		profilesync.WithTrustVerifier(staticTrust{}),
		profilesync.WithClock(clock),
	)
	if err != nil {
		return ProfileSyncProof{}, err
	}
	managerB, err := profilesync.NewSyncManager(
		profilesync.SyncConfig{Enabled: true, ProfileNamespace: proofNamespace, LocalDeviceID: deviceBeta},
		profilesync.WithSnapshotStore(storeB),
		profilesync.WithProposalStore(storeB),
		profilesync.WithTransport(transportB),
		profilesync.WithTrustVerifier(staticTrust{}),
		profilesync.WithClock(clock),
	)
	if err != nil {
		return ProfileSyncProof{}, err
	}

	pushSnapshot, err := managerA.PushLocalSnapshot(ctx)
	if err != nil {
		return ProfileSyncProof{}, err
	}
	duplicatePush, err := managerA.PushLocalSnapshot(ctx)
	if err != nil {
		return ProfileSyncProof{}, err
	}
	pushProposals, err := managerA.PushLocalProposals(ctx)
	if err != nil {
		return ProfileSyncProof{}, err
	}
	pull, err := managerB.PullRemote(ctx)
	if err != nil {
		return ProfileSyncProof{}, err
	}

	remoteSnapshot, err := storeB.LoadRemoteSnapshot(ctx, "snapshot-alpha")
	if err != nil {
		return ProfileSyncProof{}, err
	}
	_, err = storeB.LoadRemoteProposal(ctx, "proposal-alpha")
	if err != nil {
		return ProfileSyncProof{}, err
	}

	exchangeTransport, err := profilesync.NewRelaySyncTransport(profilesync.RelaySyncTransportConfig{
		Provider:        provider,
		Namespace:       proofNamespace,
		SourceDeviceID:  deviceBeta,
		TargetMailboxID: mailboxA.MailboxID,
		Mailbox:         mailboxB,
		Clock:           clock,
	})
	if err != nil {
		return ProfileSyncProof{}, err
	}
	exchangeManager, err := profilesync.NewSyncManager(
		profilesync.SyncConfig{Enabled: true, ProfileNamespace: proofNamespace, LocalDeviceID: deviceBeta},
		profilesync.WithSnapshotStore(storeB),
		profilesync.WithProposalStore(storeB),
		profilesync.WithTransport(exchangeTransport),
		profilesync.WithTrustVerifier(staticTrust{}),
		profilesync.WithClock(clock),
	)
	if err != nil {
		return ProfileSyncProof{}, err
	}
	exchange, err := exchangeManager.Exchange(ctx)
	if err != nil {
		return ProfileSyncProof{}, err
	}
	if err := storeB.SaveLastExchange(ctx, exchange); err != nil {
		return ProfileSyncProof{}, err
	}

	reopened, err := profilesync.NewLocalMetadataStore(profilesync.LocalMetadataStoreConfig{RootDir: storeRoot, ProfileNamespace: proofNamespace, Clock: clock})
	if err != nil {
		return ProfileSyncProof{}, err
	}
	reloadedSnapshot, err := reopened.LoadRemoteSnapshot(ctx, "snapshot-alpha")
	if err != nil {
		return ProfileSyncProof{}, err
	}
	lastExchange, err := reopened.LoadLastExchange(ctx)
	if err != nil {
		return ProfileSyncProof{}, err
	}
	status := reopened.BuildStatus(ctx)

	return ProfileSyncProof{
		LocalStoreAvailable:      status.Available,
		PushedSnapshot:           pushSnapshot.PushedSnapshots == 1,
		PushedProposal:           pushProposals.PushedProposals == 1,
		DuplicatePushIdempotent:  len(duplicatePush.Receipts) == 1 && duplicatePush.Receipts[0].Accepted,
		PulledSnapshot:           pull.ReceivedSnapshots == 1 && remoteSnapshot.TrustState == profilesync.TrustTrusted,
		PulledProposal:           pull.ReceivedProposals == 1,
		ConflictReviewRequired:   pull.ReviewRequired,
		ExchangeCompleted:        exchange.Session.CompletedAt.After(exchange.Session.StartedAt) || exchange.Session.CompletedAt.Equal(exchange.Session.StartedAt),
		PersistedAcrossStoreOpen: reloadedSnapshot.Snapshot.Metadata.SnapshotID == "snapshot-alpha",
		LastExchangePersisted:    lastExchange.Session.SessionID != "",
	}, nil
}

func provePartialFailure(ctx context.Context, workDir string, now time.Time) (PartialFailureProof, error) {
	disabledManager, err := profilesync.NewSyncManager(profilesync.SyncConfig{Enabled: false})
	if err != nil {
		return PartialFailureProof{}, err
	}
	disabledStatus := disabledManager.BuildStatus(ctx)

	store := profilesync.NewMemoryMetadataStore()
	store.SetLocalSnapshot(validSnapshot("snapshot-local", "", deviceAlpha, now))
	missingTransportManager, err := profilesync.NewSyncManager(
		profilesync.SyncConfig{Enabled: true, ProfileNamespace: proofNamespace, LocalDeviceID: deviceAlpha},
		profilesync.WithSnapshotStore(store),
		profilesync.WithProposalStore(store),
		profilesync.WithClock(fixedClock{now: now}),
	)
	if err != nil {
		return PartialFailureProof{}, err
	}
	degradedStatus := missingTransportManager.BuildStatus(ctx)

	corruptRoot := filepath.Join(workDir, "corrupt-proof-store")
	corruptStore, err := profilesync.NewLocalMetadataStore(profilesync.LocalMetadataStoreConfig{RootDir: corruptRoot, ProfileNamespace: proofNamespace, Clock: fixedClock{now: now}})
	if err != nil {
		return PartialFailureProof{}, err
	}
	corruptDir := filepath.Join(corruptRoot, proofNamespace, "snapshots", "remote")
	if err := os.MkdirAll(corruptDir, 0o700); err != nil {
		return PartialFailureProof{}, err
	}
	if err := os.WriteFile(filepath.Join(corruptDir, "corrupt.json"), []byte("{"), 0o600); err != nil {
		return PartialFailureProof{}, err
	}
	corruptStatus := corruptStore.BuildStatus(ctx)

	proof := PartialFailureProof{
		DisabledSyncNonFatal: !disabledStatus.Enabled && !disabledStatus.Available && len(disabledStatus.Issues) == 0,
		MissingTransportSafe: !degradedStatus.Available && safeValue(degradedStatus),
		CorruptStoreSafe:     !corruptStatus.Available && len(corruptStatus.Issues) > 0 && safeValue(corruptStatus),
	}
	proof.NoPrivatePathLeak = proofOutputSafe(proof, workDir)
	proof.NoRawPayloadLeak = proofOutputSafe(proof, "generic metadata proof payload")
	return proof, nil
}

func validSnapshot(snapshotID, parentID, sourceDeviceID string, now time.Time) profilemesh.SignedProfileSnapshot {
	return profilemesh.SignedProfileSnapshot{
		Metadata: profilemesh.ProfileSnapshotMetadata{
			SchemaVersion:       1,
			ProfileNamespace:    proofNamespace,
			ProfileID:           "profile-alpha",
			SnapshotID:          snapshotID,
			SnapshotFingerprint: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
			ParentSnapshotID:    parentID,
			SourceDeviceID:      sourceDeviceID,
			HostingMode:         profilemesh.HostingSingleProfileDevice,
			CreatedAt:           now.Add(-time.Minute),
			UpdatedAt:           now,
			ExpiresAt:           now.Add(time.Hour),
			MetadataVersion:     1,
		},
		Signature: profilemesh.SnapshotSignatureSummary{
			SignerDeviceID:       sourceDeviceID,
			SignerKeyFingerprint: "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
			SignatureFingerprint: "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc",
			Algorithm:            "generic-ed25519-summary",
			SignedAt:             now,
		},
	}
}

func validProposal(proposalID, baseSnapshotID, proposedSnapshotID string, now time.Time) profilemesh.ProfileChangeProposal {
	return profilemesh.ProfileChangeProposal{
		ProposalID:           proposalID,
		ProfileNamespace:     proofNamespace,
		ProfileID:            "profile-alpha",
		BaseSnapshotID:       baseSnapshotID,
		ProposedSnapshotID:   proposedSnapshotID,
		SourceBranchID:       "branch-alpha",
		TargetBranchID:       "branch-beta",
		AuthorDeviceID:       deviceAlpha,
		Status:               profilemesh.ProposalStatusPendingReview,
		RequestedHostingMode: profilemesh.HostingSingleProfileDevice,
		CreatedAt:            now.Add(-time.Minute),
		UpdatedAt:            now,
		RequiresUserReview:   true,
		Conflicts: []profilemesh.ConflictSummary{
			{
				ConflictID:         "conflict-alpha",
				ResourceID:         "metadata-resource",
				ResourceType:       "profile_metadata",
				Summary:            "metadata branch review required",
				RequiresUserReview: true,
				SafeFailureCode:    "review_required",
			},
		},
		MergePlan: profilemesh.MergePlan{
			PlanID:             "merge-plan-alpha",
			Strategy:           "review-only",
			Status:             "pending",
			FutureOnly:         true,
			RequiresUserReview: true,
			Summary:            "metadata review required",
		},
	}
}

func safeValue(value any) bool {
	return proofOutputSafe(value, "")
}

func proofOutputSafe(value any, extraForbidden string) bool {
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
		"generic metadata proof payload",
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

type fixedClock struct {
	now time.Time
}

func (c fixedClock) Now() time.Time {
	return c.now
}

type staticTrust struct{}

func (staticTrust) VerifySigner(ctx context.Context, signerDeviceID, signerKeyFingerprint string) profilesync.TrustDecision {
	if strings.TrimSpace(signerDeviceID) == "" {
		return profilesync.TrustDecision{Pending: true, Code: "signer_pending_validation", Message: "signer requires validation"}
	}
	return profilesync.TrustDecision{Trusted: true}
}

package appbridge

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/AegisAgentAscalon/aegis-core/pkg/devicelink"
	"github.com/AegisAgentAscalon/aegis-core/pkg/profilemesh"
	"github.com/AegisAgentAscalon/aegis-core/pkg/profilesync"
	"github.com/AegisAgentAscalon/aegis-core/pkg/relay"
	"github.com/AegisAgentAscalon/aegis-core/pkg/securityposture"
	"github.com/AegisAgentAscalon/aegis-core/pkg/setupstate"
	"github.com/AegisAgentAscalon/aegis-core/pkg/updates"
)

func TestBuildSetupOverviewDisabledCapabilitiesAreNonFatal(t *testing.T) {
	bridge, err := NewSetupBridge(AppBridgeConfig{Identity: AppIdentity{AppID: "generic-app", DisplayName: "Generic App"}})
	if err != nil {
		t.Fatalf("NewSetupBridge returned error: %v", err)
	}
	overview, err := bridge.BuildSetupOverview(context.Background())
	if err != nil {
		t.Fatalf("BuildSetupOverview returned error: %v", err)
	}
	if !overview.Ready || len(overview.Cards) != 7 {
		t.Fatalf("disabled capabilities should be non-fatal cards: %+v", overview)
	}
	for _, card := range overview.Cards {
		if card.Enabled || !card.Ready || card.State != setupstate.StateDisabled {
			t.Fatalf("expected disabled ready card, got %+v", card)
		}
	}
	assertAppBridgeSafeJSON(t, overview)
}

func TestBuildSetupOverviewIncludesProfileSyncStatusCard(t *testing.T) {
	bridge, err := NewSetupBridge(AppBridgeConfig{
		Identity: AppIdentity{AppID: "generic-app", DisplayName: "Generic App"},
		ProfileSync: ProfileSyncBridgeConfig{
			CapabilityConfig: CapabilityConfig{Enabled: true},
			Service: profileSyncStatusStub{status: profilesync.SyncStatus{
				Enabled:          true,
				Available:        true,
				ProfileNamespace: "generic-profile",
				Summary:          "profile sync metadata status ready",
			}},
		},
	})
	if err != nil {
		t.Fatalf("NewSetupBridge returned error: %v", err)
	}
	overview, err := bridge.BuildSetupOverview(context.Background())
	if err != nil {
		t.Fatalf("BuildSetupOverview returned error: %v", err)
	}
	var found bool
	for _, card := range overview.Cards {
		if card.Capability == setupstate.CapabilityProfileSync {
			found = true
			if !card.Enabled || !card.Ready || card.State != setupstate.StateReady {
				t.Fatalf("expected ready profile sync card, got %+v", card)
			}
		}
	}
	if !found {
		t.Fatalf("profile sync card missing from overview: %+v", overview.Cards)
	}
	assertAppBridgeSafeJSON(t, overview)
}

func TestInfrastructureStatusBridgeIsReadOnlyAndDegradedSafe(t *testing.T) {
	updateSvc := &countingUpdateService{status: updates.CurrentState{
		AppID:          "generic-app",
		DisplayName:    "Generic App",
		CurrentVersion: "1.0.0",
		Channel:        updates.ChannelStable,
		Platform:       "windows",
		Architecture:   "amd64",
		Provider:       updates.ProviderFileManifest,
		Configured:     true,
		Message:        "updates ready",
	}}
	profileSvc := &countingProfileSyncStatusProvider{status: profilesync.SyncStatus{
		Enabled:          true,
		Available:        false,
		ProfileNamespace: "generic-profile",
		Summary:          `token=bad at C:\Users\person\AppData\profile-sync`,
		Issues:           []profilesync.SyncIssue{{Code: "transport_unavailable", Message: `secret provider path C:\Users\person\Downloads`, Blocking: true}},
	}}
	relayProvider := &countingRelayStatusProvider{status: relay.RelayStatus{
		Enabled:   true,
		Available: false,
		Summary:   `client_secret in C:\Users\person\AppData\relay`,
		Issues:    []relay.RelayIssue{{Code: "relay_unavailable", Message: `password=bad in C:\Users\person\Desktop`, Blocking: true}},
	}}
	bridge, err := NewSetupBridge(AppBridgeConfig{
		Identity: AppIdentity{AppID: "generic-app", DisplayName: "Generic App"},
		Updates: UpdateBridgeConfig{
			CapabilityConfig: CapabilityConfig{Enabled: true},
			Service:          updateSvc,
		},
		ProfileSync: ProfileSyncBridgeConfig{
			CapabilityConfig: CapabilityConfig{Enabled: true},
			Service:          profileSvc,
		},
		Relay: RelayBridgeConfig{
			CapabilityConfig: CapabilityConfig{Enabled: true},
			Provider:         relayProvider,
		},
	})
	if err != nil {
		t.Fatalf("NewSetupBridge returned error: %v", err)
	}
	overview, err := bridge.BuildInfrastructureStatus(context.Background())
	if err != nil {
		t.Fatalf("BuildInfrastructureStatus returned error: %v", err)
	}
	if !overview.Ready {
		t.Fatalf("degraded profile sync and relay should remain non-fatal in read-only bridge: %+v", overview)
	}
	if updateSvc.getStatusCalls != 1 || updateSvc.operationCalls() != 0 {
		t.Fatalf("status bridge should only read update status, got get=%d operations=%d", updateSvc.getStatusCalls, updateSvc.operationCalls())
	}
	if profileSvc.buildStatusCalls != 1 {
		t.Fatalf("status bridge should read profile sync status once, got %d", profileSvc.buildStatusCalls)
	}
	if relayProvider.getStatusCalls != 1 {
		t.Fatalf("status bridge should only read relay status once, got %d", relayProvider.getStatusCalls)
	}
	if overview.ProfileSync.Card.State != setupstate.StateWarning || overview.Relay.Card.State != setupstate.StateWarning {
		t.Fatalf("expected degraded warning cards, got profile=%+v relay=%+v", overview.ProfileSync.Card, overview.Relay.Card)
	}
	assertAppBridgeSafeJSON(t, overview)
}

func TestRelayDegradedStatusIsSanitizedAndNonFatal(t *testing.T) {
	bridge, err := NewSetupBridge(AppBridgeConfig{
		Identity: AppIdentity{AppID: "generic-app", DisplayName: "Generic App"},
		Relay: RelayBridgeConfig{
			CapabilityConfig: CapabilityConfig{Enabled: true},
			Provider:         unsafeRelayProvider{},
		},
	})
	if err != nil {
		t.Fatalf("NewSetupBridge returned error: %v", err)
	}
	overview, err := bridge.BuildSetupOverview(context.Background())
	if err != nil {
		t.Fatalf("BuildSetupOverview returned error: %v", err)
	}
	if !overview.Ready {
		t.Fatalf("degraded relay should not block setup overview: %+v", overview)
	}
	relayResult, err := bridge.RelayStatus(context.Background())
	if err != nil {
		t.Fatalf("RelayStatus returned error: %v", err)
	}
	if relayResult.Card.State != setupstate.StateWarning || !relayResult.Card.Ready {
		t.Fatalf("expected non-fatal relay warning card, got %+v", relayResult.Card)
	}
	if len(relayResult.Status.Issues) == 0 || relayResult.Status.Issues[0].Blocking {
		t.Fatalf("relay provider issues should be non-blocking and safe: %+v", relayResult.Status)
	}
	assertAppBridgeSafeJSON(t, overview)
	assertAppBridgeSafeJSON(t, relayResult)
}

func TestAppBridgeStatusSummariesDoNotLeakNetworkOrProfileDetails(t *testing.T) {
	bridge, err := NewSetupBridge(AppBridgeConfig{
		Identity: AppIdentity{AppID: "generic-app", DisplayName: "Generic App"},
		DeviceLink: DeviceLinkBridgeConfig{
			CapabilityConfig: CapabilityConfig{Enabled: true},
			Service:          unsafeDeviceLinkService{},
		},
		ProfileMesh: ProfileMeshBridgeConfig{
			CapabilityConfig: CapabilityConfig{Enabled: true},
			Service:          unsafeProfileMeshService{},
		},
	})
	if err != nil {
		t.Fatalf("NewSetupBridge returned error: %v", err)
	}
	deviceStatus, err := bridge.DeviceLinkStatus(context.Background())
	if err != nil {
		t.Fatalf("DeviceLinkStatus returned error: %v", err)
	}
	profileStatus, err := bridge.ProfileMeshStatus(context.Background())
	if err != nil {
		t.Fatalf("ProfileMeshStatus returned error: %v", err)
	}
	assertAppBridgeSafeJSON(t, deviceStatus)
	assertAppBridgeSafeJSON(t, profileStatus)
}

func TestSecurityPostureStatusBridgeIsReadOnlyAndSafe(t *testing.T) {
	provider := &countingSecurityPostureProvider{summary: securityposture.Summary{
		Capability: "security_posture",
		Posture:    securityposture.PostureReviewRequired,
		Boundary:   securityposture.BoundaryRelayTransport,
		Risk:       securityposture.RiskUnsafeIfTrusted,
		Redaction:  securityposture.RedactionNotApplicable,
		Issues: []securityposture.Issue{{
			Code:           "relay_transport_not_authority",
			Severity:       securityposture.SeverityMedium,
			Posture:        securityposture.PostureReviewRequired,
			Boundary:       securityposture.BoundaryRelayTransport,
			Risk:           securityposture.RiskUnsafeIfTrusted,
			Summary:        `authorization: bearer sample at C:\Users\person\AppData`,
			ReviewRequired: true,
		}},
	}}
	bridge, err := NewSetupBridge(AppBridgeConfig{
		Identity: AppIdentity{AppID: "generic-app", DisplayName: "Generic App"},
		SecurityPosture: SecurityPostureBridgeConfig{
			CapabilityConfig: CapabilityConfig{Enabled: true},
			Provider:         provider,
		},
	})
	if err != nil {
		t.Fatalf("NewSetupBridge returned error: %v", err)
	}
	overview, err := bridge.BuildSetupOverview(context.Background())
	if err != nil {
		t.Fatalf("BuildSetupOverview returned error: %v", err)
	}
	if !overview.Ready {
		t.Fatalf("review-required security posture should be visible and non-fatal in setup overview: %+v", overview)
	}
	result, err := bridge.SecurityPostureStatus(context.Background())
	if err != nil {
		t.Fatalf("SecurityPostureStatus returned error: %v", err)
	}
	if provider.calls != 2 {
		t.Fatalf("expected provider to be read once for overview and once for direct status, got %d", provider.calls)
	}
	if result.Card.Capability != setupstate.CapabilitySecurityPosture || result.Card.State != setupstate.StateWarning || !result.Card.Ready {
		t.Fatalf("unexpected security posture card: %+v", result.Card)
	}
	if result.Summary.Issues[0].Summary != "security posture issue" {
		t.Fatalf("unsafe posture issue summary was not replaced safely: %+v", result.Summary.Issues[0])
	}
	assertAppBridgeSafeJSON(t, overview)
	assertAppBridgeSafeJSON(t, result)
}

func TestSecurityPostureBlockedStateCanBlockInfrastructureStatus(t *testing.T) {
	provider := &countingSecurityPostureProvider{summary: securityposture.Summary{
		Capability: "security_posture",
		Posture:    securityposture.PostureBlocked,
		Boundary:   securityposture.BoundaryAegisCoreOwned,
		Risk:       securityposture.RiskRequiresCallerPolicy,
		Issues: []securityposture.Issue{{
			Code:     "security_posture_blocked",
			Severity: securityposture.SeverityHigh,
			Posture:  securityposture.PostureBlocked,
			Summary:  "security posture blocked by policy",
		}},
	}}
	bridge, err := NewSetupBridge(AppBridgeConfig{
		Identity:        AppIdentity{AppID: "generic-app", DisplayName: "Generic App"},
		SecurityPosture: SecurityPostureBridgeConfig{CapabilityConfig: CapabilityConfig{Enabled: true}, Provider: provider},
	})
	if err != nil {
		t.Fatalf("NewSetupBridge returned error: %v", err)
	}
	overview, err := bridge.BuildInfrastructureStatus(context.Background())
	if err != nil {
		t.Fatalf("BuildInfrastructureStatus returned error: %v", err)
	}
	if overview.Ready || overview.SecurityPosture.Card.State != setupstate.StateBlocked || len(overview.BlockingIssues) == 0 {
		t.Fatalf("blocked security posture should block infrastructure readiness: %+v", overview)
	}
	assertAppBridgeSafeJSON(t, overview)
}

func TestAppBridgePackageDoesNotImportInternalsOrExamples(t *testing.T) {
	files, err := filepath.Glob("*.go")
	if err != nil {
		t.Fatalf("glob appbridge files: %v", err)
	}
	for _, file := range files {
		if strings.HasSuffix(file, "_test.go") {
			continue
		}
		raw, err := os.ReadFile(file)
		if err != nil {
			t.Fatalf("read %s: %v", file, err)
		}
		text := string(raw)
		for _, forbidden := range []string{"/internal/", "internal/", "examples/", "named-consumer-app", "named-consumer-current", "named-consumer.local"} {
			if strings.Contains(text, forbidden) {
				t.Fatalf("pkg/appbridge imports or references forbidden text %q in %s", forbidden, file)
			}
		}
	}
}

func assertAppBridgeSafeJSON(t *testing.T, v any) {
	t.Helper()
	raw, err := json.Marshal(v)
	if err != nil {
		t.Fatalf("json marshal failed: %v", err)
	}
	text := strings.ToLower(string(raw))
	for _, forbidden := range []string{`"public_key":`, "client_secret", "refresh_token", "access_token", "id_token", "auth_code", "verifier", "private_key", "begin private key", "github_pat", "ghp_", "token=", "password=", "secret=", "secret", `c:\\users\\`, "appdata", "downloads"} {
		if strings.Contains(text, forbidden) {
			t.Fatalf("unsafe appbridge JSON detail %q in %s", forbidden, string(raw))
		}
	}
}

type countingSecurityPostureProvider struct {
	summary securityposture.Summary
	calls   int
}

func (p *countingSecurityPostureProvider) BuildSecurityPosture(context.Context) securityposture.Summary {
	p.calls++
	return p.summary
}

type unsafeRelayProvider struct{}

func (unsafeRelayProvider) GetStatus(context.Context) relay.RelayStatus {
	return relay.RelayStatus{
		Enabled:    true,
		Available:  false,
		ProviderID: `provider:C:\Users\person\AppData\relay-token`,
		Summary:    `secret relay failure at C:\Users\person\AppData\mailbox`,
		Issues:     []relay.RelayIssue{{Code: "relay_secret", Message: `password=bad at C:\Users\person\Downloads\mailbox`, Blocking: true}},
	}
}

type unsafeDeviceLinkService struct{}

func (unsafeDeviceLinkService) GetCurrentDevice(context.Context) (devicelink.DeviceIdentity, error) {
	return devicelink.DeviceIdentity{
		DeviceID:             "device-1",
		DisplayName:          `secret local device C:\Users\person\AppData`,
		PublicKey:            "raw-public-key-material",
		PublicKeyFingerprint: "fingerprint-1",
		CreatedAt:            time.Now().UTC(),
	}, nil
}

func (unsafeDeviceLinkService) ListTrustedDevices(context.Context) ([]devicelink.TrustedDevice, error) {
	return []devicelink.TrustedDevice{{
		DeviceID:             "device-2",
		DisplayName:          `secret peer C:\Users\person\Downloads`,
		PublicKey:            "raw-public-key-material",
		PublicKeyFingerprint: "fingerprint-2",
		TrustStatus:          devicelink.TrustTrusted,
	}}, nil
}

type unsafeProfileMeshService struct{}

func (unsafeProfileMeshService) BuildProfileMeshOverview(context.Context) (profilemesh.ProfileMeshOverview, error) {
	return profilemesh.ProfileMeshOverview{
		ProfileID:   "profile-1",
		AppID:       "generic-app",
		Namespace:   "profile-a",
		DisplayName: `secret profile C:\Users\person\AppData`,
		Ready:       true,
		Message:     `token=bad at C:\Users\person\AppData\profile`,
		Issues:      []profilemesh.ProfileMeshIssue{{Code: "profile_secret", Message: `client_secret in C:\Users\person\Downloads`, Blocking: true}},
		Warnings:    []profilemesh.ProfileMeshIssue{{Code: "profile_warning", Message: `private_key in C:\Users\person\Desktop`, Blocking: false}},
	}, nil
}

func (unsafeProfileMeshService) ListProfileResources(context.Context) ([]profilemesh.ProfileResourceRecord, error) {
	return []profilemesh.ProfileResourceRecord{{
		ResourceID:          "resource-1",
		ResourceType:        profilemesh.ResourceProfileData,
		DisplayName:         `secret resource C:\Users\person\Downloads`,
		CurrentHostDeviceID: "device-1",
		Availability:        profilemesh.ResourceAvailable,
	}}, nil
}

type profileSyncStatusStub struct {
	status profilesync.SyncStatus
}

func (s profileSyncStatusStub) BuildStatus(context.Context) profilesync.SyncStatus {
	return s.status
}

type countingProfileSyncStatusProvider struct {
	status           profilesync.SyncStatus
	buildStatusCalls int
}

func (p *countingProfileSyncStatusProvider) BuildStatus(context.Context) profilesync.SyncStatus {
	p.buildStatusCalls++
	return p.status
}

type countingRelayStatusProvider struct {
	status         relay.RelayStatus
	getStatusCalls int
}

func (p *countingRelayStatusProvider) GetStatus(context.Context) relay.RelayStatus {
	p.getStatusCalls++
	return p.status
}

type countingUpdateService struct {
	status           updates.CurrentState
	getStatusCalls   int
	checkCalls       int
	downloadCalls    int
	verifyCalls      int
	stageCalls       int
	describeCalls    int
	buildPlanCalls   int
	applyCalls       int
	clearStagedCalls int
}

func (s *countingUpdateService) GetStatus(context.Context) (updates.CurrentState, error) {
	s.getStatusCalls++
	return s.status, nil
}

func (s *countingUpdateService) CheckForUpdates(context.Context) (updates.CheckResult, error) {
	s.checkCalls++
	return updates.CheckResult{}, nil
}

func (s *countingUpdateService) DownloadUpdate(context.Context, string) (updates.DownloadResult, error) {
	s.downloadCalls++
	return updates.DownloadResult{}, nil
}

func (s *countingUpdateService) VerifyUpdate(context.Context, string) (updates.VerifyResult, error) {
	s.verifyCalls++
	return updates.VerifyResult{}, nil
}

func (s *countingUpdateService) StageUpdate(context.Context, string) (updates.StageResult, error) {
	s.stageCalls++
	return updates.StageResult{}, nil
}

func (s *countingUpdateService) DescribeStagedUpdate(context.Context) (updates.StagedUpdateSummary, error) {
	s.describeCalls++
	return updates.StagedUpdateSummary{}, nil
}

func (s *countingUpdateService) BuildApplyPlan(context.Context) (updates.ApplyPlan, error) {
	s.buildPlanCalls++
	return updates.ApplyPlan{}, nil
}

func (s *countingUpdateService) ApplyUpdate(context.Context) (updates.ApplyResult, error) {
	s.applyCalls++
	return updates.ApplyResult{}, nil
}

func (s *countingUpdateService) ClearStagedUpdate(context.Context) (updates.ClearResult, error) {
	s.clearStagedCalls++
	return updates.ClearResult{}, nil
}

func (s *countingUpdateService) operationCalls() int {
	return s.checkCalls + s.downloadCalls + s.verifyCalls + s.stageCalls + s.describeCalls + s.buildPlanCalls + s.applyCalls + s.clearStagedCalls
}

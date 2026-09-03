# Public and Authenticated Update Sources

## Purpose

Aegis Core supports separate public and development update lanes without requiring one repository per lane. Repository layout is an application choice. Core owns source validation, safe provenance, signature/hash verification, isolated state, download/stage lifecycle, and a record-only package handoff. The consuming application owns every installer, extraction, restart, and rollback action.

A practical application topology is:

```text
private application repository
  source code
  private development manifest and release assets
  development CI

public distribution location
  stable/preview manifest
  promoted release assets
```

The public distribution location may be a small GitHub repository, release page, static site, or object store. A separate private update repository is useful only when development packages must be shared with people who should not receive source-repository access.

## Source access classes

`SourceConfig.Access` distinguishes three trust and transport modes:

- `local`: a caller-owned local manifest and local artifacts;
- `public`: an unauthenticated HTTP/GitHub source;
- `app_owned_authenticated`: an HTTP/GitHub source fetched through a credential-scoped client supplied by the host application.

Credentials never belong in `SourceConfig`, manifest URLs, artifact URLs, status DTOs, or Aegis persistence. The host application owns credential acquisition, storage, refresh, and injection through `http.Client.Transport`, `Jar`, or another app-owned HTTP mechanism.

## Separate public and private clients

Use `NewRecordOnlyServiceWithOptions` to provide separate transports without enabling the legacy callback execution surface:

```go
svc, err := updates.NewRecordOnlyServiceWithOptions(cfg, updates.ServiceOptions{
    HTTPClient:              publicClient,
    AuthenticatedHTTPClient: privateClient,
})
```

Aegis selects `HTTPClient` for public sources and `AuthenticatedHTTPClient` only for `app_owned_authenticated` sources. The selected client is used for both the manifest and its network artifacts. A private client is required for authenticated sources.

Aegis copies the supplied `http.Client` before adding finite timeout and redirect checks. Caller-owned transport, cookie jar, proxy, TLS configuration, and redirect policy remain in effect. Aegis does not inspect or persist credentials held by those components.

The authenticated transport must scope each credential to its intended authority. `AllowedHTTPHosts` limits where Aegis may send a request, but it does not make one credential valid for every allowlisted manifest, API, redirect, or asset host.

## Record-only package lifecycle

The package lifecycle contract is deliberately separate from signed Manifest v1. It does not add fields to `Manifest`, alter its canonical signed payload, or treat consumer-reported actions as release-authority facts.

Create a non-executing service with `NewRecordOnlyService` or `NewRecordOnlyServiceWithOptions`. After the existing check, download, verify, and stage sequence, use:

```go
envelope, err := svc.GetLifecycleEnvelope(ctx)
handoff, err := svc.RecordPackageHandoff(ctx, updates.PackageHandoffRequest{
    ExpectedRevision: envelope.Revision,
    IdempotencyKey:   "handoff-001",
    ConsumerID:       "consumer-host",
})

// The application may use handoff.ArtifactPath in its own process boundary.
// Core has recorded the handoff but has not executed anything.
```

`LifecycleEnvelope` is one atomically persisted lifecycle record containing:

- a path-free `PackageSummary`;
- a fixed `RouteSummary` identifying the explicit verified handoff;
- a `ValidationSummary` that distinguishes general validation from the mandatory handoff rehash;
- separate staged, validated, handoff, external-action, and completion steps;
- a safe action history bounded to `LifecycleHistoryLimit` entries;
- a monotonically increasing revision and RFC3339 string timestamps.

Every returned `ExecutionCapabilities` value reports these boundaries explicitly:

```text
can_reveal_verified_package = true
can_record_external_reports = true
can_execute_installer       = false
can_extract_package         = false
can_restart_application     = false
can_rollback_application    = false
```

`RecordPackageHandoff` revalidates metadata, size, and SHA-256 immediately before recording and returning the staged path. `ArtifactPath` is tagged `json:"-"`; it is absent from the lifecycle envelope and JSON handoff values. An idempotent handoff retry rehashes again before the path is re-revealed.

Lifecycle mutations require both `ExpectedRevision` and a non-secret `IdempotencyKey`. A stale new request returns `ErrLifecycleRevisionStale`. Repeating an accepted request with the same key and fields returns the current envelope without adding history or incrementing the revision. Reusing that key for different fields returns `ErrLifecycleIdempotencyConflict`. The persisted idempotency window is bounded.

`StageUpdate` never resets an existing lifecycle implicitly. Restaging the exact same package while its lifecycle is still in `staged` returns the existing stage without changing its lifecycle ID, revision, timestamps, metadata, or bytes. Once handoff has been recorded, or when the candidate is a different package, restaging returns `ErrLifecycleRestageConflict`. A caller must use an explicit lifecycle/reset workflow rather than silently replacing active history.

Only the following transition order is legal:

```text
staged -> handoff_recorded -> external_action_reported -> completed
```

The consumer reports its own work with `ReportExternalAction` and its final result with `ReportExternalCompletion`. Those methods validate and record fixed safe values only. They never invoke callbacks, processes, shells, installers, archive extractors, restart APIs, or rollback logic.

`ApplyStrategy`, `ApplyAdapter`, `NewService*`, `ApplyUpdate`, and `Apply` remain as deprecated compatibility APIs because removing them would break existing callers. They can execute arbitrary consumer callbacks and are not part of the safe lifecycle contract. A service created through a record-only constructor rejects those legacy methods with `ErrLegacyExecutionDisabled`.

## Authenticated source requirements

Authenticated sources are intentionally stricter. They require:

- a lowercase, non-secret `SourceID`;
- an app-owned authenticated HTTP client;
- an exact destination allowlist in `AllowedHTTPHosts`;
- manifest signatures enabled in `Policy`;
- `RequiredManifestKeyID` bound to a configured Ed25519 verification key;
- HTTPS, except explicit loopback HTTP used for local development.

Example:

```go
cfg.Source = updates.SourceConfig{
    Provider:              updates.ProviderHTTPManifest,
    ManifestURL:           "https://api.example.test/dev/manifest",
    SourceID:              "dev",
    Access:                updates.SourceAccessAppOwnedAuthenticated,
    RequiredManifestKeyID: "dev-release-2026",
    AllowedHTTPHosts:      []string{"api.example.test", "assets.example.test"},
}
cfg.Channel = updates.ChannelDev
cfg.Policy = updates.Policy{
    RequireSHA256:            true,
    AllowPrerelease:          true,
    RequireManifestSignature: true,
    ManifestVerificationKeys: map[string]string{
        "dev-release-2026": encodedDevPublicKey,
    },
}
```

Allowlist entries are exact authorities. An entry without a port means HTTPS port 443. Non-default ports must be written explicitly. Redirects are validated before the redirected request is sent. URL user information and fragments are rejected.

Persisted manifest and artifact URLs may not contain query strings. An allowlisted server may redirect to a same-policy destination containing an expiring signed query, which supports caller-controlled pre-signed asset delivery without persisting the signature.

## GitHub private repositories

A private application repository can also be the development distribution location. Configure an app-owned client for the GitHub API or raw-content endpoint and include every possible manifest, asset, and redirect authority in `AllowedHTTPHosts`.

For GitHub API responses, the host transport may need endpoint-specific `Accept` headers—for example, raw repository content for a manifest and binary media for a release asset. This behavior belongs in the app-owned transport because authentication and provider-specific request policy are outside Aegis Core.

Do not place a GitHub token in a manifest URL or Aegis configuration.

## Atomic lane switching

`ConfigureLane` changes channel, source, and optionally policy as one operation:

```go
state, err := svc.ConfigureLane(ctx, updates.LaneConfig{
    Channel: updates.ChannelDev,
    Source:  devSource,
    Policy:  &devPolicy,
})
```

When `Policy` is nil, the existing policy is preserved. `ConfigureSource` and `SetChannel` remain available for compatibility.

Network callbacks run without holding the service state mutex. If an explicit lane changes while a check or download is in flight, the stale operation is rejected with `ErrUpdateStateChanged` before it can commit metadata into the new lane.

Deprecated legacy apply callbacks also run without the state mutex. While such a callback is active, another legacy apply, lane mutation, stage, or clear operation returns `ErrApplyInProgress`. This compatibility behavior does not apply to the record-only lifecycle APIs, which never invoke the callback.

## Isolated persistence and safe provenance

A non-empty `SourceID` opts into source-, channel-, and policy-scoped storage. Stable and development lanes therefore cannot reuse one another's selected, downloaded, verified, or staged state. Switching back to a previous lane restores only that lane's own state.

Persisted records are additionally bound to cryptographic fingerprints of their normalized source and effective policy. The fingerprints include locations and trust policy but are never emitted through public DTOs.

Public status values expose only `SourceSummary`:

```text
ID, access class, provider kind, authenticated flag
```

They do not expose source URLs, allowlists, headers, cookies, credentials, local paths, or private release-note locations. Release-note URLs from authenticated manifests are deliberately redacted from public release DTOs.

`SourceID` itself is not secret. Choose a generic value such as `stable`, `preview`, or `dev`.

## Signing-key separation

Use separate verification keys for development and stable lanes. Bind each source to the expected key with `RequiredManifestKeyID`.

```text
development key -> development manifests only
stable key      -> public stable/preview manifests
```

A development key should not authorize a stable release. Key provisioning, rotation, revocation, and offline release ceremony remain application and release-pipeline responsibilities.

## Build once, promote the tested artifact

The recommended release flow is:

1. Build an artifact in private CI.
2. Publish a signed development manifest.
3. Test that exact artifact through the development lane.
4. Approve promotion.
5. Copy the same bytes to the public distribution location.
6. Re-verify the digest.
7. Sign a public manifest with the stable key.

Rebuilding during promotion can create a different artifact unless reproducible-build guarantees are in place.

## Remaining security boundary

These controls reduce credential leakage and cross-lane state confusion; they are not a complete secure-update framework. Production deployments still need release-key lifecycle and revocation, build provenance, artifact authorization, rollback/expiry policy, DNS and destination-IP policy, monitoring, incident response, and a safe application-owned installer/rollback process. Consumer-reported lifecycle completion is evidence supplied by that consumer, not proof that external execution was correct or trustworthy.

# Release and compatibility policy

W17 prepares an experimental release candidate; it does not publish a tag, create
a release, or qualify a production deployment. W18 owns final combined review,
repository publication and verification of hosted results against the published
candidate. Local validation cannot satisfy that hosted gate.

## Version and API status

All eleven public `pkg/` domains remain experimental. No package is promoted to a
stable v1 API by this campaign. Public import paths remain unchanged. The first
proposed campaign tag is `v0.1.0-rc.1`; reserve nothing and create no tag until the
published head passes its gates and release publication is separately authorized.
Check remote tags again immediately before choosing a tag; never move an existing
tag. Release candidates use increasing `-rc.N` suffixes. A final `v0.1.0` requires
an explicit release decision and does not imply v1 stability.

Within a released 0.x minor line, patch releases preserve exported contracts and
persisted/wire compatibility except for documented security corrections. Any
intentional source or format break requires a separately reviewed minor release,
an explicit migration note and old/new compatibility tests. A v1 declaration needs
a new stability review. The supported language/compiler policy is maintained in
[Compiler policy](COMPILER_POLICY.md); this page does not introduce a second pin.

## Breaking cleanup decision

Keep all existing public APIs in this candidate. Line count is not justification
for breaking an active consumer or changing callback authority.

| Candidate cleanup | Decision and prerequisite |
| --- | --- |
| Updates callback constructors, `ApplyStrategy`, `ApplyAdapter` and execution methods | Retain. The sampled VargBot consumer still calls `NewService` with `ManualApplyStrategy`. Adopt the record-only lifecycle in a separately authorized consumer migration before considering removal. |
| Updates compatibility method aliases | Retain `State`, `Check`, `Download`, `Verify`, `Stage`, `Describe`, `PlanApply` and `Apply`. Document direct equivalents and measure downstream use before a versioned removal. |
| Identity Gate legacy verification | Retain `IdentityVerificationProvider`, `Config.VerificationProvider`, `RequestVerification` and `RequestFreshVerification`. Existing receipt-based replacements and deprecations remain; removal still needs downstream adoption evidence and authority/replay/freshness migration tests. |
| Updates configuration fallbacks | Retain `AppName` -> `DisplayName` and `CacheDir`/`StateDir` -> `StagingDir` fallback behavior. The sampled consumer supplies `AppName` and `CacheDir`; they are active compatibility inputs. |
| Legacy Profile Sync exchange | Retain with SD-02/SD-03 limitations explicit. Reliable v2 adoption requires receiver/store/trust integration and recovery tests; it is not an automatic replacement. |
| AppBridge and Setup State | Retain. They are active consumer composition APIs, not unused forwarding layers. |

Deprecation requires a documented replacement, usage inventory, migration example,
and compatibility tests. Mark the exact declaration `Deprecated:` only when those
exist. A documented deprecation remains supported through its current minor line;
removal needs an explicit future release decision. This policy adds no new
deprecation annotations and does not remove previously deprecated compatibility.

## Release acceptance

1. Freeze the reviewed source commit. Run ordinary tests, vet, formatting, minimum
   compiler, API/wire/error/fixture checks, vulnerability scan and detached consumer
   resolution/compilation/behavior checks against that exact commit.
2. Independently recreate a committed-source export and verify its bytes and test
   identities. Keep baseline/evidence/export/consumer identities distinct.
3. After W18 publication, require successful Windows/Linux ordinary tests, explicit
   Windows persistence checks, full Linux race tests, minimum-language compilation,
   vulnerability scan and committed-export validation. Record run URL, job results,
   checkout SHA and candidate SHA; a green older run is not evidence for this head.
4. If a final correction changes any artifact, refresh review bindings and rerun
   affected validation on the new head. Do not publish under stale receipts.
5. Publish migration/rollback limits and the changelog. Treat tag creation, release
   publication, consumer installation and production qualification as separate
   outcomes with their own authorization and evidence.

Known legacy SD-02/SD-03 are accepted only as disclosed limitations of the retained
legacy protocol; they are not suppressed ordinary failures. No unresolved new P1
may be hidden by old CI or a changed test expectation. Reliable v2 consumer adoption,
host-owned protected storage and deployment-specific provider security remain
consumer obligations. See [Consumer migration](CONSUMER_MIGRATION.md).

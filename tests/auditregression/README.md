# Known-defect regression baseline

These tests express the desired behavior for the 2026-09-11 audit findings.
They intentionally fail on the W00 baseline. They do not assert that bugs
should remain, skip failures, or change production behavior.

Run the complete known-defect suite from the module root:

```sh
go test -mod=readonly -tags=auditregression -run 'Test.*Audit|TestAudit' -count=1 ./pkg/auth ./pkg/updates ./tests/auditregression
```

After W01, IG-01 and IG-02 are ordinary tests under pkg/identitygate and
internal/identitygate; 20 findings remain in this tagged suite.

After W02, UA-01 and UA-02 are also ordinary tests under pkg/updates;
18 findings remain in the tagged suite.

The same-package Auth and Updates cases live beside their existing private
test helpers. Public cases here exercise Identity Gate (IG-01 through IG-05),
Sync/Device (SD-01 through SD-08), and projections (AR-01 through AR-04).
Auth/Updates cover UA-01 through UA-05. Each failing assertion names its
finding. Some findings have multiple assertions or variants; test-event counts
are therefore not finding counts. Setup failures are fatal and must be
investigated rather than counted as reproduced defects.

The reentrant callback case uses a bounded two-second wait. The known deadlock
leaves a blocked goroutine until the test process exits. It must not be treated
as a race-detector result. Each execution uses temporary synthetic state and
loopback HTTP only.

When a work package fixes a finding, extract that case into an independent,
normally enabled regression test and add its boundary/negative cases. Keep
unfixed cases red under this tag. The tagged baseline is a tracking aid, not a
replacement for ordinary CI or a claim that every audit scenario is covered.

Execute one work package per user turn unless the user explicitly authorizes
otherwise. No work package changes consumers' committed dependency selections
without a separate migration decision.

# W17 integration and release-readiness preparation

Baseline: W16 fee0d23729e4a392bfd147c1b253e500fbec00e1. The W16 follow-up review
found two documentation issues; correction 4f4b27b reconciles Architecture's current
repair status and the smoke README's example-helper import boundary.

W17 changes documentation and CI only. It retains every W16 Go byte, existing test,
public API, persisted fixture and schema. The compatible release decision is in
[Release policy](../RELEASE_POLICY.md); adoption and rollback requirements are in
[Consumer migration](../CONSUMER_MIGRATION.md). No tag is created or public symbol
removed. All packages remain experimental, and active AppBridge/Updates consumers
retain their existing imports and constructors.

CI now selects and prints the exact PR-head/push commit, checks formatting, includes
explicit Windows persistence checks, runs the whole suite under Linux race, and
validates an independently recreated committed Linux export. Existing compiler,
scanner and action pins remain. Workflow definition is distinct from execution.

The campaign's original audit revision 2006392 had 20,605 library production,
1,157 example and 14,135 test lines. W17 retains W16's 23,682 / 1,136 / 23,652:
net +3,077 library, -21 example and +9,517 test lines. Physical counts include
comments/imports/blanks. Reliability and coverage additions outweigh consolidation;
the campaign does not achieve a net source-size reduction. W15 measurements show
selected repeated work reductions while preserving fresh integrity observations,
with mixed timing results; there is no universal speed or binary-size claim.

Final local validation, consumer resolution, archive-derived measurements, source
and export manifests and review bindings live in the campaign workspace under
evidence/aegis-core-w17-20260912 and its preparation directory. The local matrix
contains 28 gates, including explicit Windows persistence and the expected legacy
SD-02/SD-03 audit. This implementation record does not pre-claim their outcome.

Hosted Windows/Linux and Linux race acceptance remain pending: this machine has no
installed WSL or Docker environment, and the plan reserves publication for W18.
Older remote runs do not qualify this source. W17 local readiness is therefore
separate from complete release qualification. W18 must publish the reviewed head,
record its actual hosted results, correct failures and refresh affected evidence.
No source push, merge, tag, release, consumer installation or deployment occurs in
W17. State migration, rollback, retention and provider limits remain in their owner
documents; legacy exchange findings are disclosed rather than hidden by old CI.
